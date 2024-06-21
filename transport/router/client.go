package router

import (
	"context"
	"net"
	"net/http"
	"sync"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/direct"
	"github.com/ringo-is-a-color/heteroglossia/transport/reject"
	"github.com/ringo-is-a-color/heteroglossia/transport/tr_carrier"
	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/updater"
)

type client struct {
	route        *conf.Route
	routeRWMutex *sync.RWMutex
	outbounds    map[string]*conf.ProxyNode
	tlsKeyLog    bool

	httpClient *http.Client
}

var _ transport.Client = new(client)

func NewClient(route *conf.Route, autoUpdateRuleFiles bool, outbounds map[string]*conf.ProxyNode, tlsKeyLog bool) transport.Client {
	router := &client{route, new(sync.RWMutex), outbounds, tlsKeyLog, nil}
	router.httpClient = transport.HTTPClientThroughRouter(router)
	if autoUpdateRuleFiles {
		go updater.StartUpdateCron(func() {
			router.updateRoute()
		})
	}
	return router
}

func (c *client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	c.routeRWMutex.RLock()
	err := netutil.ValidateTCP(network)
	if err != nil {
		return nil, err
	}

	var policy string
	switch addr.AddrType {
	case transport.IPv4, transport.IPv6:
		for _, rule := range c.route.Rules {
			if rule.Matcher.MatchIP(addr.IP) {
				policy = rule.Policy
				break
			}
		}
	default:
		for _, rule := range c.route.Rules {
			if rule.Matcher.MatchDomain(addr.Domain) {
				policy = rule.Policy
				break
			}
		}
	}
	c.routeRWMutex.RUnlock()
	if policy == "final" || policy == "" {
		policy = c.route.Final
	}

	var nextClient transport.Client
	switch policy {
	case "direct":
		nextClient = direct.NewClient()
	case "reject":
		nextClient = reject.NewClient()
	default:
		proxyNode := c.outbounds[policy]
		var err error
		nextClient, err = tr_carrier.NewClient(proxyNode, c.tlsKeyLog)
		if err != nil {
			return nil, err
		}
	}
	log.Info("route", contextutil.SourceTag, ctx.Value(contextutil.SourceTag),
		contextutil.InboundTag, ctx.Value(contextutil.InboundTag), "access", addr.ToHostStr(), "policy", policy)
	return nextClient.Dial(ctx, network, addr)
}

func (c *client) updateRoute() {
	success, err := updater.UpdateRuleFile(c.httpClient)
	if err != nil {
		log.WarnWithError("fail to update rules' files", err)
		return
	}
	if !success {
		return
	}

	c.routeRWMutex.RLock()
	newRules, err := c.route.Rules.CopyWithNewRulesData()
	if err != nil {
		c.routeRWMutex.RUnlock()
		log.WarnWithError("fail to update rules' 'matcher'", err)
		return
	}
	c.routeRWMutex.RUnlock()

	c.routeRWMutex.Lock()
	c.route.Rules = newRules
	c.routeRWMutex.Unlock()
	log.Info("update rules' files successfully")
}
