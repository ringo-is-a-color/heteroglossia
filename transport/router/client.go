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
	"github.com/ringo-is-a-color/heteroglossia/transport/tls_carrier"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/updater"
)

type Client struct {
	route             *conf.Route
	routeRulesRWMutex *sync.RWMutex
	outbounds         map[string]*conf.ProxyNode
	tlsKeyLog         bool
	HTTPClient        *http.Client
}

var _ transport.Client = new(Client)

func NewClient(route *conf.Route, autoUpdateRuleFiles bool, outbounds map[string]*conf.ProxyNode, tlsKeyLog bool) *Client {
	router := &Client{route, new(sync.RWMutex), outbounds, tlsKeyLog, nil}
	router.HTTPClient = transport.HTTPClientThroughRouter(router)
	if autoUpdateRuleFiles {
		go updater.StartUpdateCron(func() {
			router.updateRoute()
		})
	}
	return router
}

func (c *Client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	c.routeRulesRWMutex.RLock()
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
	c.routeRulesRWMutex.RUnlock()
	if policy == "" {
		policy = c.route.Final
	}

	var nextClient transport.Client
	switch policy {
	case "direct":
		nextClient = new(direct.Client)
	case "reject":
		nextClient = new(reject.Client)
	default:
		proxyNode := c.outbounds[policy]
		var err error
		nextClient, err = tls_carrier.NewClient(proxyNode, c.tlsKeyLog)
		if err != nil {
			return nil, err
		}
	}
	log.Info("route", "access", addr.ToHostStr(), "policy", policy)
	return nextClient.Dial(ctx, network, addr)
}

func (c *Client) updateRoute() {
	success, err := updater.UpdateRuleFile(c.HTTPClient)
	if err != nil {
		log.WarnWithError("fail to update rules' files", err)
		return
	}
	if !success {
		return
	}

	c.routeRulesRWMutex.RLock()
	newRules, err := c.route.Rules.CopyWithNewRulesData()
	if err != nil {
		c.routeRulesRWMutex.RUnlock()
		log.WarnWithError("fail to update rules' 'matcher'", err)
		return
	}
	c.routeRulesRWMutex.RUnlock()

	c.routeRulesRWMutex.Lock()
	c.route.Rules = newRules
	c.routeRulesRWMutex.Unlock()
	log.Info("update rules' files successfully")
}
