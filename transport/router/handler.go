package router

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/direct"
	"github.com/ringo-is-a-color/heteroglossia/transport/reject"
	"github.com/ringo-is-a-color/heteroglossia/transport/tls_carrier"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/updater"
)

type Handler struct {
	route             *conf.Route
	routeRulesRWMutex *sync.RWMutex
	outbounds         map[string]*conf.ProxyNode
	tlsKeyLog         bool
	HTTPClient        *http.Client
}

var _ transport.ConnectionContinuationHandler = new(Handler)

func NewHandler(route *conf.Route, autoUpdateRuleFiles bool, outbounds map[string]*conf.ProxyNode, tlsKeyLog bool) *Handler {
	router := &Handler{route, new(sync.RWMutex), outbounds, tlsKeyLog, nil}
	router.HTTPClient = getHTTPClientThroughRouter(router)
	if autoUpdateRuleFiles {
		go updater.StartUpdateCron(func() {
			router.updateRoute()
		})
	}
	return router
}

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	forwardHandler, err := h.forwardHandler(accessAddr)
	if err != nil {
		return err
	}
	return forwardHandler.ForwardConnection(srcRWC, accessAddr)
}

func (h *Handler) forwardHandler(accessAddr *transport.SocketAddress) (transport.ConnectionContinuationHandler, error) {
	h.routeRulesRWMutex.RLock()
	var policy string
	switch accessAddr.AddrType {
	case transport.IPv4, transport.IPv6:
		for _, rule := range h.route.Rules {
			if rule.Matcher.MatchIP(accessAddr.IP) {
				policy = rule.Policy
				break
			}
		}
	default:
		for _, rule := range h.route.Rules {
			if rule.Matcher.MatchDomain(accessAddr.Domain) {
				policy = rule.Policy
				break
			}
		}
	}
	h.routeRulesRWMutex.RUnlock()
	if policy == "" {
		policy = h.route.Final
	}

	var handler transport.ConnectionContinuationHandler
	switch policy {
	case "direct":
		handler = new(direct.Handler)
	case "reject":
		handler = new(reject.Handler)
	default:
		proxyNode := h.outbounds[policy]
		var err error
		handler, err = tls_carrier.NewTLSCarrierClient(proxyNode, h.tlsKeyLog)
		if err != nil {
			return nil, err
		}
	}
	log.Info("route", "access", accessAddr.ToHostStr(), "policy", policy)
	return handler, nil
}

func (h *Handler) updateRoute() {
	success, err := updater.UpdateRulesFiles(h.HTTPClient)
	if err != nil {
		log.WarnWithError("fail to update rules' files", err)
		return
	}
	if !success {
		return
	}

	h.routeRulesRWMutex.RLock()
	newRules, err := h.route.Rules.CopyWithNewRulesData()
	if err != nil {
		h.routeRulesRWMutex.RUnlock()
		log.WarnWithError("fail to update rules' 'matcher'", err)
		return
	}
	h.routeRulesRWMutex.RUnlock()

	h.routeRulesRWMutex.Lock()
	h.route.Rules = newRules
	h.routeRulesRWMutex.Unlock()
	log.Info("update rules' files successfully")
}

func getHTTPClientThroughRouter(h *Handler) *http.Client {
	defaultTransport := http.DefaultTransport.(*http.Transport)
	// copy the same transport configuration from the 'http.DefaultTransport'
	httpTransport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			socketAddr, err := transport.ToSocketAddrFromNetworkAddr(network, addr)
			if err != nil {
				return nil, err
			}
			lp, rp := net.Pipe()
			go func() {
				err = h.ForwardConnection(rp, socketAddr)
				_ = rp.Close()
				if err != nil {
					log.InfoWithError("fail to forward connection for piping", err)
				}
			}()
			return lp, nil
		},
		ForceAttemptHTTP2:     defaultTransport.ForceAttemptHTTP2,
		MaxIdleConns:          defaultTransport.MaxIdleConns,
		IdleConnTimeout:       defaultTransport.IdleConnTimeout,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
	}
	return &http.Client{Transport: httpTransport}
}
