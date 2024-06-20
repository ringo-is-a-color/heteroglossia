package tr_carrier

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type client struct {
	proxyNode           *conf.ProxyNode
	tlsConfig           *tls.Config
	passwordWithoutCRLF [16]byte
}

var _ transport.Client = new(client)

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	clientHandler := &client{proxyNode: proxyNode}
	tlsConfig, err := netutil.TLSClientConfig(proxyNode, tlsKeyLog)
	if err != nil {
		return nil, err
	}
	clientHandler.tlsConfig = tlsConfig
	clientHandler.passwordWithoutCRLF = replaceCRLF(proxyNode.Password.Raw)
	return clientHandler, nil
}

func (c *client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	err := netutil.ValidateTCP(network)
	if err != nil {
		return nil, err
	}

	targetHostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.TLSPort)
	tlsConn, err := netutil.DialTLS(ctx, targetHostWithPort, c.tlsConfig)
	if err != nil {
		return nil, errors.Newf(err, "fail to connect to the TLS server %v", targetHostWithPort)
	}
	return newClientConn(tlsConn, addr, c.passwordWithoutCRLF), nil
}
