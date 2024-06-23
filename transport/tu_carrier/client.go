package tu_carrier

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type client struct {
	proxyNode  *conf.ProxyNode
	tlsConfig  *tls.Config
	quicConfig *quic.Config

	quicConn      *clientQUICConn
	quicConnMutex sync.Mutex
}

var _ transport.Client = new(client)

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (transport.Client, error) {
	tlsConfig, err := netutil.TLSClientConfig(proxyNode, tlsKeyLog)
	if err != nil {
		return nil, err
	}
	return &client{proxyNode: proxyNode, tlsConfig: tlsConfig, quicConfig: quicClientConfig}, nil
}

func (c *client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	c.quicConnMutex.Lock()
	if c.quicConn == nil || !isActive(c.quicConn) {
		c.quicConn = nil
		quicConn, err := c.newQUICConn(ctx)
		if err != nil {
			c.quicConnMutex.Unlock()
			targetHostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.QUICPort)
			return nil, errors.Newf(err, "fail to connect to the QUIC server %v", targetHostWithPort)
		}
		c.quicConn = quicConn
	}
	quicConn := c.quicConn
	c.quicConnMutex.Unlock()

	stream, err := quicConn.OpenStream()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	quicConn.relayingTaskCount.Add(1)
	return newClientTCPConn(quicConn, stream, addr, func() { quicConn.relayingTaskCount.Add(^uint64(0)) }), nil
}

func (c *client) newQUICConn(ctx context.Context) (*clientQUICConn, error) {
	targetHostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.QUICPort)
	// TODO: https://quic-go.net/docs/quic/transport/#stateless-reset
	quicConn, err := netutil.DialQUIC(ctx, targetHostWithPort, c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}

	clientQUICConn := &clientQUICConn{client: c, Connection: quicConn}
	go closeConnWhenParentContextDone(ctx, clientQUICConn)
	go func() {
		err := clientQUICConn.sendAuthenticationCommand()
		if err != nil {
			_ = clientQUICConn.CloseWithError(authCommandSendErrCode, authCommandSendErrStr)
		}
	}()
	go clientQUICConn.sendHeartbeats()
	return clientQUICConn, nil
}

func isActive(quicConn quic.Connection) bool {
	select {
	case <-quicConn.Context().Done():
		return false
	default:
		return true
	}
}

func closeConnWhenParentContextDone(parent context.Context, quic quic.Connection) {
	select {
	case <-parent.Done():
		_ = quic.CloseWithError(connectionContextDoneErrCode, connectionContextDoneErrStr)
	case <-quic.Context().Done():
	}
}
