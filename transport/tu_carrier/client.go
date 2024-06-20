package tu_carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"sync"

	pool "github.com/libp2p/go-buffer-pool"
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

	quicConn      quic.Connection
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

func (c *client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	err := netutil.ValidateTCPorUDP(network)
	if err != nil {
		return nil, err
	}

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
	return newConn(quicConn, stream, quicConn.LocalAddr(), quicConn.RemoteAddr(), addr, true), nil
}

func (c *client) newQUICConn(ctx context.Context) (quic.Connection, error) {
	targetHostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.QUICPort)
	// TODO: https://quic-go.net/docs/quic/transport/#stateless-reset
	conn, err := netutil.DialQUIC(ctx, targetHostWithPort, c.tlsConfig, c.quicConfig)
	if err != nil {
		return nil, err
	}

	go func() {
		err := c.sendAuthenticationCommand(conn)
		if err != nil {
			_ = c.quicConn.CloseWithError(authCommandSendErrCode, authCommandSendErrStr)
			c.quicConnMutex.Lock()
			c.quicConn = nil
			c.quicConnMutex.Unlock()
		}
	}()
	return conn, nil
}

func (c *client) sendAuthenticationCommand(quicConn quic.Connection) (err error) {
	sendStream, err := quicConn.OpenUniStream()
	if err != nil {
		return errors.WithStack(err)
	}
	authToken, err := authToken(quicConn, []byte(c.proxyNode.Password.String))
	if err != nil {
		return err
	}

	authBs := pool.Get(1 + 1 + authCommandDataSize)
	defer pool.Put(authBs)
	authBuf := bytes.NewBuffer(authBs[:0])
	authBuf.WriteByte(tuicVersion)
	authBuf.WriteByte(authCommandType)
	authBuf.WriteString(authCommandUUID)
	authBuf.Write(authToken)
	_, err = authBuf.WriteTo(sendStream)
	if err != nil {
		return errors.WithStack(err)
	}
	_ = sendStream.Close()
	return nil
}
