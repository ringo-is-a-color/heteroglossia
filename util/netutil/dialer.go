package netutil

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

var (
	dialer               = net.Dialer{Timeout: dialerTimeout, KeepAlive: tcpKeepAlive}
	dialerTimeout        = 10 * time.Second
	quicHandshakeTimeout = 10 * time.Second
)

func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return errors.WithStack2(dialer.DialContext(ctx, network, addr))
}

func DialTCP(ctx context.Context, addr string) (*net.TCPConn, error) {
	conn, err := Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func DialTLS(ctx context.Context, addr string, tlsConfig *tls.Config) (*tls.Conn, error) {
	conn, err := Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return tls.Client(conn, tlsConfig), nil
}

func DialQUIC(ctx context.Context, addr string, tlsConf *tls.Config, quicConf *quic.Config) (quic.Connection, error) {
	ctx, cancel := context.WithTimeout(ctx, quicHandshakeTimeout)
	defer cancel()
	return errors.WithStack2(quic.DialAddr(ctx, addr, tlsConf, quicConf))
}
