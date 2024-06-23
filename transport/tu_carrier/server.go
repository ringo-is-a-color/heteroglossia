package tu_carrier

import (
	"context"
	"crypto/tls"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type server struct {
	hg           *conf.Hg
	targetClient transport.Client

	tlsConfig                    *tls.Config
	tlsBadAuthFallbackServerPort uint16
}

var _ transport.Server = new(server)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{hg: hg, targetClient: targetClient}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	var err error
	s.tlsConfig, err = netutil.TLSServerConfig(s.hg)
	if err != nil {
		return err
	}

	// TODO: tlsBadAuthFallbackServerPort
	return netutil.ListenQUICAndAccept(ctx, s.hg.QUICPort, s.tlsConfig, quicServerConfig, func(quicConn quic.Connection) {
		ctx = contextutil.WithSourceAndInboundValues(ctx, quicConn.RemoteAddr().String(), "QUIC carrier")
		serverConn := &serverQUICConn{s, quicConn, make(chan struct{})}
		go serverConn.handleAuthTimeout()
		go serverConn.processIncomingUniStreams(ctx)
		go serverConn.processIncomingStreams(ctx)
		go serverConn.processIncomingDatagram(ctx)
	})
}
