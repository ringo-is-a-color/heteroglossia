package ss_carrier

import (
	"context"
	"net"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type server struct {
	hg           *conf.Hg
	targetClient transport.Client

	preSharedKey []byte
	aeadOverhead int
	// we can use '[16]byte' here actually, but we still use string here
	// because we may support "2022-blake3-aes-256-gcm" later which uses '[32]byte'
	saltPool *saltPool[string]
}

var _ transport.Server = new(server)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{hg, targetClient, hg.Password.Raw[:], gcmTagOverhead, newSaltPool[string]()}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	addr := ":" + strconv.Itoa(s.hg.TCPPort)
	return netutil.ListenTCPAndServe(ctx, addr, func(conn *net.TCPConn) {
		err := s.Serve(ctx, conn)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over SS", err)
		}
	})
}

func (s *server) Serve(ctx context.Context, conn net.Conn) error {
	serverConn := newServerConn(conn.(*net.TCPConn), s.preSharedKey, s.aeadOverhead, s.saltPool)
	// this is needed to get the access address for 'targetClient'
	err := serverConn.readClientFirstPacket()
	if err != nil {
		return err
	}
	return transport.ForwardTCP(ctx, serverConn.accessAddr, serverConn, s.targetClient)
}
