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

type Server struct {
	hg           *conf.Hg
	preSharedKey []byte
	aeadOverhead int

	// we can use '[16]byte' here actually, but we still use string here
	// because we may support "2022-blake3-aes-256-gcm" later which uses '[32]byte'
	saltPool *saltPool[string]
}

func newServer(hg *conf.Hg) *Server {
	return &Server{hg, hg.Password.Raw[:], gcmTagOverhead, newSaltPool[string]()}
}

func ListenRequests(ctx context.Context, hg *conf.Hg, targetClient transport.Client) error {
	server := newServer(hg)
	addr := ":" + strconv.Itoa(server.hg.TCPPort)
	return netutil.ListenTCPAndServe(ctx, addr, func(conn *net.TCPConn) {
		err := server.HandleConnection(ctx, conn, targetClient)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over SS", err)
		}
	})
}

func (s *Server) HandleConnection(ctx context.Context, conn net.Conn, targetClient transport.Client) error {
	serverConn := newServerConn(conn.(*net.TCPConn), s.preSharedKey, s.aeadOverhead, s.saltPool)
	// this is needed to get the access address for 'targetClient'
	err := serverConn.readClientFirstPacket()
	if err != nil {
		_ = conn.Close()
		return err
	}
	return transport.ForwardTCP(ctx, serverConn.accessAddr, serverConn, targetClient)
}
