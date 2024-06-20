package tr_carrier

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type server struct {
	hg           *conf.Hg
	targetClient transport.Client

	passwordWithCRLF [16]byte
	trojanPassword   [56]byte

	tlsConfig                    *tls.Config
	tlsBadAuthFallbackServerPort uint16
}

var _ transport.Server = new(server)

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	server := &server{hg: hg, targetClient: targetClient}
	server.passwordWithCRLF = replaceCRLF(hg.Password.Raw)
	server.trojanPassword = toTrojanPassword(hg.Password.String)
	return server
}

func (s *server) ListenAndServe(ctx context.Context) error {
	var err error
	s.tlsConfig, err = netutil.TLSServerConfig(s.hg)
	if err != nil {
		return err
	}

	port := make(chan uint16, 1)
	go func() {
		var httpHandler http.Handler = nil
		if s.hg.TLSBadAuthFallbackSiteDir != "" {
			httpHandler = http.FileServer(http.Dir(s.hg.TLSBadAuthFallbackSiteDir))
		}
		err := netutil.ListenHTTPAndServeWithListenerCallback(ctx, ":0", httpHandler, func(ln net.Listener) {
			port <- uint16(ln.Addr().(*net.TCPAddr).Port)
		})
		if err != nil {
			log.Fatal("fail to serve a fallback server", err)
		}
	}()
	s.tlsBadAuthFallbackServerPort = <-port

	addr := ":" + strconv.Itoa(s.hg.TLSPort)
	return netutil.ListenTLSAndAccept(ctx, addr, s.tlsConfig, func(conn net.Conn) {
		ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "TLS carrier")
		err := s.Serve(ctx, conn)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over TLS", err)
		}
	})
}

func (s *server) Serve(ctx context.Context, conn net.Conn) error {
	buf := pool.Get(ioutil.BufSize)
	defer pool.Put(buf)
	bufReader := ioutil.NewBufioReader(buf, conn)
	textProtoReader := textproto.NewReader(bufReader)

	// read one line to make our server like a normal HTTP server
	// for a TLS carrier client, it uses a password without CRLF
	// for a Trojan client, it uses a hex string password which doesn't include CRLF bytes
	// so we can always load a line with a password in both cases
	lineBs, err := textProtoReader.ReadLineBytes()
	if err != nil {
		return errors.WithStack(err)
	}

	isTrojan := false
	if len(lineBs) != 16 || [16]byte(lineBs[0:16]) != s.passwordWithCRLF {
		if len(lineBs) != 56 || [56]byte(lineBs[0:56]) != s.trojanPassword {
			unreadBufSize := bufReader.Buffered()
			unreadBs, err := bufReader.Peek(unreadBufSize)
			if err != nil {
				return errors.WithStack(err)
			}
			// 2 = len(CRLF)
			unrelatedBs := pool.Get(len(lineBs) + 2 + len(unreadBs))[:0]
			defer pool.Put(unrelatedBs)
			unrelatedBs = append(unrelatedBs, crlf...)
			unrelatedBs = append(unrelatedBs, unreadBs...)
			ip := netip.IPv6Loopback()
			ctx := contextutil.WithValues(ctx, contextutil.InboundTag, "TLS carrier with wrong auth")
			fallbackAddr := transport.NewSocketAddressByIP(&ip, s.tlsBadAuthFallbackServerPort)
			return transport.ForwardTCP(ctx, fallbackAddr, ioutil.NewBytesReadPreloadConn(unrelatedBs, conn), s.targetClient)
		} else {
			isTrojan = true
		}
	}

	commandType, err := ioutil.Read1(bufReader)
	if commandType != socks.ConnectionCommandConnect {
		return errors.Newf("unsupported command type %v", lineBs[1])
	}
	accessAddr, err := socks.ReadSOCKS5Address(bufReader)
	if err != nil {
		return err
	}
	if isTrojan {
		crlfBs := make([]byte, 2)
		_, err := bufReader.Read(crlfBs)
		if err != nil {
			return errors.WithStack(err)
		}
	}

	unreadSize := bufReader.Buffered()
	unreadBs, err := bufReader.Peek(unreadSize)
	if err != nil {
		return errors.WithStack(err)
	}
	return transport.ForwardTCP(ctx, accessAddr, ioutil.NewBytesReadPreloadConn(unreadBs, conn), s.targetClient)
}
