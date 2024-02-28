package tls_carrier

import (
	"bufio"
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"sync"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type Server struct {
	hg                           *conf.Hg
	tlsConfig                    *tls.Config
	passwordWithCRLF             [16]byte
	trojanPassword               [56]byte
	tlsBadAuthFallbackServerPort uint16
	tlsBadAuthFallbackSiteDir    string
}

var _ transport.Server = new(Server)

func newServer(ctx context.Context, hg *conf.Hg) (*Server, error) {
	server := &Server{hg: hg}
	if hg.TLSCertKeyPair == nil {
		tlsConfig, err := tlsConfigWithAutomatedCertificate(ctx, hg.Host)
		if err != nil {
			return nil, err
		}
		server.tlsConfig = tlsConfig
	} else {
		cert, err := tls.LoadX509KeyPair(hg.TLSCertKeyPair.CertFile, hg.TLSCertKeyPair.KeyFile)
		if err != nil {
			return nil, errors.New(err, "fail to load TLS Certificate/Key pair files")
		}
		server.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	server.passwordWithCRLF = replaceCRLF(hg.Password.Raw)
	server.trojanPassword = toTrojanPassword(hg.Password.String)

	port := make(chan uint16, 1)
	go func() {
		err := netutil.ListenTCPAndAccept(ctx, ":0", func(ln net.Listener) error {
			var handler http.Handler = nil
			if hg.TLSBadAuthFallbackSiteDir != "" {
				handler = http.FileServer(http.Dir(hg.TLSBadAuthFallbackSiteDir))
			}
			port <- uint16(ln.Addr().(*net.TCPAddr).Port)
			return errors.WithStack(http.Serve(ln, handler))
		}, nil)
		if err != nil {
			log.Fatal("fail to serve a fallback server", err)
		}
	}()
	server.tlsBadAuthFallbackServerPort = <-port
	return server, nil
}

func ListenRequests(ctx context.Context, hg *conf.Hg, targetClient transport.Client) error {
	server, err := newServer(ctx, hg)
	if err != nil {
		return errors.WithStack(err)
	}

	addr := ":" + strconv.Itoa(server.hg.TLSPort)
	return netutil.ListenTLSAndAccept(ctx, addr, server.tlsConfig, func(conn net.Conn) {
		err := server.HandleConnection(ctx, conn, targetClient)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over TLS", err)
		}
	})
}

func (s *Server) HandleConnection(ctx context.Context, conn net.Conn, targetClient transport.Client) error {
	log.Debug("request", "source", conn.RemoteAddr().String(), "type", "TLS carrier")
	// the tls_carrier protocol use 18 bytes for password(16) + CRLF(2)
	// the trojan protocol use 58 bytes for password(56) + CRLF(2)
	// so using 128 here for password + address
	bufReader := bufio.NewReaderSize(conn, 128)
	textProtoReader := newTextprotoReader(bufReader)

	// read one line to make our server like a normal HTTP server
	// for a TLS carrier client, it uses a password without CRLF
	// for a Trojan client, it uses a hex string password which doesn't include CRLF bytes
	// so we can always load a line with a password in both cases
	lineBs, err := textProtoReader.ReadLineBytes()
	putTextprotoReader(textProtoReader)
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
			unrelatedBs = append(unrelatedBs, CRLF...)
			unrelatedBs = append(unrelatedBs, unreadBs...)
			ip := netip.IPv6Loopback()
			fallbackAddr := transport.NewSocketAddressByIP(&ip, s.tlsBadAuthFallbackServerPort)
			return transport.ForwardTCP(ctx, fallbackAddr, ioutil.NewBytesReadPreloadReadWriteCloser(unrelatedBs, conn), targetClient)
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

	bufSize := bufReader.Buffered()
	unreadBs, err := bufReader.Peek(bufSize)
	if err != nil {
		return errors.WithStack(err)
	}
	return transport.ForwardTCP(ctx, accessAddr, ioutil.NewBytesReadPreloadReadWriteCloser(unreadBs, conn), targetClient)
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}
