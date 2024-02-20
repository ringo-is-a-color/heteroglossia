package tls_carrier

import (
	"bufio"
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

type serverInfo struct {
	hg                           *conf.Hg
	tlsConfig                    *tls.Config
	passwordWithCRLF             [16]byte
	trojanPassword               [56]byte
	tlsBadAuthFallbackServerPort uint16
	tlsBadAuthFallbackSiteDir    string
}

func newServerInfo(hg *conf.Hg) (*serverInfo, error) {
	serverInfo := &serverInfo{hg: hg}
	if hg.TLSCertKeyPair == nil {
		tlsConfig, err := getTLSConfigWithAutomatedCertificate(hg.Host)
		if err != nil {
			return nil, err
		}
		serverInfo.tlsConfig = tlsConfig
	} else {
		cert, err := tls.LoadX509KeyPair(hg.TLSCertKeyPair.CertFile, hg.TLSCertKeyPair.KeyFile)
		if err != nil {
			return nil, errors.Wrap(err, "fail to load TLS Certificate/Key pair files")
		}
		serverInfo.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	serverInfo.passwordWithCRLF = replaceCRLF(hg.Password.Raw)
	serverInfo.trojanPassword = toTrojanPassword(hg.Password.String)

	ln, err := netutil.ListenTCP(":0")
	if err != nil {
		log.Fatal("fail to listen a port", err)
	}
	go func() {
		var handler http.Handler = nil
		if hg.TLSBadAuthFallbackSiteDir != "" {
			handler = http.FileServer(http.Dir(hg.TLSBadAuthFallbackSiteDir))
		}
		err := http.Serve(ln, handler)
		if err != nil {
			log.Fatal("fail to serve a fallback server", err)
		}
	}()
	serverInfo.tlsBadAuthFallbackServerPort = uint16(ln.Addr().(*net.TCPAddr).Port)
	return serverInfo, nil
}

func ListenRequests(hg *conf.Hg, handler transport.ConnectionContinuationHandler) error {
	serverInfo, err := newServerInfo(hg)
	if err != nil {
		return errors.WithStack(err)
	}
	return listenRequests(serverInfo, handler)
}

func listenRequests(serverInfo *serverInfo, handler transport.ConnectionContinuationHandler) error {
	addr := ":" + strconv.Itoa(serverInfo.hg.TLSPort)
	return netutil.ListenTLSAndAccept(addr, serverInfo.tlsConfig, func(conn net.Conn) {
		err := handleRequest(conn, serverInfo, handler)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a request over TLS", err)
		}
	})
}

func handleRequest(conn net.Conn, serverInfo *serverInfo, handler transport.ConnectionContinuationHandler) error {
	log.Debug("request", "source", conn.RemoteAddr().String(), "type", "TLS carrier")
	// the tls_carrier protocol use 18 bytes for password(16) + CRLF(2)
	// the trojan protocol use 58 bytes for password(56) + CRLF(2)
	// so using 128 here for password + address
	bufReader := bufio.NewReaderSize(conn, 128)
	textProtoReader := newTextprotoReader(bufReader)

	// read one line in order to make our server like a normal HTTP server
	lineBs, err := textProtoReader.ReadLineBytes()
	putTextprotoReader(textProtoReader)
	if err != nil {
		return errors.WithStack(err)
	}

	isTrojan := false
	if len(lineBs) != 16 || [16]byte(lineBs[0:16]) != serverInfo.passwordWithCRLF {
		if len(lineBs) != 56 || [56]byte(lineBs[0:56]) != serverInfo.trojanPassword {
			unreadBufSize := bufReader.Buffered()
			unreadBs, err := bufReader.Peek(unreadBufSize)
			if err != nil {
				log.Fatal("fail to peek buff", err)
			}
			// 2 = len(CRLF)
			unrelatedBs := pool.Get(len(lineBs) + 2 + len(unreadBs))[:0]
			defer pool.Put(unrelatedBs)
			unrelatedBs = append(unrelatedBs, CRLF...)
			unrelatedBs = append(unrelatedBs, unreadBs...)
			ip := netip.IPv6Loopback()
			addr := transport.NewSocketAddressByIP(&ip, serverInfo.tlsBadAuthFallbackServerPort)
			return handler.ForwardConnection(ioutil.NewBytesReadPreloadReadWriteCloser(unrelatedBs, conn), addr)
		} else {
			isTrojan = true
		}
	}

	commandType, err := ioutil.Read1(bufReader)
	if commandType != socks.ConnectionCommandConnect {
		return errors.Newf("unsupported command type %v", lineBs[1])
	}
	dest, err := socks.ReadSOCKS5Address(bufReader)
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
		log.Fatal("fail to peek buff", err)
	}
	return handler.ForwardConnection(ioutil.NewBytesReadPreloadReadWriteCloser(unreadBs, conn), dest)
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
