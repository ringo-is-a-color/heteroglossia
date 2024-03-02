package http_socks

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"sync/atomic"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/http"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
	"github.com/ringo-is-a-color/heteroglossia/util/proxy"
)

type Server struct {
	AuthInfo *transport.HTTPSOCKSAuthInfo
}

var _ transport.Server = new(Server)

func ListenRequests(ctx context.Context, httpSOCKS *conf.HTTPSOCKS, targetClient transport.Client) error {
	// can't listen to IPv4 & IPv6 together due to https://github.com/golang/go/issues/9334
	// so also listen to IPv4 one when using '::1' or '::'
	var host = httpSOCKS.Host
	authInfo := &transport.HTTPSOCKSAuthInfo{Username: httpSOCKS.Username, Password: httpSOCKS.Password}
	server := &Server{authInfo}
	connHandler := func(conn *net.TCPConn) {
		err := server.HandleConnection(ctx, conn, targetClient)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a HTTP/SOCKS request", err)
		}
	}

	var ipv4RequestsHandlerForDualstack func() error
	if host == "::1" {
		ipv4Localhost := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(httpSOCKS.Port)))
		ipv4RequestsHandlerForDualstack = func() error {
			return netutil.ListenTCPAndServe(ctx, ipv4Localhost, connHandler)
		}
	} else if host == "::" {
		// the Golang will listen both IPv4 & IPv6 when using the empty string for host
		host = ""
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(httpSOCKS.Port)))
	return parRunWithFirstErrReturn(func() error {
		var unsetProxy func()
		var hasUnsetProxy atomic.Bool
		return netutil.ListenTCPAndServeWithCallback(ctx, addr, connHandler, func(_ net.Listener) {
			if httpSOCKS.SystemProxy {
				log.Info("try to set the system proxy")
				// do not use the 'host' variable directly because we changed it for '::'
				var err error
				unsetProxyFunction, err := proxy.SetSystemProxy(httpSOCKS.Host, httpSOCKS.Port, authInfo)
				if err != nil {
					log.WarnWithError("fail to set the system proxy", err)
				}
				unsetProxy = func() {
					if hasUnsetProxy.CompareAndSwap(false, true) {
						unsetProxyFunction()
					}
				}
				osutil.RegisterProgramTerminationHandler(func() {
					unsetProxy()
				})
			}
		}, func() {
			if unsetProxy != nil {
				unsetProxy()
			}
		})
	}, ipv4RequestsHandlerForDualstack)
}

func (s *Server) HandleConnection(ctx context.Context, conn net.Conn, targetClient transport.Client) error {
	b, err := ioutil.Read1(conn)
	if err != nil {
		return err
	}
	switch b {
	case socks.Sock4Version:
		return errors.New("SOCKS4 protocol is not supported, only SOCKS5 is supported")
	case socks.Sock5Version:
		ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "SOCKS5 Proxy")
		return (&socks.Server{AuthInfo: s.AuthInfo}).HandleConnection(ctx, conn, targetClient)
	default:
		// assume this is an HTTP proxy request
		ctx = contextutil.WithSourceAndInboundValues(ctx, conn.RemoteAddr().String(), "HTTP Proxy")
		// 256 is a micro optimization here to reduce the buffer size
		bufReader := bufio.NewReaderSize(ioutil.NewBytesReadPreloadReadWriteCloser([]byte{b}, conn), 256)
		return (&http.Server{ConnBufReader: bufReader, AuthInfo: s.AuthInfo}).HandleConnection(ctx, conn, targetClient)
	}
}

func parRunWithFirstErrReturn(f1 func() error, f2 func() error) error {
	if f1 == nil {
		return f2()
	}
	if f2 == nil {
		return f1()
	}

	ch := make(chan error, 1)
	go func() {
		ch <- f1()
	}()
	go func() {
		ch <- f2()
	}()

	err := <-ch
	if err != nil {
		return err
	}
	return <-ch
}
