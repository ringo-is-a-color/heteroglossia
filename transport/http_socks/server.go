package http_socks

import (
	"bufio"
	"net"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/http"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/proxy"
)

func ListenRequests(httpSOCKS *conf.HTTPSOCKS, handler transport.ConnectionContinuationHandler) error {
	// can't listen to IPv4 & IPv6 together due to https://github.com/golang/go/issues/9334
	// so also listen to IPv4 one when using ::1 or ::
	var host = httpSOCKS.Host
	authInfo := &transport.HTTPSOCKSAuthInfo{Username: httpSOCKS.Username, Password: httpSOCKS.Password}
	var ipv4RequestsHandlerForDualstack func() error
	connHandler := func(conn net.Conn) {
		err := handleRequest(conn, authInfo, handler)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a HTTP/SOCKS request", err)
		}
	}

	if host == "::1" {
		ipv4Localhost := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(httpSOCKS.Port)))
		ipv4RequestsHandlerForDualstack = func() error {
			return netutil.ListenTCPAndAccept(ipv4Localhost, nil, connHandler)
		}
	} else if host == "::" {
		host = ""
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(httpSOCKS.Port)))
	return parRunWithFirstErrReturn(func() error {
		return netutil.ListenTCPAndAccept(addr, func() {
			if httpSOCKS.SystemProxy {
				log.Info("try to set the system proxy")
				// do not use the 'host' variable directly because we changed it for ::
				err := proxy.SetSystemProxy(httpSOCKS.Host, httpSOCKS.Port, authInfo)
				if err != nil {
					log.WarnWithError("fail to set the system proxy", err)
				}
			}
		}, connHandler)
	}, ipv4RequestsHandlerForDualstack)
}

func handleRequest(conn net.Conn, authInfo *transport.HTTPSOCKSAuthInfo, handler transport.ConnectionContinuationHandler) error {
	b, err := ioutil.Read1(conn)
	if err != nil {
		return err
	}
	switch b {
	case socks.Sock4Version:
		return errors.New("SOCKS4 protocol is not supported, only SOCKS5 is supported")
	case socks.Sock5Version:
		log.Debug("request", "source", conn.RemoteAddr().String(), "type", "SOCKS5 Proxy")
		return socks.HandleSOCKS5RequestWithFirstByte(conn, authInfo, handler)
	default:
		// assume this is an HTTP proxy request
		log.Debug("request", "source", conn.RemoteAddr().String(), "type", "HTTP Proxy")
		// 256 is a micro optimisation here to reduce the buffer size
		bufReader := bufio.NewReaderSize(&ioutil.BytesReadPreloadReadWriteCloser{Preload: []byte{b}, RWC: conn}, 256)
		return http.HandleRequest(conn, bufReader, authInfo, handler)
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
