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
	var host = httpSOCKS.Host
	addr := net.JoinHostPort(host, strconv.Itoa(int(httpSOCKS.Port)))
	authInfo := &transport.HTTPSOCKSAuthInfo{Username: httpSOCKS.Username, Password: httpSOCKS.Password}
	return netutil.ListenTCPAndAccept(addr, func() {
		if httpSOCKS.SystemProxy {
			err := proxy.SetSystemProxy(httpSOCKS.Host, httpSOCKS.Port, authInfo)
			if err != nil {
				log.WarnWithError("fail to set system proxy", err)
			}
		}
	}, func(conn net.Conn) {
		err := handleRequest(conn, authInfo, handler)
		_ = conn.Close()
		if err != nil {
			log.InfoWithError("fail to handle a HTTP/SOCKS request", err)
		}
	})
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
