package netutil

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

var (
	dial         = net.Dialer{Timeout: 15 * time.Second, KeepAlive: 2 * time.Hour}
	listenConfig = net.ListenConfig{KeepAlive: 1000 * time.Second}
	listeners    = sync.Map{}
)

func DialTCP(addr string) (*net.TCPConn, error) {
	conn, err := dial.Dial("tcp", addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	tcpConn := conn.(*net.TCPConn)
	if err != nil {
		return nil, err
	}
	return tcpConn, nil
}

func ListenTCPAndAccept(addr string, afterListenCallback func(), connHandler func(conn net.Conn)) error {
	ln, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer closeListener(ln)
	addListener(ln)
	if afterListenCallback != nil {
		afterListenCallback()
	}
	return accept(ln, connHandler)
}

func ListenTLSAndAccept(addr string, config *tls.Config, connHandler func(conn net.Conn)) error {
	ln, err := listenConfig.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer closeListener(ln)
	addListener(ln)
	tlsLn := tls.NewListener(ln, config)
	return accept(tlsLn, connHandler)
}

func ListenHTTPAndServe(addr string, handler http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer closeListener(ln)
	addListener(ln)
	return http.Serve(ln, handler)
}

func ListenTCP(addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	addListener(ln)
	return ln, nil
}

func StopAllListeners() {
	listeners.Range(func(key, value any) bool {
		_ = key.(net.Listener).Close()
		return true
	})
}

func closeListener(ln net.Listener) {
	removeListener(ln)
	_ = ln.Close()
}

func addListener(ln net.Listener) {
	listeners.Store(ln, struct{}{})
}

func removeListener(ln net.Listener) {
	listeners.Delete(ln)
}

func accept(ln net.Listener, f func(conn net.Conn)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return errors.WithStack(err)
		}
		if err != nil {
			return err
		}
		go f(conn)
	}
}
