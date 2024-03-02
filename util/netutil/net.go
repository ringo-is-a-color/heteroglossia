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

func Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return errors.WithStack2(dial.DialContext(ctx, network, addr))
}

func DialTCP(ctx context.Context, addr string) (*net.TCPConn, error) {
	conn, err := Dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn.(*net.TCPConn), nil
}

func ListenTCPAndAccept(ctx context.Context, addr string,
	listenHandler func(ln net.Listener) error, listenFinishedCallback func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ln, err := listenConfig.Listen(ctx, "tcp", addr)
	if err != nil {
		return errors.WithStack(err)
	}
	go func() {
		// https://github.com/golang/go/issues/28120
		<-ctx.Done()
		_ = ln.Close()
	}()

	addListener(ln)
	defer func() {
		removeListener(ln)
		if listenFinishedCallback != nil {
			listenFinishedCallback()
		}
	}()
	err = listenHandler(ln)
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func ListenTCPAndServe(ctx context.Context, addr string, connHandler func(tcpConn *net.TCPConn)) error {
	return ListenTCPAndServeWithCallback(ctx, addr, connHandler, nil, nil)
}

func ListenTCPAndServeWithCallback(ctx context.Context, addr string, connHandler func(tcpConn *net.TCPConn),
	listenSuccessCallback func(ln net.Listener), listenFinishedCallback func()) error {
	return ListenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenSuccessCallback != nil {
			listenSuccessCallback(ln)
		}
		return accept(ln, func(conn net.Conn) {
			connHandler(conn.(*net.TCPConn))
		})
	}, listenFinishedCallback)
}

func ListenHTTPAndServe(ctx context.Context, addr string, handler http.Handler) error {
	return ListenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		return http.Serve(ln, handler)
	}, nil)
}

func ListenTLSAndAccept(ctx context.Context, addr string, config *tls.Config, connHandler func(conn net.Conn)) error {
	return ListenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		tlsLn := tls.NewListener(ln, config)
		return accept(tlsLn, connHandler)
	}, nil)
}

func StopAllListeners() {
	listeners.Range(func(key, value any) bool {
		_ = key.(net.Listener).Close()
		return true
	})
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
		go f(conn)
	}
}
