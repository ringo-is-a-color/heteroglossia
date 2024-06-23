package netutil

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

var (
	// TODO: https://github.com/golang/go/issues/62254#issuecomment-1791102281
	listenConfig   = net.ListenConfig{KeepAlive: KeepAlive}
	serverListener = sync.Map{}

	httpReadTimeout  = 10 * time.Second
	httpWriteTimeout = 10 * time.Second
)

func listenTCPAndAccept(ctx context.Context, addr string,
	listenHandler func(ln net.Listener) error, listenFinishedCallback func()) error {
	// use 'context.WithCancel' to avoid memory leak in the below goroutine
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
	addServerListener(ln)
	defer func() {
		removeServerListener(ln)
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
	return ListenTCPAndServeWithListenerCallback(ctx, addr, connHandler, nil, nil)
}

func ListenTCPAndServeWithListenerCallback(ctx context.Context, addr string, connHandler func(tcpConn *net.TCPConn),
	listenSuccessCallback func(ln net.Listener), listenFinishedCallback func()) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenSuccessCallback != nil {
			listenSuccessCallback(ln)
		}
		return accept(ln, func(conn net.Conn) {
			connHandler(conn.(*net.TCPConn))
		})
	}, listenFinishedCallback)
}

func ListenHTTPAndServe(ctx context.Context, addr string, httpHandler http.Handler) error {
	return ListenHTTPAndServeWithListenerCallback(ctx, addr, httpHandler, nil)
}

func ListenHTTPAndServeWithListenerCallback(ctx context.Context, addr string, httpHandler http.Handler, listenerCallback func(ln net.Listener)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		if listenerCallback != nil {
			listenerCallback(ln)
		}
		server := &http.Server{
			Handler:      httpHandler,
			ReadTimeout:  httpReadTimeout,
			WriteTimeout: httpWriteTimeout,
		}
		return server.Serve(ln)
	}, nil)
}

func ListenTLSAndAccept(ctx context.Context, addr string, tlsConfig *tls.Config, connHandler func(conn net.Conn)) error {
	return listenTCPAndAccept(ctx, addr, func(ln net.Listener) error {
		tlsLn := tls.NewListener(ln, tlsConfig)
		return accept(tlsLn, connHandler)
	}, nil)
}

func ListenQUICAndAccept(ctx context.Context, port int, tlsConfig *tls.Config, quicConfig *quic.Config,
	connHandler func(quicConn quic.Connection)) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
	if err != nil {
		return errors.WithStack(err)
	}

	// we can use 0.5-RTT here because we don't use TLS client authentication
	ln, err := quic.ListenEarly(udpConn, tlsConfig, quicConfig)
	// use 'context.WithCancel' to avoid memory leak in the below goroutine
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	addServerListener(ln)
	defer removeServerListener(ln)

	// https://quic-go.net/docs/quic/server/#using-the-convenience-functions
	// closing a listener created using these shortcuts causes all accepted connections to be immediately terminated,
	// so no need to close the 'conn' additionally
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return errors.WithStack(err)
		}

		select {
		case <-conn.HandshakeComplete():
			// handshake completed
			connHandler(conn)
		case <-conn.Context().Done():
			// connection closed before handshake completion, e.g., due to handshake failure
		}
	}
}

func StopAllServerListeners() {
	serverListener.Range(func(key, value any) bool {
		_ = key.(io.Closer).Close()
		return true
	})
}

func addServerListener(listenerCloser io.Closer) {
	serverListener.Store(listenerCloser, struct{}{})
}

func removeServerListener(listenerCloser io.Closer) {
	serverListener.Delete(listenerCloser)
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
