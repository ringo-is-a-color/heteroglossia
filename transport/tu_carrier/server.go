package tu_carrier

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type server struct {
	hg           *conf.Hg
	targetClient transport.Client

	tlsConfig                    *tls.Config
	tlsBadAuthFallbackServerPort uint16
}

var _ transport.Server = new(server)

// one server has n serverConn/quic.Connection
type serverConn struct {
	*server
	quicConn quic.Connection

	authDone        chan struct{}
	doneOrCancelled context.Context
	cancel          context.CancelFunc
}

func NewServer(hg *conf.Hg, targetClient transport.Client) transport.Server {
	return &server{hg: hg, targetClient: targetClient}
}

func (s *server) ListenAndServe(ctx context.Context) error {
	var err error
	s.tlsConfig, err = netutil.TLSServerConfig(s.hg)
	if err != nil {
		return err
	}

	// TODO: tlsBadAuthFallbackServerPort
	return netutil.ListenQUICAndAccept(ctx, s.hg.QUICPort, s.tlsConfig, quicServerConfig, func(quicConn quic.Connection) {
		ctx = contextutil.WithSourceAndInboundValues(ctx, quicConn.RemoteAddr().String(), "QUIC carrier")
		ctx, cancel := context.WithCancel(ctx)
		serverConn := &serverConn{s, quicConn, make(chan struct{}), ctx, cancel}
		go serverConn.handleAuthTimeout()
		go serverConn.processIncomingUniStreams()
		go serverConn.processIncomingStreams()
	})
}

func (c *serverConn) handleAuthTimeout() {
	select {
	case <-c.authDone:
	case <-c.doneOrCancelled.Done():
	case <-time.After(authTimeout):
		c.closeWithError(authCommandReceiveTimeoutErrCode, authCommandReceiveTimeoutErrStr)
	}
}

func (c *serverConn) processIncomingUniStreams() {
	for {
		uniStream, err := c.quicConn.AcceptUniStream(c.doneOrCancelled)
		if err != nil {
			log.InfoWithError("fail to accept a QUIC unidirectional stream", errors.WithStack(err))
			return
		}
		go func() {
			err = c.handleUniStream(uniStream)
			if err != nil {
				log.InfoWithError("fail to handle a QUIC unidirectional stream", err)
				c.closeWithError(handleUniStreamErrCode, fmt.Sprintf("%v: %v", handleUniStreamErrStr, err.Error()))
			}
		}()
	}
}

func (c *serverConn) handleUniStream(stream quic.ReceiveStream) error {
	_, bs, err := ioutil.ReadN(stream, 2)
	if err != nil {
		return err
	}

	err = validateVersion(bs[0])
	if err != nil {
		return err
	}
	command := bs[1]
	switch command {
	case authCommandType:
		select {
		case <-c.authDone:
			return errors.New("already authenticated")
		default:
		}

		_, authCommandDataBs, err := ioutil.ReadN(stream, authCommandDataSize)
		if err != nil {
			return err
		}
		if !bytes.Equal(authCommandDataBs[0:authCommandUUIDSize], []byte(authCommandUUID)) {
			return errors.New("incorrect UUID '%v' in request authenticate command", uuid.UUID(authCommandDataBs[0:authCommandUUIDSize]))
		}
		token, err := authToken(c.quicConn, []byte(c.server.hg.Password.String))
		if err != nil {
			return err
		}
		if !bytes.Equal(token, authCommandDataBs[authCommandUUIDSize:authCommandDataSize]) {
			return errors.New("incorrect token in request authenticate command")
		}

		close(c.authDone)
		return nil
	default:
		return errors.Newf("unknown command type %v", command)
	}
}

func (c *serverConn) processIncomingStreams() {
	for {
		stream, err := c.quicConn.AcceptStream(c.doneOrCancelled)
		if err != nil {
			log.InfoWithError("fail to accept a QUIC stream", errors.WithStack(err))
			return
		}
		go func() {
			err = c.handleStream(stream)
			if err != nil {
				log.InfoWithError("fail to handle a QUIC stream", errors.WithStack(err))
				c.closeWithError(handleUniStreamErrCode, fmt.Sprintf("%v: %v", handleUniStreamErrStr, err.Error()))
			}
		}()
	}
}

func (c *serverConn) handleStream(stream quic.Stream) error {
	_, bs, err := ioutil.ReadN(stream, 2)
	if err != nil && !errors.IsIoEof(err) {
		return err
	}

	err = validateVersion(bs[0])
	if err != nil {
		return err
	}
	command := bs[1]
	switch command {
	case connectCommandType:
		accessAddr, err := readTUICAddress(stream)
		if err != nil {
			return err
		}

		select {
		case <-c.authDone:
		case <-c.doneOrCancelled.Done():
			return nil
		}
		conn := newConn(c.quicConn, stream, c.quicConn.LocalAddr(), c.quicConn.RemoteAddr(), accessAddr, false)
		return transport.ForwardTCP(c.doneOrCancelled, accessAddr, conn, c.server.targetClient)
	default:
		return errors.Newf("unknown command type %v", command)
	}
}

func (c *serverConn) closeWithError(code quic.ApplicationErrorCode, desc string) {
	c.cancel()
	_ = c.quicConn.CloseWithError(code, desc)
}
