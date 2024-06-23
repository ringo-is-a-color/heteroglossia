package tu_carrier

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/google/uuid"
	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

// one server has n serverQUICConn/quic.Connection
type serverQUICConn struct {
	*server
	quic.Connection

	authDone chan struct{}
}

func (c *serverQUICConn) handleAuthTimeout() {
	select {
	case <-c.authDone:
	case <-c.Context().Done():
	case <-time.After(authTimeout):
		_ = c.CloseWithError(authCommandReceiveTimeoutErrCode, authCommandReceiveTimeoutErrStr)
	}
}

func (c *serverQUICConn) processIncomingUniStreams(ctx context.Context) {
	for {
		uniStream, err := c.AcceptUniStream(ctx)
		if err != nil {
			// this can happen when timeout
			return
		}
		go func() {
			err = c.handleUniStream(uniStream)
			if err != nil {
				log.InfoWithError("fail to handle a QUIC unidirectional stream", err)
				_ = c.CloseWithError(handleUniStreamErrCode, fmt.Sprintf("%v: %v", handleUniStreamErrStr, err.Error()))
			}
		}()
	}
}

func (c *serverQUICConn) handleUniStream(stream quic.ReceiveStream) error {
	command, err := validateVersionAndGetCommandType(stream)
	if err != nil {
		return err
	}
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
		token, err := authToken(c, []byte(c.server.hg.Password.String))
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

func (c *serverQUICConn) processIncomingStreams(ctx context.Context) {
	for {
		stream, err := c.AcceptStream(ctx)
		if err != nil {
			// this can happen when timeout
			return
		}
		go func() {
			err = c.handleStream(ctx, stream)
			if err != nil {
				log.InfoWithError("fail to handle a QUIC stream", errors.WithStack(err))
				_ = c.CloseWithError(handleUniStreamErrCode, fmt.Sprintf("%v: %v", handleUniStreamErrStr, err.Error()))
			}
		}()
	}
}

func (c *serverQUICConn) handleStream(ctx context.Context, stream quic.Stream) error {
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
		case <-ctx.Done():
			return nil
		}
		conn := newServerTCPConn(c, stream, accessAddr)
		return transport.ForwardTCP(ctx, accessAddr, conn, c.server.targetClient)
	default:
		return errors.Newf("unknown command type %v", command)
	}
}

func (c *serverQUICConn) processIncomingDatagram(ctx context.Context) {
	for {
		datagram, err := c.ReceiveDatagram(ctx)
		if err != nil {
			_ = c.CloseWithError(receiveDatagramErrCode, receiveDatagramStreamErrStr)
			return
		}
		err = c.handleDatagram(datagram)
		if err != nil {
			_ = c.CloseWithError(handleUniStreamErrCode, handleUniStreamErrStr)
			return
		}
	}
}

func (c *serverQUICConn) handleDatagram(datagram []byte) error {
	command, err := validateVersionAndGetCommandType(bytes.NewReader(datagram))
	if err != nil {
		return err
	}
	switch command {
	case heartbeatCommandType:
		return nil
	default:
		return errors.Newf("unknown command type %v", command)
	}
}

func (c *serverQUICConn) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	return c.Connection.CloseWithError(code, desc)
}

func validateVersionAndGetCommandType(r io.Reader) (byte, error) {
	_, bs, err := ioutil.ReadN(r, 2)
	if err != nil {
		return 0, err
	}

	err = validateVersion(bs[0])
	if err != nil {
		return 0, err
	}
	return bs[1], nil
}
