package tu_carrier

import (
	"bytes"
	"sync/atomic"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

// one client has one clientQUICConn/quic.Connection
type clientQUICConn struct {
	client          *client
	quic.Connection // avoid using client.quicConn from this directly to avoid concurrency issues

	relayingTaskCount atomic.Uint64
}

func (c *clientQUICConn) sendAuthenticationCommand() (err error) {
	sendStream, err := c.OpenUniStream()
	if err != nil {
		return errors.WithStack(err)
	}
	authToken, err := authToken(c, []byte(c.client.proxyNode.Password.String))
	if err != nil {
		return err
	}

	authBs := pool.Get(1 + 1 + authCommandDataSize)
	defer pool.Put(authBs)
	authBuf := bytes.NewBuffer(authBs[:0])
	authBuf.WriteByte(tuicVersion)
	authBuf.WriteByte(authCommandType)
	authBuf.WriteString(authCommandUUID)
	authBuf.Write(authToken)
	_, err = authBuf.WriteTo(sendStream)
	if err != nil {
		return errors.WithStack(err)
	}
	_ = sendStream.Close()
	return nil
}

func (c *clientQUICConn) sendHeartbeats() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.Context().Done():
			return
		case <-ticker.C:
			if c.relayingTaskCount.Load() != 0 {
				err := c.SendDatagram([]byte{tuicVersion, heartbeatCommandType})
				if err != nil {
					log.InfoWithError("fail to send a datagram", err)
					_ = c.CloseWithError(heartbeatCommandSendErrCode, heartbeatCommandSendErrStr)
				}
			}
		}
	}
}

func (c *clientQUICConn) CloseWithError(code quic.ApplicationErrorCode, desc string) error {
	c.client.quicConnMutex.Lock()
	c.client.quicConn = nil
	c.client.quicConnMutex.Unlock()
	return c.Connection.CloseWithError(code, desc)
}
