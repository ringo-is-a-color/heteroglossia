package tu_carrier

import (
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

// forked from https://github.com/cloudflare/cloudflared/blob/354a5bb8afb16be9fa260c4eb28d4d1778f655bc/quic/safe_stream.go
type tcpConn struct {
	quicConn quic.Connection
	quic.Stream
	accessAddr *transport.SocketAddress

	writeLock                 sync.Mutex
	needToWriteConnectCommand bool
	connCloseCallback         func()
}

var _ net.Conn = new(tcpConn)

func newClientTCPConn(quicConn quic.Connection, quicStream quic.Stream, accessAddr *transport.SocketAddress, connCloseCallback func()) *tcpConn {
	return &tcpConn{quicConn: quicConn, Stream: quicStream, accessAddr: accessAddr,
		needToWriteConnectCommand: true, connCloseCallback: connCloseCallback}
}

func newServerTCPConn(quicConn quic.Connection, quicStream quic.Stream, accessAddr *transport.SocketAddress) *tcpConn {
	return &tcpConn{quicConn: quicConn, Stream: quicStream, accessAddr: accessAddr, needToWriteConnectCommand: false}
}

func (c *tcpConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *tcpConn) RemoteAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *tcpConn) Write(p []byte) (n int, err error) {
	c.writeLock.Lock()
	defer c.writeLock.Unlock()
	if c.needToWriteConnectCommand {
		c.needToWriteConnectCommand = false
		_, err := c.writeConnectCommand()
		if err != nil {
			_ = c.quicConn.CloseWithError(connectCommandSendErrCode, connectCommandSendErrStr)
			return 0, err
		}
	}
	return ioutil.Write(c.Stream, p)
}

/*
https://github.com/EAimTY/tuic/blob/dev/SPEC.md#authenticate
+----------+
|   ADDR   |
+----------+
| Variable |
+----------+
*/
func (c *tcpConn) writeConnectCommand() (int, error) {
	// 16 + 2 = len(password) + len(CRLF)
	// we don't write the second CRLF like Trojan protocol
	connectCommandSize := 2 + c.connectAddressSizeInBytes()
	connectCommandBs := make([]byte, connectCommandSize)

	connectCommandBs[0] = tuicVersion
	connectCommandBs[1] = connectCommandType
	addressBuf := bytes.NewBuffer(connectCommandBs[2:2])
	c.writeConnectAddress(addressBuf)

	n, err := ioutil.Write(c.Stream, connectCommandBs)
	if err != nil {
		return n, errors.WithStack(err)
	}
	return n, nil
}

func (c *tcpConn) connectAddressSizeInBytes() int {
	return socks.SOCKSLikeAddrSizeInBytes(c.accessAddr)
}

/*
https://github.com/EAimTY/tuic/blob/dev/SPEC.md#address
+------+----------+----------+
| TYPE |   ADDR   |   PORT   |
+------+----------+----------+
|  1   | Variable |    2     |
+------+----------+----------+
* 0x00: fully-qualified domain name
* 0x01: IPv4 address
* 0x02: IPv6 address
*/
func (c *tcpConn) writeConnectAddress(buf *bytes.Buffer) {
	socks.WriteSOCKSLikeAddr(buf, c.accessAddr)
	bufBs := buf.Bytes()
	switch c.accessAddr.AddrType {
	case transport.IPv4:
		bufBs[0] = 0x01
	case transport.IPv6:
		bufBs[0] = 0x02
	default:
		bufBs[0] = 0x00
	}
}

func (c *tcpConn) Close() error {
	// Make sure a possible writer does not block the lock forever. We need it, so we can close the writer
	// side of the stream safely.
	_ = c.Stream.SetWriteDeadline(time.Now())

	// This lock is eventually acquired despite Write also acquiring it, because we set a deadline to write.
	c.writeLock.Lock()
	defer c.writeLock.Unlock()

	// We have to clean up the receiving stream ourselves since the Close in the bottom does not handle that.
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}
