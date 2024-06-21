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
type conn struct {
	quicConn quic.Connection
	quic.Stream
	localAddr  net.Addr
	remoteAddr net.Addr
	accessAddr *transport.SocketAddress

	writeLock                 sync.Mutex
	needToWriteConnectCommand bool
}

var _ net.Conn = new(conn)

func newConn(quicConn quic.Connection, quicStream quic.Stream,
	localAddr, remoteAddr net.Addr, accessAddr *transport.SocketAddress,
	isClient bool) *conn {
	return &conn{quicConn: quicConn, Stream: quicStream,
		localAddr: localAddr, remoteAddr: remoteAddr, accessAddr: accessAddr,
		needToWriteConnectCommand: isClient}
}

func (c *conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *conn) Write(p []byte) (n int, err error) {
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
func (c *conn) writeConnectCommand() (int, error) {
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

func (c *conn) connectAddressSizeInBytes() int {
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
func (c *conn) writeConnectAddress(buf *bytes.Buffer) {
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

func (c *conn) Close() error {
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
