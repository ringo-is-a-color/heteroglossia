package tr_carrier

import (
	"bytes"
	"io"
	"net"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

type clientConn struct {
	net.Conn
	accessAddr           *transport.SocketAddress
	passwordWithCRLF     [16]byte
	hasWriteFirstPayload bool
}

var _ net.Conn = new(clientConn)
var _ io.ReaderFrom = new(clientConn)
var _ io.WriterTo = new(clientConn)

func newClientConn(conn net.Conn, accessAddr *transport.SocketAddress, passwordWithoutCRLF [16]byte) *clientConn {
	return &clientConn{conn, accessAddr, passwordWithoutCRLF, false}
}

func (c *clientConn) Write(b []byte) (n int, err error) {
	if !c.hasWriteFirstPayload {
		c.hasWriteFirstPayload = true
		return c.writeClientFirstPayload(b)
	}
	return c.Conn.Write(b)
}

/*
https://trojan-gfw.github.io/trojan/protocol

+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
*/

func (c *clientConn) writeClientFirstPayload(payload []byte) (int, error) {
	// 16 + 2 = len(password) + len(CRLF)
	// we don't write the second CRLF like Trojan protocol
	headerSize := 16 + 2 + socksLikeRequestSizeInBytes(c.accessAddr)
	firstPayloadBs := pool.Get(headerSize + len(payload))
	defer pool.Put(firstPayloadBs)

	buf := bytes.NewBuffer(firstPayloadBs[:0])
	buf.Write(c.passwordWithCRLF[:])
	buf.Write(crlf)
	writeSocksLikeConnectionCommandRequest(buf, c.accessAddr)
	buf.Write(payload)

	count, err := buf.WriteTo(c.Conn)
	n := int(max(count-int64(headerSize), 0))
	return n, errors.WithStack(err)
}

func (c *clientConn) ReadFrom(r io.Reader) (n int64, err error) {
	var count int
	if !c.hasWriteFirstPayload {
		c.hasWriteFirstPayload = true
		firstPayloadBs := pool.Get(ioutil.BufSize)

		for {
			count, err = r.Read(firstPayloadBs)
			if err != nil && !errors.IsIoEof(err) {
				pool.Put(firstPayloadBs)
				return int64(count), err
			}
			if count > 0 || errors.IsIoEof(err) {
				break
			}
		}
		_, err = c.writeClientFirstPayload(firstPayloadBs[:count])
		pool.Put(firstPayloadBs)
		if err != nil {
			return int64(count), err
		}
	}
	n, err = io.Copy(c.Conn, r)
	return n + int64(count), err
}

func (c *clientConn) WriteTo(w io.Writer) (n int64, err error) {
	return io.Copy(w, c.Conn)
}

/*
SOCKS5-like request
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
*/

func socksLikeRequestSizeInBytes(addr *transport.SocketAddress) int {
	return 1 + socks.SocksLikeAddrSizeInBytes(addr)
}

func writeSocksLikeConnectionCommandRequest(buf *bytes.Buffer, addr *transport.SocketAddress) {
	buf.WriteByte(socks.ConnectionCommandConnect)
	socks.WriteSocksLikeAddr(buf, addr)
}
