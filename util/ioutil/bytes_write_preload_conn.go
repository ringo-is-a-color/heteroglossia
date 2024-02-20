package ioutil

import (
	"io"
	"net"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
)

type BytesReadPreloadConn struct {
	preload []byte
	conn    net.Conn
}

var _ net.Conn = new(BytesReadPreloadConn)
var _ io.ReaderFrom = new(BytesReadPreloadConn)
var _ io.WriterTo = new(BytesReadPreloadConn)

func NewBytesReadPreloadConn(preload []byte, conn net.Conn) *BytesReadPreloadConn {
	return &BytesReadPreloadConn{preload, conn}
}

func (conn *BytesReadPreloadConn) Read(p []byte) (n int, err error) {
	return conn.conn.Read(p)
}

func (conn *BytesReadPreloadConn) Write(p []byte) (n int, err error) {
	if conn.preload != nil {
		bs := pool.Get(len(conn.preload) + len(p))[:0]
		defer pool.Put(bs)
		bs = append(bs, conn.preload...)
		bs = append(bs, p...)
		conn.preload = nil
		return conn.conn.Write(bs)
	}
	return conn.conn.Write(p)
}

func (conn *BytesReadPreloadConn) Close() error {
	conn.preload = nil
	return conn.conn.Close()
}

func (conn *BytesReadPreloadConn) LocalAddr() net.Addr {
	return conn.conn.LocalAddr()
}

func (conn *BytesReadPreloadConn) RemoteAddr() net.Addr {
	return conn.conn.RemoteAddr()
}

func (conn *BytesReadPreloadConn) SetDeadline(t time.Time) error {
	return conn.conn.SetDeadline(t)
}

func (conn *BytesReadPreloadConn) SetReadDeadline(t time.Time) error {
	return conn.conn.SetReadDeadline(t)
}

func (conn *BytesReadPreloadConn) SetWriteDeadline(t time.Time) error {
	return conn.conn.SetWriteDeadline(t)
}

func (conn *BytesReadPreloadConn) ReadFrom(r io.Reader) (n int64, err error) {
	if conn.preload != nil {
		n, err := conn.conn.Write(conn.preload)
		conn.preload = nil
		if err != nil {
			return int64(n), err
		}
		n2, err := io.Copy(conn.conn, r)
		return int64(n) + n2, err
	}
	return io.Copy(conn.conn, r)
}

func (conn *BytesReadPreloadConn) WriteTo(w io.Writer) (n int64, err error) {
	return io.Copy(w, conn.conn)
}
