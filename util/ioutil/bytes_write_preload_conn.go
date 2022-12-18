package ioutil

import (
	"io"
	"net"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
)

type BytesReadPreloadConn struct {
	Preload []byte
	Conn    net.Conn
}

func (conn *BytesReadPreloadConn) Read(p []byte) (n int, err error) {
	return conn.Conn.Read(p)
}

func (conn *BytesReadPreloadConn) Write(p []byte) (n int, err error) {
	if conn.Preload != nil {
		pooledBs := pool.Get(len(conn.Preload) + len(p))[:0]
		defer pool.Put(pooledBs)
		pooledBs = append(pooledBs, conn.Preload...)
		pooledBs = append(pooledBs, p...)
		conn.Preload = nil
		return conn.Conn.Write(pooledBs)
	}
	return conn.Conn.Write(p)
}

func (conn *BytesReadPreloadConn) WriteTo(w io.Writer) (n int64, err error) {
	return io.Copy(w, conn.Conn)
}
func (conn *BytesReadPreloadConn) ReadFrom(r io.Reader) (n int64, err error) {
	if conn.Preload != nil {
		n, err := conn.Conn.Write(conn.Preload)
		conn.Preload = nil
		if err != nil {
			return int64(n), err
		}
		n2, err := io.Copy(conn.Conn, r)
		return int64(n) + n2, err
	}
	return io.Copy(conn.Conn, r)
}

func (conn *BytesReadPreloadConn) Close() error {
	conn.Preload = nil
	return conn.Conn.Close()
}

func (conn *BytesReadPreloadConn) LocalAddr() net.Addr {
	return conn.Conn.LocalAddr()
}

func (conn *BytesReadPreloadConn) RemoteAddr() net.Addr {
	return conn.Conn.RemoteAddr()
}

func (conn *BytesReadPreloadConn) SetDeadline(t time.Time) error {
	return conn.Conn.SetDeadline(t)
}

func (conn *BytesReadPreloadConn) SetReadDeadline(t time.Time) error {
	return conn.Conn.SetReadDeadline(t)
}

func (conn *BytesReadPreloadConn) SetWriteDeadline(t time.Time) error {
	return conn.Conn.SetWriteDeadline(t)
}
