package ioutil

import (
	"io"
	"net"
)

type BytesReadPreloadConn struct {
	preloadBs []byte
	net.Conn
}

var _ net.Conn = new(BytesReadPreloadConn)
var _ io.ReaderFrom = new(BytesReadPreloadConn)
var _ io.WriterTo = new(BytesReadPreloadConn)

func NewBytesReadPreloadConn(preloadBs []byte, conn net.Conn) net.Conn {
	if len(preloadBs) > 0 {
		return &BytesReadPreloadConn{preloadBs, conn}
	}
	return conn
}

func (c *BytesReadPreloadConn) Read(p []byte) (n int, err error) {
	if len(c.preloadBs) > 0 {
		return c.readFirstPacketWithPreload(p, nil)
	}
	return c.Conn.Read(p)
}

func (c *BytesReadPreloadConn) readFirstPacketWithPreload(p []byte, w io.Writer) (int, error) {
	if w != nil {
		n, err := w.Write(c.preloadBs)
		c.preloadBs = c.preloadBs[n:]
		return n, err
	}
	n := copy(p, c.preloadBs)
	preloadLen := len(c.preloadBs)
	if n == preloadLen {
		c.preloadBs = nil
	} else {
		c.preloadBs = c.preloadBs[n:]
	}
	// Return directly because the documentation says:
	// If some data is available but not len(p) bytes, Read conventionally
	// returns what is available instead of waiting for more.
	// If we try to read here, it will not send the payload bytes and will be stuck in reading.
	// And the server is still waiting for the first request and won't send anything back.
	return n, nil
}

func (c *BytesReadPreloadConn) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(c.Conn, r)
}

func (c *BytesReadPreloadConn) WriteTo(w io.Writer) (n int64, err error) {
	var count int
	if c.preloadBs != nil {
		count, err := c.readFirstPacketWithPreload(nil, w)
		if err != nil {
			return int64(count), err
		}
	}
	n, err = io.Copy(w, c.Conn)
	return n + int64(count), err
}
