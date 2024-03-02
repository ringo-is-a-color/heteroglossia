package ioutil

import (
	"io"
)

type BytesReadPreloadReadWriteCloser struct {
	preloadBs []byte
	io.ReadWriteCloser
}

var _ io.ReadWriteCloser = new(BytesReadPreloadReadWriteCloser)
var _ io.ReaderFrom = new(BytesReadPreloadReadWriteCloser)
var _ io.WriterTo = new(BytesReadPreloadReadWriteCloser)

func NewBytesReadPreloadReadWriteCloser(preloadBs []byte, rwc io.ReadWriteCloser) *BytesReadPreloadReadWriteCloser {
	return &BytesReadPreloadReadWriteCloser{preloadBs: preloadBs, ReadWriteCloser: rwc}
}

func (rwc *BytesReadPreloadReadWriteCloser) Read(p []byte) (n int, err error) {
	if len(rwc.preloadBs) > 0 {
		return rwc.readFirstPacketWithPreload(p, nil)
	}
	return rwc.ReadWriteCloser.Read(p)
}

func (rwc *BytesReadPreloadReadWriteCloser) readFirstPacketWithPreload(p []byte, w io.Writer) (int, error) {
	if w != nil {
		n, err := w.Write(rwc.preloadBs)
		rwc.preloadBs = rwc.preloadBs[n:]
		return n, err
	}
	n := copy(p, rwc.preloadBs)
	preloadLen := len(rwc.preloadBs)
	if n == preloadLen {
		rwc.preloadBs = nil
	} else {
		rwc.preloadBs = rwc.preloadBs[n:]
	}
	// Return directly because the documentation says:
	// If some data is available but not len(p) bytes, Read conventionally
	// returns what is available instead of waiting for more.
	// If we try to read here, it will not send the payload bytes and will be stuck in reading.
	// And the server is still waiting for the first request and won't send anything back.
	return n, nil
}

func (rwc *BytesReadPreloadReadWriteCloser) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(rwc.ReadWriteCloser, r)
}

func (rwc *BytesReadPreloadReadWriteCloser) WriteTo(w io.Writer) (n int64, err error) {
	var count int
	if rwc.preloadBs != nil {
		count, err := rwc.readFirstPacketWithPreload(nil, w)
		if err != nil {
			return int64(count), err
		}
	}
	n, err = io.Copy(w, rwc.ReadWriteCloser)
	return n + int64(count), err
}
