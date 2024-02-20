package ioutil

import (
	"io"
)

type BytesReadPreloadReadWriteCloser struct {
	preload []byte
	rwc     io.ReadWriteCloser
}

var _ io.ReadWriteCloser = new(BytesReadPreloadReadWriteCloser)
var _ io.ReaderFrom = new(BytesReadPreloadReadWriteCloser)
var _ io.WriterTo = new(BytesReadPreloadReadWriteCloser)

func NewBytesReadPreloadReadWriteCloser(preload []byte, rwc io.ReadWriteCloser) *BytesReadPreloadReadWriteCloser {
	return &BytesReadPreloadReadWriteCloser{preload, rwc}
}

func (rwc *BytesReadPreloadReadWriteCloser) Read(p []byte) (n int, err error) {
	if rwc.preload != nil {
		n = copy(p, rwc.preload)
		preloadLen := len(rwc.preload)
		if n == preloadLen {
			rwc.preload = nil
		} else {
			rwc.preload = rwc.preload[n:]
		}
		// return directly because the documentation says:
		// If some data is available but not len(p) bytes, Read conventionally
		// returns what is available instead of waiting for more.
		return n, nil
	}
	return rwc.rwc.Read(p)
}

func (rwc *BytesReadPreloadReadWriteCloser) Write(p []byte) (n int, err error) {
	return rwc.rwc.Write(p)
}

func (rwc *BytesReadPreloadReadWriteCloser) Close() error {
	rwc.preload = nil
	return rwc.rwc.Close()
}

func (rwc *BytesReadPreloadReadWriteCloser) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(rwc.rwc, r)
}

func (rwc *BytesReadPreloadReadWriteCloser) WriteTo(w io.Writer) (n int64, err error) {
	if rwc.preload != nil {
		n, err := w.Write(rwc.preload)
		rwc.preload = nil
		if err != nil {
			return int64(n), err
		}
		n2, err := io.Copy(w, rwc.rwc)
		return int64(n) + n2, err
	}
	return io.Copy(w, rwc.rwc)
}
