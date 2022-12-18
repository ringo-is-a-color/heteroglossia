package ioutil

import (
	"io"
)

type BytesReadPreloadReadWriteCloser struct {
	Preload []byte
	RWC     io.ReadWriteCloser
}

func (rwc *BytesReadPreloadReadWriteCloser) Read(p []byte) (n int, err error) {
	if rwc.Preload != nil {
		n = copy(p, rwc.Preload)
		preloadLen := len(rwc.Preload)
		if n == preloadLen {
			rwc.Preload = nil
		} else {
			rwc.Preload = rwc.Preload[n:]
		}
		if n < len(p) {
			n2, err := rwc.RWC.Read(p[n:])
			return n + n2, err
		}
		return n, nil
	}
	return rwc.RWC.Read(p)
}

func (rwc *BytesReadPreloadReadWriteCloser) Write(p []byte) (n int, err error) {
	return rwc.RWC.Write(p)
}

func (rwc *BytesReadPreloadReadWriteCloser) WriteTo(w io.Writer) (n int64, err error) {
	if rwc.Preload != nil {
		n, err := w.Write(rwc.Preload)
		rwc.Preload = nil
		if err != nil {
			return int64(n), err
		}
		n2, err := io.Copy(w, rwc.RWC)
		return int64(n) + n2, err
	}
	return io.Copy(w, rwc.RWC)
}

func (rwc *BytesReadPreloadReadWriteCloser) ReadFrom(r io.Reader) (n int64, err error) {
	return io.Copy(rwc.RWC, r)
}

func (rwc *BytesReadPreloadReadWriteCloser) Close() error {
	rwc.Preload = nil
	return rwc.RWC.Close()
}
