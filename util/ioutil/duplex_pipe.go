package ioutil

import (
	"io"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

type DuplexPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func NewDuplexPipe() (*DuplexPipe, *DuplexPipe) {
	lr, lw := io.Pipe()
	rr, rw := io.Pipe()
	return &DuplexPipe{
			r: lr,
			w: rw,
		}, &DuplexPipe{
			r: rr,
			w: lw,
		}
}

func (pipe *DuplexPipe) Read(b []byte) (int, error) {
	return pipe.r.Read(b)
}

func (pipe *DuplexPipe) Write(b []byte) (int, error) {
	return pipe.w.Write(b)
}

func (pipe *DuplexPipe) CloseRead() error {
	return pipe.r.Close()
}

func (pipe *DuplexPipe) CloseWrite() error {
	return pipe.w.Close()
}

func (pipe *DuplexPipe) Close() error {
	return errors.Join(pipe.r.CloseWithError(nil), pipe.w.CloseWithError(nil))
}

func (pipe *DuplexPipe) CloseReadWithError(err error) {
	_ = pipe.r.CloseWithError(err)
}

func (pipe *DuplexPipe) CloseWriteWithError(err error) {
	_ = pipe.w.CloseWithError(err)
}
