package ioutil

import (
	"bufio"
	"io"
	_ "unsafe"
)

//go:linkname reset bufio.(*Reader).reset
func reset(b *bufio.Reader, buf []byte, r io.Reader)

func NewBufioReader(bs []byte, r io.Reader) *bufio.Reader {
	buf := new(bufio.Reader)
	reset(buf, bs, r)
	return buf
}
