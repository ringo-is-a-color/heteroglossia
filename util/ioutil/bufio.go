package ioutil

import (
	"bufio"
	"io"
	_ "unsafe"
)

//go:linkname reset bufio.(*Reader).reset
func reset(_ *bufio.Reader, _ []byte, _ io.Reader)

func NewBufioReader(bs []byte, r io.Reader) *bufio.Reader {
	buf := new(bufio.Reader)
	reset(buf, bs, r)
	return buf
}
