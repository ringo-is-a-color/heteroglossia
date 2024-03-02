package tls_carrier

import (
	"bufio"
	"net/textproto"
	_ "unsafe"
)

var crlf = []byte{'\r', '\n'}

//go:linkname newTextprotoReader net/http.newTextprotoReader
func newTextprotoReader(_ *bufio.Reader) *textproto.Reader

//go:linkname putTextprotoReader net/http.putTextprotoReader
func putTextprotoReader(_ *textproto.Reader)
