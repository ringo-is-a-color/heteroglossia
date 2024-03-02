package tls_carrier

import (
	"bufio"
	"net/textproto"
	_ "unsafe"
)

var CRLF = []byte{'\r', '\n'}

//go:linkname newTextprotoReader net/http.newTextprotoReader
func newTextprotoReader(br *bufio.Reader) *textproto.Reader

//go:linkname putTextprotoReader net/http.putTextprotoReader
func putTextprotoReader(r *textproto.Reader)
