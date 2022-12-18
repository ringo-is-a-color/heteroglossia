package http

import (
	"bufio"
	"net/http"
	_ "unsafe"
)

//go:linkname readRequest net/http.readRequest
func readRequest(_ *bufio.Reader) (req *http.Request, err error)

//go:linkname parseBasicAuth net/http.parseBasicAuth
func parseBasicAuth(_ string) (username, password string, ok bool)
