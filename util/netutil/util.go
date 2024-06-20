package netutil

import (
	"net/http"
	"strings"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

var tcpKeepAlive = 1000 * time.Second
var httpClientTimeout = 60 * time.Second

func HTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}

func ValidateTCPorUDP(network string) error {
	if !strings.HasPrefix(network, "tcp") && !strings.HasPrefix(network, "udp") {
		return errors.Newf("unsupported network: %v", network)
	}
	return nil
}

func ValidateTCP(network string) error {
	if !strings.HasPrefix(network, "tcp") {
		return errors.Newf("unsupported network: %v", network)
	}
	return nil
}
