package netutil

import (
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

// https://superuser.com/a/1652039
// Use a TCP MSS value because it may cover the most common case

const BufSize = 1448

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
