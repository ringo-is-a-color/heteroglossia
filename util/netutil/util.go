package netutil

import (
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

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
