//go:build !(darwin || linux)

package proxy

import (
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

func SetSystemProxy(_ string, _ uint16, _ *transport.HTTPSOCKSAuthInfo) error {
	log.Info("doesn't support the system proxy in this OS")
	return nil
}
