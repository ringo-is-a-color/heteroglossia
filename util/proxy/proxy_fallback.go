//go:build !(darwin || linux)

package proxy

import (
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func SetSystemProxy(_ string, _ uint16, _ *transport.HTTPSOCKSAuthInfo) error {
	return errors.New("doesn't support the system proxy in this OS")
}
