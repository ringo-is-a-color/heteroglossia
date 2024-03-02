//go:build !(darwin || linux)

package proxy

import (
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func SetSystemProxy(_ string, _ uint16, _ *conf.HTTPSOCKSAuthInfo) (unsetProxy func(), err error) {
	return nil, errors.New("doesn't support the system proxy in this OS")
}
