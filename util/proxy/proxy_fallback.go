//go:build !(darwin || linux)

package proxy

import (
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

func SetSystemProxy(string, uint16, *conf.HTTPSOCKSAuthInfo) (unsetProxy func(), err error) {
	return nil, errors.New("doesn't support the system proxy in this OS")
}
