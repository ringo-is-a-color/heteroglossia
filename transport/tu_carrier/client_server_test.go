package tu_carrier

import (
	"testing"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/test"
)

func TestClientServerConnection(t *testing.T) {
	test.TestClientServerConnection(t, newClient, NewServer)
}

func newClient(serverConf *conf.Config) (transport.Client, error) {
	return NewClient(test.ToProxyNode(serverConf.Inbounds.Hg), false)
}
