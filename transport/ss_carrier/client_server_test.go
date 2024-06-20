package ss_carrier

import (
	"testing"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/testutil"
)

func TestClientServerConnection(t *testing.T) {
	testutil.TestClientServerConnection(t, newClient, NewServer)
}

func newClient(proxyNode *conf.ProxyNode) (transport.Client, error) {
	return NewClient(proxyNode), nil
}
