package direct

import (
	"context"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type client struct{}

var _ transport.Client = new(client)

func NewClient() transport.Client {
	return new(client)
}

func (_ *client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	err := netutil.ValidateTCPorUDP(network)
	if err != nil {
		return nil, err
	}
	return netutil.Dial(ctx, network, addr.ToHostStr())
}
