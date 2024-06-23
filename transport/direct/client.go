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

func (*client) DialTCP(ctx context.Context, addr *transport.SocketAddress) (net.Conn, error) {
	return netutil.DialTCP(ctx, addr.ToHostStr())
}
