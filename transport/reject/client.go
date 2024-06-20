package reject

import (
	"context"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

type client struct{}

var _ transport.Client = new(client)

func NewClient() transport.Client {
	return new(client)
}

var rejectedErr = errors.New("rejected")

func (*client) Dial(_ context.Context, _ string, _ *transport.SocketAddress) (net.Conn, error) {
	return nil, rejectedErr
}
