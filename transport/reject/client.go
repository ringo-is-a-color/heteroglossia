package reject

import (
	"context"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

type Client struct{}

var _ transport.Client = new(Client)
var rejectedErr = errors.New("rejected")

func (_ *Client) Dial(_ context.Context, _ string, _ *transport.SocketAddress) (net.Conn, error) {
	return nil, rejectedErr
}
