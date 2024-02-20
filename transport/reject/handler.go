package reject

import (
	"io"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

type Handler struct{}

var _ transport.ConnectionContinuationHandler = new(Handler)

func (h *Handler) CreateConnection(_ *transport.SocketAddress) (net.Conn, error) {
	return nil, errors.New("Connection rejected")
}

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, _ *transport.SocketAddress) error {
	_ = srcRWC.Close()
	return nil
}
