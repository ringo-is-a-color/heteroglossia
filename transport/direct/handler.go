package direct

import (
	"io"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type Handler struct{}

var _ transport.ConnectionContinuationHandler = new(Handler)

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	targetConn, err := netutil.DialTCP(accessAddr.ToHostStr())
	if err != nil {
		return errors.WithStack(err)
	}
	return ioutil.Pipe(srcRWC, targetConn)
}
