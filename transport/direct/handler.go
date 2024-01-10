package direct

import (
	"io"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type TCPReplayHandler struct{}

var _ transport.ConnectionContinuationHandler = &TCPReplayHandler{}

func (_ *TCPReplayHandler) CreateConnection(accessAddr *transport.SocketAddress) (net.Conn, error) {
	return netutil.DialTCP(accessAddr.ToHostStr())
}

func (handler *TCPReplayHandler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	targetConn, err := handler.CreateConnection(accessAddr)
	if err != nil {
		return errors.WithStack(err)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(targetConn)
	return ioutil.Pipe(srcRWC, targetConn)
}
