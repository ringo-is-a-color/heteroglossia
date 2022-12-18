package transport

import (
	"io"
	"net"
)

type ConnectionContinuationHandler interface {
	CreateConnection(accessAddr *SocketAddress) (net.Conn, error)
	ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *SocketAddress) error
}
