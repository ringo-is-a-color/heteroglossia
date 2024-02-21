package transport

import (
	"io"
)

type ConnectionContinuationHandler interface {
	ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *SocketAddress) error
}
