package transport

import (
	"context"
	"io"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

type Server interface {
	HandleConnection(ctx context.Context, conn net.Conn, targetClient Client) error
}

func ForwardTCP(ctx context.Context, addr *SocketAddress, srcRwc io.ReadWriteCloser, targetClient Client) error {
	return forward(ctx, "tcp", addr, srcRwc, targetClient)
}

func forward(ctx context.Context, network string, addr *SocketAddress, srcRwc io.ReadWriteCloser, targetClient Client) error {
	select {
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	default:
		targetConn, err := targetClient.Dial(ctx, network, addr)
		if err != nil {
			_ = srcRwc.Close()
			return err
		}
		return ioutil.Pipe(srcRwc, targetConn)
	}
}
