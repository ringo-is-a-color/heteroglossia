package transport

import (
	"context"
	"io"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

type Server interface {
	ListenAndServe(ctx context.Context) error
}

func ForwardTCP(ctx context.Context, accessAddr *SocketAddress, srcRwc io.ReadWriteCloser, targetClient Client) error {
	return forward(ctx, "tcp", accessAddr, srcRwc, targetClient)
}

func forward(ctx context.Context, network string, accessAddr *SocketAddress, srcRwc io.ReadWriteCloser, targetClient Client) error {
	select {
	case <-ctx.Done():
		return errors.WithStack(ctx.Err())
	default:
		targetConn, err := targetClient.Dial(ctx, network, accessAddr)
		if err != nil {
			_ = srcRwc.Close()
			return err
		}
		return ioutil.Pipe(srcRwc, targetConn)
	}
}
