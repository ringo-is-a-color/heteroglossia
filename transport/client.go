package transport

import (
	"context"
	"net"
	"net/http"

	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type Client interface {
	DialTCP(ctx context.Context, addr *SocketAddress) (net.Conn, error)
}

func HTTPClientThroughRouter(client Client) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		addrStr, err := toSocketAddrFromNetworkAddr(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		ctx = contextutil.WithSourceAndInboundValues(ctx, "hg binary itself", "internal HTTP Client")
		return client.DialTCP(ctx, addrStr)
	}
	return netutil.HTTPClient(tr)
}
