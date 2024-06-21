package transport

import (
	"context"
	"net"
	"net/http"

	"github.com/ringo-is-a-color/heteroglossia/util/contextutil"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

type Client interface {
	// support 'tcp*' and 'udp*' networks only

	Dial(ctx context.Context, network string, addr *SocketAddress) (net.Conn, error)
}

func HTTPClientThroughRouter(client Client) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		err := netutil.ValidateTCPorUDP(network)
		if err != nil {
			return nil, err
		}
		addrStr, err := toSocketAddrFromNetworkAddr(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		ctx = contextutil.WithSourceAndInboundValues(ctx, "hg binary itself", "internal HTTP Client")
		return client.Dial(ctx, network, addrStr)
	}
	return netutil.HTTPClient(tr)
}
