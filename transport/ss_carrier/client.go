package ss_carrier

import (
	"context"
	"math/rand/v2"
	"net"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/randutil"
)

type Client struct {
	proxyNode    *conf.ProxyNode
	preSharedKey []byte
	aeadOverhead int
	// a function to randomly pick Ex2 and 5 mentioned here https://gfw.report/publications/usenixsecurity23/en/
	exPicker func() int
}

var _ transport.Client = new(Client)

func NewClient(proxyNode *conf.ProxyNode) *Client {
	return &Client{proxyNode, proxyNode.Password.Raw[:], gcmTagOverhead, randutil.WeightedIntN(2)}
}

func (c *Client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	err := netutil.ValidateTCP(network)
	if err != nil {
		return nil, err
	}

	saltSize := len(c.preSharedKey)
	clientSalt, err := randutil.RandNBytes(saltSize)
	if err != nil {
		return nil, err
	}
	c.customFirstReqPrefixes(clientSalt)

	hostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.TCPPort)
	targetConn, err := netutil.DialTCP(ctx, hostWithPort)
	if err != nil {
		return nil, errors.Newf(err, "fail to connect to the TCP server %v", hostWithPort)
	}
	return newAEADClientConn(targetConn, addr, c.preSharedKey, clientSalt, c.aeadOverhead), nil
}

// https://gfw.report/publications/usenixsecurity23/en/
func (c *Client) customFirstReqPrefixes(bs []byte) {
	switch c.exPicker() {
	case 0:
		// Ex2 exemption
		for i := range 6 {
			bs[i] = byte(rand.IntN(0x7e-0x20+1) + 0x20)
		}
	case 1:
		// Ex5 exemption
		pattern := [6]string{"GET ", "HEAD ", "POST ", "PUT ", "\x16\x03\x02", "\x16\x03\x03"}
		copy(bs, pattern[rand.IntN(6)])
	default:
		panic("unreachable code line")
	}
}
