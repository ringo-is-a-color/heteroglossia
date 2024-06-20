package socks

import (
	"io"

	"github.com/ringo-is-a-color/heteroglossia/transport"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc1928#section-4
	// ATYP   address type of following address
	//   o  IP V4 address: X'01'
	//   o  DOMAINNAME: X'03'
	//   o  IP V6 address: X'04'
	connectionAddressIpv4   byte = 0x01
	connectionAddressIpv6   byte = 0x04
	connectionAddressDomain byte = 0x03
)

var socksAddressType = [3]byte{connectionAddressIpv4, connectionAddressIpv6, connectionAddressDomain}

func ReadSOCKS5Address(r io.Reader) (dest *transport.SocketAddress, err error) {
	return transport.ReadAddressWithType(r, socksAddressType)
}
