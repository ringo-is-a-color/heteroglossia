package socks

import (
	"encoding/binary"
	"io"
	"net/netip"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

const (
	ConnectionAddressIpv4   byte = 1
	ConnectionAddressIpv6   byte = 4
	ConnectionAddressDomain byte = 3
)

func ReadSOCKS5Address(r io.Reader) (dest *transport.SocketAddress, err error) {
	addressType, err := ioutil.Read1(r)
	if err != nil {
		return
	}

	var ip *netip.Addr
	var domain string
	switch addressType {
	case ConnectionAddressIpv4:
		ipv4, err := ioutil.ReadN(r, 4)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom4([4]byte(ipv4))
		ip = &addr
	case ConnectionAddressIpv6:
		ipv6, err := ioutil.ReadN(r, 16)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom16([16]byte(ipv6))
		ip = &addr
	case ConnectionAddressDomain:
		domain, err = ioutil.ReadStringByUint8(r)
		if err != nil {
			return nil, err
		}
	default:
		err = errors.Newf("unknown address type %v", addressType)
		return
	}
	portBs, err := ioutil.ReadN(r, 2)
	if err != nil {
		return
	}

	port := binary.BigEndian.Uint16(portBs)
	if ip != nil {
		return transport.NewSocketAddressByIP(ip, port), nil
	}
	return transport.NewSocketAddressByDomain(domain, port), nil
}
