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
	connectionAddressIpv4   byte = 1
	connectionAddressIpv6   byte = 4
	connectionAddressDomain byte = 3
)

func ReadSOCKS5Address(r io.Reader) (dest *transport.SocketAddress, err error) {
	addressType, err := ioutil.Read1(r)
	if err != nil {
		return
	}

	var ip *netip.Addr
	var domain string
	switch addressType {
	case connectionAddressIpv4:
		_, ipv4, err := ioutil.ReadN(r, 4)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom4([4]byte(ipv4))
		ip = &addr
	case connectionAddressIpv6:
		_, ipv6, err := ioutil.ReadN(r, 16)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom16([16]byte(ipv6))
		ip = &addr
	case connectionAddressDomain:
		domain, err = ioutil.ReadStringByUint8(r)
		if err != nil {
			return nil, err
		}
	default:
		err = errors.Newf("unknown address type %v", addressType)
		return
	}
	_, portBs, err := ioutil.ReadN(r, 2)
	if err != nil {
		return
	}

	port := binary.BigEndian.Uint16(portBs)
	if ip != nil {
		return transport.NewSocketAddressByIP(ip, port), nil
	}
	return transport.NewSocketAddressByDomain(domain, port), nil
}
