package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

type SocketAddress struct {
	IP     *netip.Addr
	Domain string
	Port   uint16

	AddrType AddrType
}

type AddrType byte

const (
	IPv4   AddrType = 1
	IPv6   AddrType = 2
	Domain AddrType = 3
)

func NewSocketAddressByIP(ip *netip.Addr, port uint16) *SocketAddress {
	addr := new(SocketAddress)
	addr.IP = ip
	addr.Port = port

	if addr.IP.Is4() {
		addr.AddrType = IPv4
	} else {
		addr.AddrType = IPv6
	}
	return addr
}

func NewSocketAddressByDomain(domain string, port uint16) *SocketAddress {
	addr := new(SocketAddress)
	addr.Domain = domain
	addr.Port = port
	addr.AddrType = Domain
	return addr
}

// https://datatracker.ietf.org/doc/html/rfc1928#section-4
//  +------+----------+----------+
//  | ATYP | DST.ADDR | DST.PORT |
//  +------+----------+----------+
//  |  1   | Variable |    2     |
//  +------+----------+----------+

func ReadAddressWithType(r io.Reader, addressTypeBs [3]byte) (*SocketAddress, error) {
	addressType, err := ioutil.Read1(r)
	if err != nil {
		return nil, err
	}

	var ip *netip.Addr
	var domain string
	switch addressType {
	case addressTypeBs[0]:
		_, ipv4, err := ioutil.ReadN(r, 4)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom4([4]byte(ipv4))
		ip = &addr
	case addressTypeBs[1]:
		_, ipv6, err := ioutil.ReadN(r, 16)
		if err != nil {
			return nil, err
		}
		addr := netip.AddrFrom16([16]byte(ipv6))
		ip = &addr
	case addressTypeBs[2]:
		domain, err = ioutil.ReadStringByUint8(r)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.Newf("unknown address type %v", addressType)
	}
	_, portBs, err := ioutil.ReadN(r, 2)
	if err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBs)
	if ip != nil {
		return NewSocketAddressByIP(ip, port), nil
	}
	return NewSocketAddressByDomain(domain, port), nil
}

// Host examples:
//
// 127.0.0.1
// 127.0.0.1:80
// [::1]
// [::1]:80
// example.com
// example.com:80

func ToSocketAddr(host string, requirePort bool, defaultPort uint16) (*SocketAddress, error) {
	if len(host) == 0 || strings.HasPrefix(host, ":") {
		return nil, errors.New("empty host")
	}

	if !requirePort {
		// IPv4/domain with no port
		if strings.IndexByte(host, ':') == -1 {
			return toSocketAddr(host, defaultPort, false)
		}

		// IPv6 with no port
		if host[0] == '[' && host[len(host)-1] == ']' {
			hostWithBracket := host[1 : len(host)-1]
			return toSocketAddr(hostWithBracket, defaultPort, true)
		}
	}

	// host with port
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return toSocketAddr(host, uint16(port), false)
}

func (addr *SocketAddress) ToHostStr() string {
	port := strconv.Itoa(int(addr.Port))
	switch addr.AddrType {
	case IPv4, IPv6:
		return net.JoinHostPort(addr.IP.String(), port)
	default:
		return net.JoinHostPort(addr.Domain, port)
	}
}

func toSocketAddrFromNetworkAddr(ctx context.Context, network, host string) (*SocketAddress, error) {
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	port, err := net.DefaultResolver.LookupPort(ctx, network, portStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return toSocketAddr(host, uint16(port), false)
}

func toSocketAddr(host string, port uint16, ipv6Required bool) (*SocketAddress, error) {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return NewSocketAddressByDomain(host, port), nil
	}

	if ipv6Required && !ip.Is6() {
		return nil, errors.Newf("require IPv6 address but found %v", host)
	}
	return NewSocketAddressByIP(&ip, port), nil
}
