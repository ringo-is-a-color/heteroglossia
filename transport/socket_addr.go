package transport

import (
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
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

// not handle IP addr currently

func ToSocketAddrFromNetworkAddr(network, host string) (*SocketAddress, error) {
	host, portStr, err := net.SplitHostPort(host)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	port, err := net.LookupPort(network, portStr)
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

func (addr *SocketAddress) ToHostStr() string {
	port := strconv.Itoa(int(addr.Port))
	switch addr.AddrType {
	case IPv4, IPv6:
		return net.JoinHostPort(addr.IP.String(), port)
	default:
		return net.JoinHostPort(addr.Domain, port)
	}
}
