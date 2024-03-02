package socks

import (
	"bytes"
	"encoding/binary"

	"github.com/ringo-is-a-color/heteroglossia/transport"
)

/*
SOCKS5-like address
+------+----------+-----------------+
| ATYP | DST.ADDR |     DST.PORT    |
+------+----------+-----------------+
|  1B  | Variable | 2B (big-endian) |
+------+----------+-----------------+
*/

//goland:noinspection GoNameStartsWithPackageName
func SocksLikeAddrSizeInBytes(addr *transport.SocketAddress) int {
	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// Addr+Port(2)
	// the address data that follows. Depending on type:
	//   4 bytes for IPv4 address
	//   1 byte of name length followed by 1–255 bytes for the domain name
	//   16 bytes for IPv6 address
	switch addr.AddrType {
	case transport.IPv4:
		return 1 + 4 + 2
	case transport.IPv6:
		return 1 + 16 + 2
	default:
		return 1 + 1 + len(addr.Domain) + 2
	}
}

func WriteSocksLikeAddr(buf *bytes.Buffer, addr *transport.SocketAddress) {
	writeAddrType(buf, addr)
	writeAddrAndPort(buf, addr)
}
func writeAddrType(buf *bytes.Buffer, addr *transport.SocketAddress) {
	switch addr.AddrType {
	case transport.IPv4:
		buf.WriteByte(connectionAddressIpv4)
	case transport.IPv6:
		buf.WriteByte(connectionAddressIpv6)
	default:
		buf.WriteByte(connectionAddressDomain)
	}
}

func writeAddrAndPort(buf *bytes.Buffer, addr *transport.SocketAddress) {
	switch addr.AddrType {
	case transport.IPv4, transport.IPv6:
		buf.Write(addr.IP.AsSlice())
	default:
		buf.WriteByte(byte(len(addr.Domain)))
		buf.Write([]byte(addr.Domain))
	}

	bs := make([]byte, 2)
	binary.BigEndian.PutUint16(bs, addr.Port)
	buf.Write(bs)
}
