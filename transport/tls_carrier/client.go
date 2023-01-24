package tls_carrier

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path"
	"strconv"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

type ClientHandler struct {
	proxyNode        *conf.ProxyNode
	tlsConfig        *tls.Config
	passwordWithCRLF [16]byte
}

func NewTLSCarrierClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (*ClientHandler, error) {
	clientHandler := &ClientHandler{proxyNode: proxyNode}
	if proxyNode.TLSCertFile == "" {
		clientHandler.tlsConfig = &tls.Config{
			ServerName: proxyNode.Host,
		}
	} else {
		certBs, err := ioutil.ReadFile(proxyNode.TLSCertFile)
		if err != nil {
			return nil, errors.Wrap(err, "fail to load the TLS certificate file")
		}
		certPool := x509.NewCertPool()
		block, _ := pem.Decode(certBs)
		if block == nil {
			return nil, errors.New("fail to decode the TLS certificate file")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		// https://stackoverflow.com/a/73912711
		if len(cert.DNSNames) == 0 {
			return nil, errors.New("no DNSNames in the TLS certificate file")
		}
		certPool.AppendCertsFromPEM(certBs)
		clientHandler.tlsConfig = &tls.Config{
			RootCAs:    certPool,
			ServerName: cert.DNSNames[0],
		}
	}

	if tlsKeyLog {
		tlsKeyLogPath, err := ioutil.GetPathFromExecutablePath("logs/tls_key_log")
		if err != nil {
			return nil, err
		}
		err = os.MkdirAll(path.Dir(tlsKeyLogPath), 0700)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		tlsKeyLogFile, err := os.OpenFile(tlsKeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		clientHandler.tlsConfig.KeyLogWriter = tlsKeyLogFile
		osutil.RegisterProgramTerminationHandler(func() {
			err := os.Remove(tlsKeyLogPath)
			if err != nil {
				log.WarnWithError("fail to remove the file", err, "path", tlsKeyLogPath)
			}
		})
	}

	clientHandler.passwordWithCRLF = replaceCRLF(proxyNode.Password.Raw)
	return clientHandler, nil
}

var CRLF = []byte{'\r', '\n'}

func (handler *ClientHandler) CreateConnection(accessAddr *transport.SocketAddress) (net.Conn, error) {
	headerLen := 16 + 2 + socksLikeRequestSize(accessAddr)
	bs := make([]byte, 0, headerLen)
	buf := bytes.NewBuffer(bs)
	buf.Write(handler.passwordWithCRLF[:])
	buf.Write(CRLF)
	writeSocksLikeConnectionCommandRequest(buf, accessAddr)

	hostWithPort := handler.proxyNode.Host + ":" + strconv.Itoa(handler.proxyNode.TLSPort)
	conn, err := netutil.DialTCP(hostWithPort)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to connect to the TLS server %v", hostWithPort)
	}
	tlsConn := tls.Client(conn, handler.tlsConfig)

	_, err = buf.WriteTo(buf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &ioutil.BytesReadPreloadConn{Preload: bs[:headerLen], Conn: tlsConn}, nil
}

// https://superuser.com/a/1652039

const TCPMss = 1448

func (handler *ClientHandler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	// len(password) + len(CRLF) = 16 + 2
	headerLen := 16 + 2 + socksLikeRequestSize(accessAddr)
	pooledBs := pool.Get(TCPMss)
	n, err := srcRWC.Read(pooledBs[headerLen:])
	if err != nil {
		return errors.WithStack(err)
	}
	buf := bytes.NewBuffer(pooledBs[:0:headerLen])
	buf.Write(handler.passwordWithCRLF[:])
	buf.Write(CRLF)
	writeSocksLikeConnectionCommandRequest(buf, accessAddr)

	hostWithPort := handler.proxyNode.Host + ":" + strconv.Itoa(handler.proxyNode.TLSPort)
	targetConn, err := netutil.DialTCP(hostWithPort)
	if err != nil {
		return errors.Wrapf(err, "fail to connect to the TLS server %v", hostWithPort)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(targetConn)
	tlsConn := tls.Client(targetConn, handler.tlsConfig)

	_, err = tlsConn.Write(pooledBs[0 : headerLen+n])
	pool.Put(pooledBs)
	if err != nil {
		return errors.WithStack(err)
	}
	return ioutil.Pipe(srcRWC, tlsConn)
}

/*
https://trojan-gfw.github.io/trojan/protocol

SOCKS5-like request
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
*/

func socksLikeRequestSize(addr *transport.SocketAddress) int {
	return 1 + 1 + toLen(addr)
}

func writeSocksLikeConnectionCommandRequest(buf *bytes.Buffer, addr *transport.SocketAddress) {
	buf.WriteByte(socks.ConnectionCommandConnect)
	writeType(buf, addr)
	writeAddrAndPort(buf, addr)
}

func writeType(buf *bytes.Buffer, addr *transport.SocketAddress) {
	switch addr.AddrType {
	case transport.IPv4:
		buf.WriteByte(socks.ConnectionAddressIpv4)
	case transport.IPv6:
		buf.WriteByte(socks.ConnectionAddressIpv6)
	default:
		buf.WriteByte(socks.ConnectionAddressDomain)
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

/*
https://en.wikipedia.org/wiki/SOCKS#SOCKS5

Addr+Port(2)
the address data that follows. Depending on type:
4 bytes for IPv4 address
1 byte of name length followed by 1–255 bytes for the domain name
16 bytes for IPv6 address
*/

func toLen(addr *transport.SocketAddress) int {
	switch addr.AddrType {
	case transport.IPv4:
		return 4 + 2
	case transport.IPv6:
		return 16 + 2
	default:
		return 1 + len(addr.Domain) + 2
	}
}
