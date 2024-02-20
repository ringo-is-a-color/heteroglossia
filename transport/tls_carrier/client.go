package tls_carrier

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
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

type Handler struct {
	proxyNode        *conf.ProxyNode
	tlsConfig        *tls.Config
	passwordWithCRLF [16]byte
}

var _ transport.ConnectionContinuationHandler = new(Handler)

const tlsKeyLogFilepath = "logs/tls_key.log"

func NewTLSCarrierClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (*Handler, error) {
	clientHandler := &Handler{proxyNode: proxyNode}
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
		err := os.MkdirAll(path.Dir(tlsKeyLogFilepath), 0700)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		tlsKeyLogFile, err := os.OpenFile(tlsKeyLogFilepath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, err
		}
		clientHandler.tlsConfig.KeyLogWriter = tlsKeyLogFile
		osutil.RegisterProgramTerminationHandler(func() {
			err := os.Remove(tlsKeyLogFilepath)
			if err != nil {
				log.WarnWithError("fail to remove the file", err, "path", tlsKeyLogFilepath)
			}
		})
	}

	clientHandler.passwordWithCRLF = replaceCRLF(proxyNode.Password.Raw)
	return clientHandler, nil
}

var CRLF = []byte{'\r', '\n'}

func (h *Handler) CreateConnection(accessAddr *transport.SocketAddress) (net.Conn, error) {
	headerSize := 16 + 2 + socksLikeRequestSizeInBytes(accessAddr)
	bs := make([]byte, 0, headerSize)
	// use a buffer as a view for bytes
	buf := bytes.NewBuffer(bs)
	buf.Write(h.passwordWithCRLF[:])
	buf.Write(CRLF)
	writeSocksLikeConnectionCommandRequest(buf, accessAddr)

	hostWithPort := h.proxyNode.Host + ":" + strconv.Itoa(h.proxyNode.TLSPort)
	conn, err := netutil.DialTCP(hostWithPort)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to connect to the TLS server %v", hostWithPort)
	}
	tlsConn := tls.Client(conn, h.tlsConfig)

	return ioutil.NewBytesReadPreloadConn(bs[:headerSize], tlsConn), nil
}

/*
https://trojan-gfw.github.io/trojan/protocol

+-----------------------+---------+----------------+---------+----------+
| hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
+-----------------------+---------+----------------+---------+----------+
|          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
+-----------------------+---------+----------------+---------+----------+
*/

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	// len(password) + len(CRLF) = 16 + 2
	headerSize := 16 + 2 + socksLikeRequestSizeInBytes(accessAddr)
	firstPacketBs := pool.Get(ioutil.TCPBufSize)
	pooledBsRecycled := false
	defer func() {
		if !pooledBsRecycled {
			pool.Put(firstPacketBs)
		}
	}()
	n, err := srcRWC.Read(firstPacketBs[headerSize:])
	if err != nil {
		return errors.WithStack(err)
	}
	buf := bytes.NewBuffer(firstPacketBs[:0])
	buf.Write(h.passwordWithCRLF[:])
	buf.Write(CRLF)
	writeSocksLikeConnectionCommandRequest(buf, accessAddr)

	hostWithPort := h.proxyNode.Host + ":" + strconv.Itoa(h.proxyNode.TLSPort)
	targetConn, err := netutil.DialTCP(hostWithPort)
	if err != nil {
		return errors.Wrapf(err, "fail to connect to the TLS server %v", hostWithPort)
	}
	defer func(conn net.Conn) {
		_ = conn.Close()
	}(targetConn)
	tlsConn := tls.Client(targetConn, h.tlsConfig)

	_, err = tlsConn.Write(firstPacketBs[0 : headerSize+n])
	pool.Put(firstPacketBs)
	pooledBsRecycled = true
	if err != nil {
		return errors.WithStack(err)
	}
	return ioutil.Pipe(srcRWC, tlsConn)
}

/*
SOCKS5-like request
+-----+------+----------+----------+
| CMD | ATYP | DST.ADDR | DST.PORT |
+-----+------+----------+----------+
|  1  |  1   | Variable |    2     |
+-----+------+----------+----------+
*/

func socksLikeRequestSizeInBytes(addr *transport.SocketAddress) int {
	return 1 + socks.SocksLikeAddrSizeInBytes(addr)
}

func writeSocksLikeConnectionCommandRequest(buf *bytes.Buffer, addr *transport.SocketAddress) {
	buf.WriteByte(socks.ConnectionCommandConnect)
	socks.WriteSocksLikeAddr(buf, addr)
}
