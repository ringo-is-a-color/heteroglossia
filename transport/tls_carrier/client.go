package tls_carrier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path"
	"strconv"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

type Client struct {
	proxyNode           *conf.ProxyNode
	tlsConfig           *tls.Config
	passwordWithoutCRLF [16]byte
}

var _ transport.Client = new(Client)

const tlsKeyLogFilepath = "logs/tls_key.log"

func NewClient(proxyNode *conf.ProxyNode, tlsKeyLog bool) (*Client, error) {
	clientHandler := &Client{proxyNode: proxyNode}
	if proxyNode.TLSCertFile == "" {
		clientHandler.tlsConfig = &tls.Config{
			ServerName: proxyNode.Host,
		}
	} else {
		certBs, err := ioutil.ReadFile(proxyNode.TLSCertFile)
		if err != nil {
			return nil, errors.New(err, "fail to load the TLS certificate file")
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

	clientHandler.passwordWithoutCRLF = replaceCRLF(proxyNode.Password.Raw)
	return clientHandler, nil
}

func (c *Client) Dial(ctx context.Context, network string, addr *transport.SocketAddress) (net.Conn, error) {
	err := netutil.ValidateTCP(network)
	if err != nil {
		return nil, err
	}

	targetHostWithPort := c.proxyNode.Host + ":" + strconv.Itoa(c.proxyNode.TLSPort)
	targetConn, err := netutil.DialTCP(ctx, targetHostWithPort)
	if err != nil {
		return nil, errors.Newf(err, "fail to connect to the TLS server %v", targetHostWithPort)
	}
	tlsConn := tls.Client(targetConn, c.tlsConfig)
	return newClientConn(tlsConn, addr, c.passwordWithoutCRLF), nil
}
