package netutil

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path"
	"sync"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/osutil"
)

var (
	tlsClientConfigMap      = make(map[string]*tls.Config)
	tlsClientConfigMapMutex sync.Mutex

	tlsServerConfigMap      = make(map[string]*tls.Config)
	tlsServerConfigMapMutex sync.Mutex
)

const tlsKeyLogFilepath = "logs/tls_key.log"

func TLSClientConfig(proxyNode *conf.ProxyNode, tlsKeyLog bool) (*tls.Config, error) {
	tlsClientConfigMapMutex.Lock()
	defer tlsClientConfigMapMutex.Unlock()
	tlsConfig, ok := tlsClientConfigMap[proxyNode.Host]
	if ok {
		return tlsConfig, nil
	}

	if proxyNode.TLSCertFile == "" {
		tlsConfig = &tls.Config{ServerName: proxyNode.Host}
	} else {
		certBs, err := ioutil.ReadFile(proxyNode.TLSCertFile)
		if err != nil {
			return nil, errors.New(err, "fail to load the TLS certificate file")
		}
		certPool := x509.NewCertPool()
		block, _ := pem.Decode(certBs)
		if block == nil {
			return nil, errors.New(err, "fail to decode the TLS certificate file")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, errors.New(err, "fail to parse the TLS certificate")
		}
		// https://stackoverflow.com/a/73912711
		if len(cert.DNSNames) == 0 {
			return nil, errors.New(err, "no DNSNames in the TLS certificate")
		}
		certPool.AppendCertsFromPEM(certBs)
		tlsConfig = &tls.Config{
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
			return nil, errors.WithStack(err)
		}
		tlsConfig.KeyLogWriter = tlsKeyLogFile

		if len(tlsClientConfigMap) == 0 {
			osutil.RegisterProgramTerminationHandler(func() {
				err := os.Remove(tlsKeyLogFilepath)
				if err != nil {
					log.WarnWithError("fail to remove the file", err, "path", tlsKeyLogFilepath)
				}
			})
		}
	}

	tlsClientConfigMap[proxyNode.Host] = tlsConfig
	return tlsConfig, nil
}

func TLSServerConfig(hg *conf.Hg) (*tls.Config, error) {
	tlsServerConfigMapMutex.Lock()
	defer tlsServerConfigMapMutex.Unlock()
	tlsConfig, ok := tlsServerConfigMap[hg.Host]
	if ok {
		return tlsConfig, nil
	}

	if hg.TLSCertKeyPair == nil {
		// use context.Background() for reusing the same tls.Config for different server types,
		// otherwise cancel one context can stop tls.Config used by others
		tlsConfig = tlsConfigWithAutomatedCertificate(context.Background(), hg.Host)
	} else {
		cert, err := tls.LoadX509KeyPair(hg.TLSCertKeyPair.CertFile, hg.TLSCertKeyPair.KeyFile)
		if err != nil {
			return nil, errors.New(err, "fail to load TLS Certificate/Key pair files")
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	tlsServerConfigMap[hg.Host] = tlsConfig
	return tlsConfig, nil
}
