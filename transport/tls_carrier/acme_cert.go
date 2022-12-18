package tls_carrier

import (
	"crypto/tls"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"golang.org/x/crypto/acme/autocert"
)

func getTLSConfigWithAutomatedCertificate(host string) (*tls.Config, error) {
	certsStorePath, err := ioutil.GetPathFromExecutablePath("certs")
	if err != nil {
		return nil, err
	}
	certManager := autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache(certsStorePath),
		HostPolicy:  autocert.HostWhitelist(host),
		RenewBefore: 10 * 24 * time.Hour,
	}

	go func() {
		err = netutil.ListenHTTPAndServe(":80", certManager.HTTPHandler(nil))
		if err != nil {
			log.Fatal("fail to start a HTTP server for automatic renewing certificate", err)
		}
	}()
	return &tls.Config{
		GetCertificate: certManager.GetCertificate,
	}, nil
}
