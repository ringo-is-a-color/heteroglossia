package tls_carrier

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"golang.org/x/crypto/acme/autocert"
)

func tlsConfigWithAutomatedCertificate(ctx context.Context, host string) *tls.Config {
	certManager := autocert.Manager{
		Prompt:      autocert.AcceptTOS,
		Cache:       autocert.DirCache("certs"),
		HostPolicy:  autocert.HostWhitelist(host),
		RenewBefore: 10 * 24 * time.Hour,
	}
	go func() {
		err := netutil.ListenHTTPAndServe(ctx, ":80", certManager.HTTPHandler(nil))
		if err != nil {
			log.Fatal("fail to start a HTTP server for automatic renewing certificate", err)
		}
	}()
	return &tls.Config{GetCertificate: certManager.GetCertificate}
}
