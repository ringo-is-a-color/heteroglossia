package tls_carrier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	_ "github.com/flashlabs/rootpath"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/direct"
	"github.com/stretchr/testify/assert"
)

func TestClientServerConnection(t *testing.T) {
	serverConf, err := conf.Parse("server_example.conf.json")
	assert.Nil(t, err)
	if serverConf.Inbounds.Hg != nil {
		go func() {
			err := ListenRequests(context.Background(), serverConf.Inbounds.Hg, new(direct.Client))
			assert.Nil(t, err)
		}()
	}
	tlsClient, err := NewClient(toProxyNode(serverConf.Inbounds.Hg), false)
	assert.Nil(t, err)
	server := startWebServer()
	defer server.Close()

	httpClient := transport.HTTPClientThroughRouter(tlsClient)
	resp, err := httpClient.Get(server.URL)

	assert.Nil(t, err)
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300)
}

func toProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:        hg.Host,
		Password:    hg.Password,
		TLSPort:     hg.TLSPort,
		TLSCertFile: hg.TLSCertKeyPair.CertFile,
	}
}

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
}
