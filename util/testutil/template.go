package testutil

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

func TestClientServerConnection(t *testing.T, newClient func(proxyNode *conf.ProxyNode) (transport.Client, error),
	newServer func(hg *conf.Hg, targetClient transport.Client) transport.Server) {
	serverConf, err := conf.Parse("server_example.conf.json")
	assert.Nil(t, err)
	assert.NotNil(t, serverConf.Inbounds.Hg)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		server := newServer(serverConf.Inbounds.Hg, direct.NewClient())
		err := server.ListenAndServe(ctx)
		assert.Nil(t, err)
	}()
	client, err := newClient(toProxyNode(serverConf.Inbounds.Hg))
	assert.Nil(t, err)

	server := startWebServer()
	defer server.Close()
	httpClient := transport.HTTPClientThroughRouter(client)
	resp, err := httpClient.Get(server.URL)

	assert.Nil(t, err)
	assert.True(t, resp.StatusCode >= 200 && resp.StatusCode < 300)
}

func startWebServer() *httptest.Server {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	return httptest.NewServer(handler)
}

func toProxyNode(hg *conf.Hg) *conf.ProxyNode {
	return &conf.ProxyNode{
		Host:        hg.Host,
		Password:    hg.Password,
		TCPPort:     hg.TCPPort,
		TLSPort:     hg.TLSPort,
		TLSCertFile: hg.TLSCertKeyPair.CertFile,
		QUICPort:    hg.QUICPort,
	}
}
