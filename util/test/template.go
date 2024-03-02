package test

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

func TestClientServerConnection(t *testing.T, newClient func(serverConf *conf.Config) (transport.Client, error),
	listenRequest func(ctx context.Context, hg *conf.Hg, targetClient transport.Client) error) {
	serverConf, err := conf.Parse("server_example.conf.json")
	assert.Nil(t, err)
	if serverConf.Inbounds.Hg != nil {
		go func() {
			err := listenRequest(context.Background(), serverConf.Inbounds.Hg, new(direct.Client))
			assert.Nil(t, err)
		}()
	}
	client, err := newClient(serverConf)
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
