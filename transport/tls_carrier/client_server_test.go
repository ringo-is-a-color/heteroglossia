package tls_carrier

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

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
			err := ListenRequests(serverConf.Inbounds.Hg, new(direct.TCPReplayHandler))
			assert.Nil(t, err)
		}()
	}

	tlsClient, err := NewTLSCarrierClient(toProxyNode(serverConf.Inbounds.Hg), false)
	assert.Nil(t, err)

	server := startWebServer()
	defer server.Close()
	parse, err := url.Parse(server.URL)
	assert.Nil(t, err)
	port, err := strconv.ParseUint(parse.Port(), 10, 16)
	assert.Nil(t, err)
	conn, err := tlsClient.CreateConnection(transport.NewSocketAddressByDomain(parse.Hostname(), uint16(port)))
	assert.Nil(t, err)

	req, err := http.NewRequest("GET", server.URL, nil)
	assert.Nil(t, err)
	err = req.Write(conn)
	assert.Nil(t, err)
	respReader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(respReader, req)
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
