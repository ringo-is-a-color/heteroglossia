package http_socks

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport/direct"
	"github.com/stretchr/testify/assert"
)

const (
	proxyServerAddr = "[::1]:2080"
	webServerPort   = ":2081"
)

var (
	proxyProtocolPrefix string
	accessURL           string
	accessAddrs         = []string{"127.0.0.1", "[::ffff:127.0.0.1]", "[::1]", "localhost"}

	authInfo      = &conf.HTTPSOCKSAuthInfo{Username: "username", Password: "password"}
	wrongAuthInfo = &conf.HTTPSOCKSAuthInfo{Username: "username", Password: "password1"}
)

func init() {
	go startWebServer(webServerPort)
}

func TestProxyConnectionHandle(t *testing.T) {
	proxyProtocolInfo := []struct {
		proxyProtocolName   string
		proxyProtocolPrefix string
	}{
		{"HTTP", "http://"},
		{"Socks5", "socks5h://"},
	}

	for _, i := range proxyProtocolInfo {
		proxyProtocolPrefix = i.proxyProtocolPrefix
		for _, addr := range accessAddrs {
			accessURL = "http://" + addr + webServerPort
			name := addr + " via " + i.proxyProtocolName
			t.Run(name, testHandleConnectionWithoutAuthInfo)
			t.Run(name, testHandleConnectionWithEmptyAuthInfo)
			t.Run(name, testHandleConnectionWithAuthInfo)
			t.Run(name, testHandleConnectionWithIncorrectAuthInfo)
		}
	}
}

func testHandleConnectionWithoutAuthInfo(t *testing.T) {
	err1, err2 := parRun(func() error {
		return startProxyServer(t, nil)
	}, func() error {
		return startClient(nil)
	})

	assert.Nil(t, err1)
	assert.Nil(t, err2)
}

func testHandleConnectionWithEmptyAuthInfo(t *testing.T) {
	err1, err2 := parRun(func() error {
		return startProxyServer(t, &conf.HTTPSOCKSAuthInfo{})
	}, func() error {
		return startClient(nil)
	})

	assert.Nil(t, err1)
	assert.Nil(t, err2)
}

func testHandleConnectionWithAuthInfo(t *testing.T) {
	err1, err2 := parRun(func() error {
		return startProxyServer(t, authInfo)
	}, func() error {
		return startClient(authInfo)
	})

	assert.Nil(t, err1)
	assert.Nil(t, err2)
}

func testHandleConnectionWithIncorrectAuthInfo(t *testing.T) {
	err1, err2 := parRun(func() error {
		return startProxyServer(t, authInfo)
	}, func() error {
		return startClient(wrongAuthInfo)
	})

	assert.NotNil(t, err1)
	assert.NotNil(t, err2)
}

func startProxyServer(t *testing.T, authInfo *conf.HTTPSOCKSAuthInfo) error {
	ln, err := net.Listen("tcp", proxyServerAddr)
	if err != nil {
		return err
	}
	defer func(ln net.Listener) {
		err := ln.Close()
		assert.Nil(t, err)
	}(ln)

	rwc, err := ln.Accept()
	if err != nil {
		return err
	}

	var httpSOCKS *conf.HTTPSOCKS
	if authInfo == nil {
		httpSOCKS = &conf.HTTPSOCKS{}
	} else {
		httpSOCKS = &conf.HTTPSOCKS{Username: authInfo.Username, Password: authInfo.Password}
	}
	return (NewServer(httpSOCKS, direct.NewClient()).(*server)).Serve(context.Background(), rwc)
}

func startClient(authInfo *conf.HTTPSOCKSAuthInfo) error {
	var proxyUser string
	if authInfo.IsEmpty() {
		proxyUser = ""
	} else {
		proxyUser = fmt.Sprintf("-U %v:%v", authInfo.Username, authInfo.Password)
	}

	cmd := fmt.Sprintf("curl -fx %v %v %v", proxyProtocolPrefix+proxyServerAddr, proxyUser, accessURL)
	args := strings.Fields(cmd)
	_, err := exec.Command(args[0], args[1:]...).Output()
	return err
}

func startWebServer(listenPort string) {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	_ = http.ListenAndServe(listenPort, nil)
}

func parRun[X, Y any](f1 func() X, f2 func() Y) (X, Y) {
	x := make(chan X, 1)
	y := make(chan Y, 1)

	timeout := time.After(time.Second)
	go func() {
		x <- f1()
	}()
	go func() {
		y <- f2()
	}()
	select {
	case xResult := <-x:
		select {
		case yResult := <-y:
			return xResult, yResult
		case <-timeout:
			panic("timeout when running f2 function")
		}
	case <-timeout:
		select {
		case yResult := <-y:
			panic(fmt.Sprintf("timeout when running f1 function while f2 function finshed with %v", yResult))
		default:
			panic("timeout when running f1 and f2 functions")
		}
	}
}
