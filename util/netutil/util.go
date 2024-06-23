package netutil

import (
	"net/http"
	"time"
)

// Linux uses 7200 by default but we use a smaller value

var IdleTimeout = 720 * time.Second

// Linux uses 75 by default so we use the same value

var KeepAlive = 75 * time.Second
var httpClientTimeout = 60 * time.Second

func HTTPClient(tr *http.Transport) *http.Client {
	return &http.Client{Transport: tr, Timeout: httpClientTimeout}
}
