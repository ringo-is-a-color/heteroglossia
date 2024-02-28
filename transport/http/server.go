package http

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"

	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

type Server struct {
	ConnBufReader *bufio.Reader
	AuthInfo      *transport.HTTPSOCKSAuthInfo
}

var _ transport.Server = new(Server)

// see https://www.mnot.net/blog/2011/07/11/what_proxies_must_do point 1
// point 0: always advise HTTP 1.1
// point 1: remove Hop-by-hop headers

// already done in Go's code net/http.readRequest
// point 3: an absolute URI always override the Host header

var connectSuccessBytes = []byte("HTTP/1.1 200 OK\r\n\r\n")

// forked from https://github.com/database64128/shadowsocks-go/blob/88c2d63ccd0b022f76902195ceb1559eaf15a3a7/http/server.go
// always consider connection persistent and take little care of HTTP connection header to make the impl simper

func (s *Server) HandleConnection(ctx context.Context, conn net.Conn, targetClient transport.Client) error {
	req, err := readRequest(s.ConnBufReader)
	if err != nil {
		return errors.WithStack(err)
	}

	isHTTPConnect := req.Method == http.MethodConnect
	var addr *transport.SocketAddress
	if isHTTPConnect {
		// https://www.rfc-editor.org/rfc/rfc9110#name-connect
		// There is no default port; a client MUST send the port number
		// even if the CONNECT request is based on a URI reference that
		// contains an authority component with an elided port.
		// A server MUST reject a CONNECT request that targets an empty or invalid port number,
		// typically by responding with a 400 (Bad Request) status code.
		addr, err = transport.ToSocketAddr(req.Host, true, 0)
	} else {
		addr, err = transport.ToSocketAddr(req.Host, false, 80)
	}
	if err != nil {
		return errors.Join(err, httpError(req, conn, http.StatusBadRequest))
	}
	if !s.AuthInfo.IsEmpty() {
		username, password, ok := parse(req)
		if !ok || s.AuthInfo.NotEqual2(username, password) {
			return errors.Join(errors.New("no authentication info, or incorrect username/password"),
				httpError(req, conn, http.StatusProxyAuthRequired))
		}
	}
	if isHTTPConnect {
		err = ioutil.Write_(conn, connectSuccessBytes)
		if err != nil {
			return err
		}
		return transport.ForwardTCP(ctx, addr, conn, targetClient)
	}

	lp, rp := net.Pipe()
	go func() {
		lprb := bufio.NewReader(lp)
		var rerr, werr error
		for {
			removeHopByHopHeaders(req.Header)

			werr := req.Write(lp)
			if werr != nil {
				werr = errors.WithStack(werr)
				break
			}
			resp, rerr := http.ReadResponse(lprb, req)
			if rerr != nil {
				rerr = errors.WithStack(rerr)
				break
			}
			rerr = resp.Write(conn)
			if rerr != nil {
				rerr = errors.WithStack(rerr)
				break
			}

			// https://www.rfc-editor.org/rfc/rfc9110#name-connect
			// A tunnel is closed when a tunnel intermediary detects that either side has closed its connection:
			// the intermediary MUST attempt to send any outstanding data that came from the closed side to the other side,
			// close both connections, and then discard any remaining data left undelivered.
			if req.Close || resp.Close {
				break
			}
			req, werr = readRequest(s.ConnBufReader)
			if werr != nil {
				if !errors.IsIoEof(werr) {
					werr = errors.WithStack(werr)
				}
				break
			}
		}

		_ = lp.Close()
		if rerr != nil {
			log.InfoWithError("fail to read request", rerr)
		}
		if werr != nil {
			log.InfoWithError("fail to write resp", rerr)
		}
	}()

	return transport.ForwardTCP(ctx, addr, rp, targetClient)
}

func parse(r *http.Request) (username, password string, ok bool) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return "", "", false
	}
	return parseBasicAuth(auth)
}

func removeHopByHopHeaders(header http.Header) {
	connectionHeader := header["Connection"]
	for i := range connectionHeader {
		header.Del(connectionHeader[i])
	}
	delete(header, "Connection")
	delete(header, "Keep-Alive")
	delete(header, "Proxy-Authenticate")
	delete(header, "Proxy-Authorization")
	delete(header, "TE")
	delete(header, "Trailers")
	delete(header, "Transfer-Encoding")
	delete(header, "Upgrade")
}

func httpError(req *http.Request, w io.Writer, statusCode int) error {
	resp := http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		ProtoMajor: req.ProtoMajor,
		ProtoMinor: req.ProtoMinor,
	}
	return resp.Write(w)
}
