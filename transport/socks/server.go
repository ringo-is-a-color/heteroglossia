package socks

import (
	"context"
	"io"
	"net"

	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"golang.org/x/exp/slices"
)

type Server struct {
	authInfo     *conf.HTTPSOCKSAuthInfo
	targetClient transport.Client
}

var _ transport.Server = new(Server)

func NewServer(authInfo *conf.HTTPSOCKSAuthInfo, targetClient transport.Client) *Server {
	return &Server{authInfo, targetClient}
}

const (
	Sock4Version byte = 4
	Sock5Version byte = 5

	helloNoAuthRequired      byte = 0
	helloUsernamePassword    byte = 2
	helloNoAcceptableMethods byte = 0xFF

	authUsernamePasswordVersion byte = 1
	authUsernamePasswordSuccess byte = 0
	authUsernamePasswordFailure byte = 1

	ConnectionCommandConnect byte = 1

	connectionSucceeded           byte = 0
	connectionCommandNotSupported byte = 7
	connectionReserved            byte = 0
)

// https://www.rfc-editor.org/rfc/rfc1928

/*
Client Hello

Request
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

Response
+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+
*/

var (
	helloNoAuthBytes              = []byte{Sock5Version, helloNoAuthRequired}
	helloUsernamePasswordBytes    = []byte{Sock5Version, helloUsernamePassword}
	helloNoAcceptableMethodsBytes = []byte{Sock5Version, helloNoAcceptableMethods}
)

func (s *Server) ListenAndServe(ctx context.Context) error {
	panic("no implemented")
}

// handle SOCKS5 request without the first version byte

func (s *Server) Serve(ctx context.Context, conn net.Conn) error {
	return s.handleClientHelloRequest(ctx, conn)
}

func (s *Server) handleClientHelloRequest(ctx context.Context, conn net.Conn) error {
	// the version byte of the SOCKS5 protocol is already checked in the http_socks package
	// so we start to check the 'methods' directly
	methods, err := ioutil.ReadByUint8(conn)
	if err != nil {
		return err
	}

	switch {
	case s.authInfo.IsEmpty() && slices.Contains(methods, helloNoAuthRequired):
		err = ioutil.Write_(conn, helloNoAuthBytes)
	case !s.authInfo.IsEmpty() && slices.Contains(methods, helloUsernamePassword):
		err = ioutil.Write_(conn, helloUsernamePasswordBytes)
		if err == nil {
			err = s.handleClientAuthenticationRequest(conn)
		}
	default:
		err = ioutil.Write_(conn, helloNoAcceptableMethodsBytes)
		if err != nil {
			return err
		}
		err = errors.New("unsupported or no acceptable methods")
	}
	if err != nil {
		return err
	}
	return s.handleClientConnectionRequest(ctx, conn)
}

/*
https://datatracker.ietf.org/doc/rfc1929

Client Authentication

Request
+----+------+----------+------+----------+
|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
+----+------+----------+------+----------+
| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
+----+------+----------+------+----------+

Response
+----+--------+
|VER | STATUS |
+----+--------+
| 1  |   1    |
+----+--------+
*/

var authUsernamePasswordSuccessBytes = []byte{authUsernamePasswordVersion, authUsernamePasswordSuccess}
var authUsernamePasswordFailureBytes = []byte{authUsernamePasswordVersion, authUsernamePasswordFailure}

func (s *Server) handleClientAuthenticationRequest(conn net.Conn) error {
	authInfoFromRequest, err := readClientAuthUsernamePassword(conn)
	if err != nil {
		return err
	}
	if s.authInfo.NotEqual(authInfoFromRequest) {
		err = ioutil.Write_(conn, authUsernamePasswordFailureBytes)
		return errors.Join(errors.New("incorrect username or password"), err)
	}
	return ioutil.Write_(conn, authUsernamePasswordSuccessBytes)
}

func readClientAuthUsernamePassword(r io.Reader) (authInfo *conf.HTTPSOCKSAuthInfo, err error) {
	version, err := ioutil.Read1(r)
	if err != nil {
		return
	}
	if version != authUsernamePasswordVersion {
		err = errors.Newf("excepted version %v in the client authentication request, but got %v", authUsernamePasswordVersion, version)
		return
	}

	authInfo = &conf.HTTPSOCKSAuthInfo{}
	authInfo.Username, err = ioutil.ReadStringByUint8(r)
	if err != nil {
		return
	}
	authInfo.Password, err = ioutil.ReadStringByUint8(r)
	return
}

/*
Client Connection

Request
+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Response
+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
*/

var connectionCommandNotSupportedBytes = []byte{Sock5Version, connectionCommandNotSupported, connectionReserved,
	connectionAddressIpv4, 0, 0, 0, 0, 0}

// According to the rfc1928, we need to return the source address/port that SOCKS5 server used to connect to the target host,
// but we just return dummy values here as these values are not useful to a client and some SOCKS5 server returns the dummy values.
// See https://stackoverflow.com/q/43013695, https://stackoverflow.com/q/39990056, https://stackoverflow.com/q/72753182
var connectionSucceededPrefix = []byte{Sock5Version, connectionSucceeded, connectionReserved,
	1, 0, 0, 0, 0, 0, 0}

func (s *Server) handleClientConnectionRequest(ctx context.Context, conn net.Conn) error {
	_, bs, err := ioutil.ReadN(conn, 3)
	if err != nil {
		return err
	}
	if bs[0] != Sock5Version {
		return errors.Newf("SOCKS%v protocol is not supported, only SOCKS5 is supported", bs[0])
	}
	if bs[1] != ConnectionCommandConnect {
		err = ioutil.Write_(conn, connectionCommandNotSupportedBytes)
		return errors.Join(errors.Newf("the command type %v is not supported, only command type 0x01 is supported", bs[1]), err)
	}

	accessAddr, err := ReadSOCKS5Address(conn)
	if err != nil {
		return err
	}
	err = ioutil.Write_(conn, connectionSucceededPrefix)
	if err != nil {
		return err
	}
	return transport.ForwardTCP(ctx, accessAddr, conn, s.targetClient)
}
