package tu_carrier

import (
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
)

const (
	tuicVersion byte = 5

	authCommandType      byte = 0
	connectCommandType   byte = 0x01
	heartbeatCommandType byte = 0x04

	// label should begin with 'EXPORTER' according to https://datatracker.ietf.org/doc/html/rfc5705#section-4
	authCommandUUID      = "EXPORTER_hg_QUIC" // needs to be 16 bytes
	authCommandUUIDSize  = len(authCommandUUID)
	authCommandTokenSize = 32
	authCommandDataSize  = authCommandUUIDSize + authCommandTokenSize

	authCommandSendErrCode           = 0x00
	authCommandSendErrStr            = "Fail to send an authentication command"
	authCommandReceiveTimeoutErrCode = 0x01
	connectCommandSendErrCode        = 0x10
	connectCommandSendErrStr         = "Fail to send a connect command"
	heartbeatCommandSendErrCode      = 0x40
	heartbeatCommandSendErrStr       = "Fail to send a heartbeat command"
	handleUniStreamErrCode           = 0x100
	handleUniStreamErrStr            = "Fail to handle a unidirectional command"
	receiveDatagramErrCode           = 0x104
	receiveDatagramStreamErrStr      = "Fail to receive a datagram"
	handleDatagramErrCode            = 0x105
	handleDatagramStreamErrStr       = "Fail to handle a datagram"
	connectionContextDoneErrCode     = 0x110
	connectionContextDoneErrStr      = "connection's context is done"

	authTimeout = 7 * time.Second
)

var (
	authCommandReceiveTimeoutErrStr = fmt.Sprintf("fail to receive authentication command in %v", authTimeout)
	heartbeatInterval               = netutil.KeepAlive

	quicClientConfig = &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingUniStreams: 1 << 60,
		MaxIdleTimeout:        netutil.IdleTimeout,
	}

	quicServerConfig = &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingStreams:    1 << 60,
		MaxIncomingUniStreams: 1 << 60,
		MaxIdleTimeout:        netutil.IdleTimeout,
	}
)

func validateVersion(version byte) error {
	if version != tuicVersion {
		return errors.Newf("excepted version %v in the client authentication command, but got %v", tuicVersion, version)
	}
	return nil
}

func authToken(quicConn quic.Connection, password []byte) ([]byte, error) {
	tls := quicConn.ConnectionState().TLS
	return errors.WithStack2(tls.ExportKeyingMaterial(authCommandUUID, password, authCommandTokenSize))
}

const (
	// https://github.com/EAimTY/tuic/blob/dev/SPEC.md#address
	// The address type can be one of the following:
	//   o 0xff: None
	//   o 0x00: Fully-qualified domain name (the first byte indicates the length of the domain name)
	//   o 0x01: IPv4 address
	//   o 0x02: IPv6 address
	tuicAddressTypeIpv4   byte = 0x01
	tuicAddressTypeIpv6   byte = 0x02
	tuicAddressTypeDomain byte = 0x00
	tuicAddressTypeNone   byte = 0xff
)

var tuicAddressType = [3]byte{tuicAddressTypeIpv4, tuicAddressTypeIpv6, tuicAddressTypeDomain}

func readTUICAddress(r io.Reader) (*transport.SocketAddress, error) {
	return transport.ReadAddressWithType(r, tuicAddressType)
}
