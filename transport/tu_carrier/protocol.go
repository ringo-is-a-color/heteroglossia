package tu_carrier

import (
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
)

const (
	tuicVersion = 5

	authCommandType = 0
	// needs to be 16 bytes
	authCommandUUID                  = "EXPORTER_hg_QUIC"
	authCommandUUIDSize              = len(authCommandUUID)
	authCommandTokenSize             = 32
	authCommandDataSize              = authCommandUUIDSize + authCommandTokenSize
	authCommandSendErrCode           = 0x00
	authCommandSendErrStr            = "Fail to send authentication command"
	authCommandReceiveTimeoutErrCode = 0x01

	connectCommandType        = 0x01
	connectCommandSendErrCode = 0x10
	connectCommandSendErrStr  = "Fail to send connect command"

	handleUniStreamErrCode = 0x100
	handleUniStreamErrStr  = "Fail to handle unidirectional command"
)

var (
	authTimeout                     = 5 * time.Second
	authCommandReceiveTimeoutErrStr = fmt.Sprintf("fail to receive authentication command in %v", authTimeout)
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
