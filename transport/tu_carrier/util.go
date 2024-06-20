package tu_carrier

import (
	"github.com/quic-go/quic-go"
)

var (
	quicClientConfig = &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingUniStreams: 1 << 60,
	}

	quicServerConfig = &quic.Config{
		EnableDatagrams:       true,
		MaxIncomingStreams:    1 << 60,
		MaxIncomingUniStreams: 1 << 60,
	}
)

func isActive(quicConn quic.Connection) bool {
	select {
	case <-quicConn.Context().Done():
		return false
	default:
		return true
	}
}
