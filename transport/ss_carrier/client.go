package ss_carrier

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"strconv"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/conf"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/netutil"
	"github.com/ringo-is-a-color/heteroglossia/util/randutil"
)

type Handler struct {
	proxyNode    *conf.ProxyNode
	preSharedKey []byte
	// a function to randomly pick Ex2 and 5 mentioned here https://gfw.report/publications/usenixsecurity23/en/
	exPicker func() int
}

var _ transport.ConnectionContinuationHandler = new(Handler)

func NewSSCarrierClient(proxyNode *conf.ProxyNode) *Handler {
	return &Handler{proxyNode, proxyNode.Password.Raw[:], randutil.WeightedIntN(2)}
}

func (h *Handler) ForwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) error {
	targetConn, err := h.forwardConnection(srcRWC, accessAddr)
	if err != nil {
		return err
	}
	return ioutil.Pipe(srcRWC, targetConn)
}

/*
https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-header

Request stream:
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted header chunk   | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B |   11B + 16B AEAD tag   | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+

+----------------+
|  length chunk  |
+----------------+
| u16 big-endian |
+----------------+

+---------------+
| payload chunk |
+---------------+
|   variable    |
+---------------+
*/

const (
	maxPaddingSize         = 900
	lenFieldSize           = 2
	clientStreamHeaderType = 0
	serverStreamHeaderType = 1
)

func (h *Handler) forwardConnection(srcRWC io.ReadWriteCloser, accessAddr *transport.SocketAddress) (net.Conn, error) {
	saltSize := len(h.preSharedKey)
	clientSalt, err := randutil.RandNBytes(saltSize)
	if err != nil {
		return nil, err
	}
	h.customFirstReqPrefixes(clientSalt)

	firstPayload := pool.Get(ioutil.TCPBufSize)
	defer pool.Put(firstPayload)
	var paddingSize, paddingAndPayloadSize int
	n, err := srcRWC.Read(firstPayload)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if n < 0 {
		paddingSize = rand.IntN(maxPaddingSize + 1)
		paddingAndPayloadSize = paddingSize
	} else {
		paddingSize = 0
		paddingAndPayloadSize = n
	}

	// Request variable-length header
	// +------+----------+-------+----------------+----------+-----------------+
	// | ATYP |  address |  port | padding length |  padding | initial payload |
	// +------+----------+-------+----------------+----------+-----------------+
	// |  1B  | variable | u16be |     u16be      | variable |    variable     |
	// +------+----------+-------+----------------+----------+-----------------+
	paddingOrPayloadStart := socks.SocksLikeAddrSizeInBytes(accessAddr) + lenFieldSize
	reqVarLenHeaderSize := paddingOrPayloadStart + paddingAndPayloadSize
	reqVarLenHeaderBs := pool.Get(reqVarLenHeaderSize)
	defer pool.Put(reqVarLenHeaderBs)
	reqVarLenHeaderBuf := bytes.NewBuffer(reqVarLenHeaderBs[:0])
	socks.WriteSocksLikeAddr(reqVarLenHeaderBuf, accessAddr)
	err = binary.Write(reqVarLenHeaderBuf, binary.BigEndian, uint16(paddingSize))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	if n < 0 {
		_, err = randutil.RandBytes(reqVarLenHeaderBs[paddingOrPayloadStart : paddingOrPayloadStart+paddingSize])
		if err != nil {
			return nil, err
		}
	} else {
		reqVarLenHeaderBuf.Write(firstPayload[:n])
	}

	// Request fixed-length header
	// +------+------------------+--------+
	// | type |     timestamp    | length |
	// +------+------------------+--------+
	// |  1B  | u64be unix epoch |  u16be |
	// +------+------------------+--------+
	reqFixedLenHeaderSize := 1 + 8 + lenFieldSize
	reqFixedLenHeaderBuf := bytes.NewBuffer(make([]byte, 0, reqFixedLenHeaderSize))
	reqFixedLenHeaderBuf.WriteByte(clientStreamHeaderType)
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return nil, errors.WithStack(err)
	}
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint16(reqVarLenHeaderSize))
	if err != nil {
		return nil, errors.WithStack(err)
	}

	reqSubkey := deriveSubkey(h.preSharedKey, clientSalt)
	reqAEAD, err := aeadCipher(reqSubkey)
	if err != nil {
		return nil, err
	}
	aeadRWC := new(aeadReadWriteCloser)
	aeadRWC.setAEADWriter(reqAEAD)

	reqVarLenHeaderStart := saltSize + reqFixedLenHeaderSize + reqAEAD.Overhead()
	reqHeaderEncryptedBs := pool.Get(reqVarLenHeaderStart + reqVarLenHeaderSize + reqAEAD.Overhead())
	defer pool.Put(reqHeaderEncryptedBs)
	reqHeaderBuf := bytes.NewBuffer(reqHeaderEncryptedBs[:0])
	_, err = reqHeaderBuf.Write(clientSalt)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	aeadRWC.Encrypt(reqHeaderEncryptedBs[saltSize:saltSize], reqFixedLenHeaderBuf.Bytes())
	aeadRWC.Encrypt(reqHeaderEncryptedBs[reqVarLenHeaderStart:reqVarLenHeaderStart], reqVarLenHeaderBuf.Bytes())

	hostWithPort := h.proxyNode.Host + ":" + strconv.Itoa(h.proxyNode.TCPPort)
	targetConn, err := netutil.DialTCP(hostWithPort)
	if err != nil {
		return nil, errors.Wrapf(err, "fail to connect to the TCP server %v", hostWithPort)
	}
	_, err = targetConn.Write(reqHeaderEncryptedBs)
	if err != nil {
		_ = targetConn.Close()
		return nil, errors.WithStack(err)
	}
	err = h.handleResponse(srcRWC, targetConn, aeadRWC, clientSalt, reqAEAD.Overhead())
	if err != nil {
		_ = targetConn.Close()
		return nil, err
	}
	return targetConn, nil
}

/*
Response stream:
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted payload chunk  | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B | 27/43B + 16B AEAD tag  | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
*/
func (h *Handler) handleResponse(srcRWC io.ReadWriteCloser, targetConn *net.TCPConn,
	aeadRWC *aeadReadWriteCloser, clientSalt []byte, aeadOverhead int) error {
	saltSize := len(h.preSharedKey)
	respFixedLenHeaderSize := 1 + 8 + saltSize + lenFieldSize + aeadOverhead
	respSaltWithFixedLenHeaderSize := pool.Get(saltSize + respFixedLenHeaderSize)
	defer pool.Put(respSaltWithFixedLenHeaderSize)
	var err error
	defer func() {
		if err != nil {
			// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-detection-prevention
			// To consistently send RST even when the received buffer is empty, set 'SO_LINGER' to true with a zero timeout, then close the socket.
			err = targetConn.SetLinger(0)
			if err != nil {
				log.WarnWithError("fail to set SO_LINGER", err)
			}
		}
	}()
	_, err = ioutil.ReadOnceExpectFull(targetConn, respSaltWithFixedLenHeaderSize)
	if err != nil {
		return err
	}

	respSubkey := deriveSubkey(h.preSharedKey, respSaltWithFixedLenHeaderSize[:saltSize])
	respAEAD, err := aeadCipher(respSubkey)
	if err != nil {
		return err
	}
	aeadRWC.setAEADReader(respAEAD)
	aeadRWC.rwc = targetConn

	respFixedLenHeaderBs := respSaltWithFixedLenHeaderSize[saltSize:]
	err = aeadRWC.Decrypt(respFixedLenHeaderBs[:0], respFixedLenHeaderBs)
	if err != nil {
		return err
	}
	respPayloadSize, err := validateResponseHeaderAndReturnLen(respFixedLenHeaderBs, clientSalt)
	if err != nil {
		return err
	}

	respPayloadEncryptedBs := pool.Get(respPayloadSize + respAEAD.Overhead())
	pool.Put(respPayloadEncryptedBs)
	_, err = ioutil.ReadFull(targetConn, respPayloadEncryptedBs)
	if err != nil {
		return err
	}
	err = aeadRWC.Decrypt(respPayloadEncryptedBs[:0], respPayloadEncryptedBs)
	if err != nil {
		return err
	}
	_, err = srcRWC.Write(respPayloadEncryptedBs[:respPayloadSize])
	if err != nil {
		return err
	}
	return nil
}

/*
Response fixed-length header
+------+------------------+----------------+--------+
| type |     timestamp    |  request salt  | length |
+------+------------------+----------------+--------+
|  1B  | u64be unix epoch |     16/32B     |  u16be |
+------+------------------+----------------+--------+
*/
func validateResponseHeaderAndReturnLen(respFixedLenHeaderBs []byte, clientSalt []byte) (int, error) {
	if respFixedLenHeaderBs[0] != serverStreamHeaderType {
		return 0, errors.Newf("invalid stream header type '%v' but '%v expected",
			respFixedLenHeaderBs[0], serverStreamHeaderType)
	}
	err := validateUnixTimeInRange(respFixedLenHeaderBs[1:])
	if err != nil {
		return 0, err
	}
	lenStart := 1 + 8 + len(clientSalt)
	receivedClientSalt := respFixedLenHeaderBs[1+8 : lenStart]
	if !bytes.Equal(clientSalt, receivedClientSalt) {
		return 0, errors.New("incorrect client salt in response header")
	}

	respPayloadSizeBs := respFixedLenHeaderBs[lenStart:]
	return int(binary.BigEndian.Uint16(respPayloadSizeBs)), nil
}

// https://gfw.report/publications/usenixsecurity23/en/
func (h *Handler) customFirstReqPrefixes(bs []byte) {
	switch h.exPicker() {
	case 0:
		// Ex2 exemption
		for i := range 6 {
			bs[i] = byte(rand.IntN(0x7e-0x20+1) + 0x20)
		}
	case 1:
		// Ex5 exemption
		pattern := [6]string{"GET ", "HEAD ", "POST ", "PUT ", "\x16\x03\x02", "\x16\x03\x03"}
		copy(bs, pattern[rand.IntN(6)])
	default:
		panic("unreachable code line")
	}
}
