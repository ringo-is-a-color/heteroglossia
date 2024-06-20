package ss_carrier

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"math/rand/v2"
	"net"
	"time"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/transport"
	"github.com/ringo-is-a-color/heteroglossia/transport/socks"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
	"github.com/ringo-is-a-color/heteroglossia/util/randutil"
)

type conn struct {
	*net.TCPConn
	accessAddr   *transport.SocketAddress
	preSharedKey []byte

	clientSalt  []byte
	aeadWriter  cipher.AEAD
	nonceWriter []byte

	aeadReader   cipher.AEAD
	nonceReader  []byte
	readerBuf    []byte
	aeadOverhead int

	isClient             bool
	hasWriteFirstPayload bool
	hasReadFirstPayload  bool
	serverSideSaltPool   *saltPool[string]
}

var _ net.Conn = new(conn)
var _ io.ReaderFrom = new(conn)
var _ io.WriterTo = new(conn)

func newClientConn(tcpConn *net.TCPConn, accessAddr *transport.SocketAddress,
	preSharedKey []byte, clientSalt []byte, aeadOverhead int) *conn {
	return &conn{TCPConn: tcpConn, accessAddr: accessAddr,
		preSharedKey: preSharedKey, clientSalt: clientSalt, aeadOverhead: aeadOverhead, isClient: true}
}

func newServerConn(tcpConn *net.TCPConn, preSharedKey []byte, aeadOverhead int, serverSideSaltPool *saltPool[string]) *conn {
	return &conn{TCPConn: tcpConn, preSharedKey: preSharedKey, aeadOverhead: aeadOverhead, isClient: false, serverSideSaltPool: serverSideSaltPool}
}

const (
	maxPaddingSize = 900
	// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/60c3f41461a303ba3d7f8837065294699b1e0526/2022-1-shadowsocks-2022-edition.md#312-format
	// A payload chunk can have up to 0xFFFF (65535) bytes of unencrypted payload.
	maxChunkSize           = 65535
	clientStreamHeaderType = 0
	serverStreamHeaderType = 1

	lenFieldSize          = 2
	typeWithTimestampSize = 1 + 8
	reqFixedLenHeaderSize = typeWithTimestampSize + lenFieldSize
)

/*
https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format
Request stream
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted header chunk   | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B |   11B + 16B AEAD tag   | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+

Response stream
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
|  salt  | encrypted header chunk |  encrypted payload chunk  | encrypted length chunk |  encrypted payload chunk  |...|
+--------+------------------------+---------------------------+------------------------+---------------------------+---+
| 16/32B | 27/43B + 16B AEAD tag  | variable length + 16B tag |  2B length + 16B tag   | variable length + 16B tag |...|
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

func (c *conn) Write(p []byte) (n int, err error) {
	count, err := c.ReadFrom(bytes.NewReader(p))
	return int(count), err
}

func (c *conn) writeClientFirstPayload(payload []byte) (int, error) {
	payloadSize := len(payload)
	var paddingSize, reqPaddingAndPayloadSize int
	if payloadSize <= 0 {
		paddingSize = rand.IntN(maxPaddingSize + 1)
		reqPaddingAndPayloadSize = paddingSize
	} else {
		paddingSize = 0
		reqPaddingAndPayloadSize = payloadSize
	}

	reqPaddingOrPayloadStart := socks.SocksLikeAddrSizeInBytes(c.accessAddr) + lenFieldSize
	reqVarLenHeaderSize := reqPaddingOrPayloadStart + reqPaddingAndPayloadSize
	saltSize := len(c.preSharedKey)
	reqVarLenHeaderEncryptedStart := saltSize + reqFixedLenHeaderSize + c.aeadOverhead
	reqHeaderEncryptedBs := pool.Get(reqVarLenHeaderEncryptedStart + reqVarLenHeaderSize + c.aeadOverhead)
	defer pool.Put(reqHeaderEncryptedBs)

	// Request fixed-length header
	// +------+------------------+--------+
	// | type |     timestamp    | length |
	// +------+------------------+--------+
	// |  1B  | u64be unix epoch |  u16be |
	// +------+------------------+--------+
	reqFixedLenHeaderBs := reqHeaderEncryptedBs[saltSize:reqVarLenHeaderEncryptedStart]
	reqFixedLenHeaderBuf := bytes.NewBuffer(reqFixedLenHeaderBs[:0])
	reqFixedLenHeaderBuf.WriteByte(clientStreamHeaderType)
	err := binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint16(reqVarLenHeaderSize))
	if err != nil {
		return 0, errors.WithStack(err)
	}

	// Request variable-length header
	// +------+----------+-------+----------------+----------+-----------------+
	// | ATYP |  address |  port | padding length |  padding | initial payload |
	// +------+----------+-------+----------------+----------+-----------------+
	// |  1B  | variable | u16be |     u16be      | variable |    variable     |
	// +------+----------+-------+----------------+----------+-----------------+
	reqVarLenHeaderBs := reqHeaderEncryptedBs[reqVarLenHeaderEncryptedStart:]
	reqVarLenHeaderBuf := bytes.NewBuffer(reqVarLenHeaderBs[:0])
	socks.WriteSocksLikeAddr(reqVarLenHeaderBuf, c.accessAddr)
	err = binary.Write(reqVarLenHeaderBuf, binary.BigEndian, uint16(paddingSize))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	if payloadSize < 0 {
		_, err = randutil.RandBytes(reqVarLenHeaderBs[reqPaddingOrPayloadStart : reqPaddingOrPayloadStart+paddingSize])
		if err != nil {
			return 0, err
		}
	} else {
		reqVarLenHeaderBuf.Write(payload[:payloadSize])
	}

	copy(reqHeaderEncryptedBs, c.clientSalt)
	clientAEAD, err := aeadCipher(c.preSharedKey, c.clientSalt)
	if err != nil {
		return 0, err
	}
	c.setAEADWriter(clientAEAD)
	c.encryptInPlace(reqFixedLenHeaderBuf.Bytes())
	c.encryptInPlace(reqVarLenHeaderBuf.Bytes())

	_, err = c.TCPConn.Write(reqHeaderEncryptedBs)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	// the total written count (reqHeaderEncryptedBs) is less than the one (payloadSize) written into 'c.TCPConn'
	return payloadSize, nil
}

/*
First response stream
+--------+------------------------+---------------------------+
|  salt  | encrypted header chunk |  encrypted payload chunk  |
+--------+------------------------+---------------------------+
| 16/32B |    27/43B + 16B tag    | variable length + 16B tag |
+--------+------------------------+---------------------------+
*/
func (c *conn) writeServerFirstPayload(payload []byte) (int, error) {
	saltSize := len(c.preSharedKey)
	payloadSize := len(payload)
	respPayloadEncryptedStart := saltSize + reqFixedLenHeaderSize + saltSize + c.aeadOverhead
	respSaltWithFixedLenHeaderAndPayloadEncryptedBs := pool.Get(respPayloadEncryptedStart + payloadSize + c.aeadOverhead)
	defer pool.Put(respSaltWithFixedLenHeaderAndPayloadEncryptedBs)
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf := bytes.NewBuffer(respSaltWithFixedLenHeaderAndPayloadEncryptedBs[:0])
	serverSalt, err := generateSalt(c.preSharedKey)
	if err != nil {
		return 0, err
	}
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.Write(serverSalt)

	// Response fixed-length header
	// +------+------------------+----------------+--------+
	// | type |     timestamp    |  request salt  | length |
	// +------+------------------+----------------+--------+
	// |  1B  | u64be unix epoch |     16/32B     |  u16be |
	// +------+------------------+----------------+--------+
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.WriteByte(serverStreamHeaderType)
	err = binary.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.Write(c.clientSalt)
	err = binary.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf, binary.BigEndian, uint16(payloadSize))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	copy(respSaltWithFixedLenHeaderAndPayloadEncryptedBuf.AvailableBuffer()[c.aeadOverhead:c.aeadOverhead+payloadSize], payload)

	serverAEAD, err := aeadCipher(c.preSharedKey, serverSalt)
	if err != nil {
		return 0, err
	}
	c.setAEADWriter(serverAEAD)

	respFixedLenHeaderEncryptedBs := respSaltWithFixedLenHeaderAndPayloadEncryptedBs[saltSize:]
	c.encryptInPlace(respFixedLenHeaderEncryptedBs[:reqFixedLenHeaderSize+saltSize])
	if err != nil {
		return 0, err
	}
	respVarLenHeaderEncryptedBs := respSaltWithFixedLenHeaderAndPayloadEncryptedBs[respPayloadEncryptedStart:]
	c.encryptInPlace(respVarLenHeaderEncryptedBs[:payloadSize])
	if err != nil {
		return 0, err
	}
	_, err = c.TCPConn.Write(respSaltWithFixedLenHeaderAndPayloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	return payloadSize, err
}

func (c *conn) Read(b []byte) (n int, err error) {
	return c.readOrWriteTo(b, nil)
}

func (c *conn) readOrWriteTo(b []byte, w io.Writer) (n int, err error) {
	if c.isClient && !c.hasReadFirstPayload {
		c.hasReadFirstPayload = true
		return c.readServerFirstPayload(b, w)
	}

	if len(c.readerBuf) != 0 {
		if w != nil {
			n, err := ioutil.Write(w, c.readerBuf)
			c.readerBuf = c.readerBuf[n:]
			return n, err
		}
		n = copy(b, c.readerBuf)
		if n > 0 {
			c.readerBuf = c.readerBuf[n:]
			return
		}
	}

	// Response stream chunk
	// +------------------------+---------------------------+
	// | encrypted length chunk |  encrypted payload chunk  |
	// +------------------------+---------------------------+
	// |   2B + 16B AEAD tag    | variable length + 16B tag |
	// +------------------------+---------------------------+
	payloadLenEncryptedSize := lenFieldSize + c.aeadOverhead
	_, payloadLenEncryptedBs, err := ioutil.ReadN(c.TCPConn, payloadLenEncryptedSize)
	if err != nil {
		return 0, err
	}
	err = c.decryptInPlace(payloadLenEncryptedBs)
	if err != nil {
		return 0, err
	}
	payloadSize := int(binary.BigEndian.Uint16(payloadLenEncryptedBs))

	payloadEncryptedBs := pool.Get(payloadSize + c.aeadOverhead)
	defer pool.Put(payloadEncryptedBs)
	_, err = ioutil.ReadFull(c.TCPConn, payloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	err = c.decryptInPlace(payloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	if w != nil {
		return ioutil.Write(w, payloadEncryptedBs[:payloadSize])
	}
	return c.copyReadPayload(b, payloadEncryptedBs[:payloadSize])
}

func (c *conn) readServerFirstPayload(b []byte, w io.Writer) (int, error) {
	c.hasReadFirstPayload = true
	saltSize := len(c.preSharedKey)
	respSaltWithFixedLenHeaderEncryptedBs := pool.Get(saltSize + reqFixedLenHeaderSize + saltSize + c.aeadOverhead)
	defer pool.Put(respSaltWithFixedLenHeaderEncryptedBs)
	_, err := ioutil.ReadOnceExpectFull(c.TCPConn, respSaltWithFixedLenHeaderEncryptedBs)
	if err != nil && !errors.IsIoEof(err) {
		return 0, err
	}

	serverAEAD, err := aeadCipher(c.preSharedKey, respSaltWithFixedLenHeaderEncryptedBs[:saltSize])
	if err != nil {
		return 0, err
	}
	c.setAEADReader(serverAEAD)

	respFixedLenHeaderEncryptedBs := respSaltWithFixedLenHeaderEncryptedBs[saltSize:]
	err = c.decryptInPlace(respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}
	respPayloadSize, err := c.validateFixedHeaderAndReturnLen(respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}

	respPayloadEncryptedBs := pool.Get(respPayloadSize + c.aeadOverhead)
	pool.Put(respPayloadEncryptedBs)
	_, err = ioutil.ReadFull(c.TCPConn, respPayloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	err = c.decryptInPlace(respPayloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	if w != nil {
		return ioutil.Write(w, respPayloadEncryptedBs[:respPayloadSize])
	}
	return c.copyReadPayload(b, respPayloadEncryptedBs[:respPayloadSize])
}

func (c *conn) readClientFirstPayload() error {
	c.hasReadFirstPayload = true
	var err error
	defer func() {
		if err != nil {
			// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#313-detection-prevention
			// To consistently send RST even when the received buffer is empty, set 'SO_LINGER' to true with a zero timeout, then close the socket.
			err = c.TCPConn.SetLinger(0)
			if err != nil {
				log.WarnWithError("fail to set SO_LINGER", err)
			}
		}
	}()
	saltSize := len(c.preSharedKey)
	reqSaltWithFixedLenHeaderEncryptedSize := saltSize + reqFixedLenHeaderSize + c.aeadOverhead
	reqSaltWithFixedLenHeaderEncryptedBs := pool.Get(reqSaltWithFixedLenHeaderEncryptedSize)
	defer pool.Put(reqSaltWithFixedLenHeaderEncryptedBs)
	_, err = ioutil.ReadOnceExpectFull(c.TCPConn, reqSaltWithFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}

	c.clientSalt = reqSaltWithFixedLenHeaderEncryptedBs[:saltSize]
	clientSaltStr := string(c.clientSalt)
	ok := c.serverSideSaltPool.check(clientSaltStr)
	if !ok {
		return errors.New("replay detected due to repeated salt found")
	}
	clientAEAD, err := aeadCipher(c.preSharedKey, reqSaltWithFixedLenHeaderEncryptedBs[:saltSize])
	if err != nil {
		return err
	}
	c.setAEADReader(clientAEAD)

	reqFixedLenHeaderEncryptedBs := reqSaltWithFixedLenHeaderEncryptedBs[saltSize:]
	err = c.decryptInPlace(reqFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	reqVarLenHeaderSize, err := c.validateFixedHeaderAndReturnLen(reqFixedLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	c.serverSideSaltPool.add(clientSaltStr)

	reqVarLenHeaderEncryptedBs := pool.Get(reqVarLenHeaderSize + c.aeadOverhead)
	defer pool.Put(reqVarLenHeaderEncryptedBs)
	_, err = ioutil.ReadFull(c.TCPConn, reqVarLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	err = c.decryptInPlace(reqVarLenHeaderEncryptedBs)
	if err != nil {
		return err
	}
	reqVarLenHeaderReader := bytes.NewBuffer(reqVarLenHeaderEncryptedBs[0 : len(reqVarLenHeaderEncryptedBs)-c.aeadOverhead])
	accessAddr, err := socks.ReadSOCKS5Address(reqVarLenHeaderReader)
	if err != nil {
		return err
	}
	c.accessAddr = accessAddr

	// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format
	// Servers MUST reject the request if the variable-length header chunk does not contain payload
	// and the padding length is 0. Servers MUST enforce that the request header (including padding)
	// does not extend beyond the header chunks.
	if reqVarLenHeaderReader.Len() <= lenFieldSize {
		return errors.New("client payload and the padding length are both 0 in request variable-length header")
	}
	_, paddingLenBs, err := ioutil.ReadN(reqVarLenHeaderReader, lenFieldSize)
	if err != nil {
		return errors.WithStack(err)
	}
	paddingLen := int(binary.BigEndian.Uint16(paddingLenBs))
	remainSize := reqVarLenHeaderReader.Len()
	if remainSize < paddingLen {
		return errors.Newf("expect %v padding byte(s), but only have %v remain bytes in request header",
			paddingLen, remainSize)
	}
	_, err = c.copyReadPayload([]byte{}, reqVarLenHeaderReader.Bytes()[paddingLen:])
	return err
}

func (c *conn) copyReadPayload(b []byte, payloadBs []byte) (int, error) {
	n := copy(b, payloadBs)
	payloadSize := len(payloadBs)
	if n < payloadSize {
		readerBuf := make([]byte, payloadSize-n)
		copy(readerBuf, payloadBs[n:payloadSize])
		c.readerBuf = readerBuf
	}
	return n, nil
}

/*
Request fixed-length header
+------+------------------+--------+
| type |     timestamp    | length |
+------+------------------+--------+
|  1B  | u64be unix epoch |  u16be |
+------+------------------+--------+

Response fixed-length header
+------+------------------+----------------+--------+
| type |     timestamp    |  request salt  | length |
+------+------------------+----------------+--------+
|  1B  | u64be unix epoch |     16/32B     |  u16be |
+------+------------------+----------------+--------+
*/
func (c *conn) validateFixedHeaderAndReturnLen(fixedLenHeaderBs []byte) (int, error) {
	var streamHeaderType byte
	if c.isClient {
		streamHeaderType = serverStreamHeaderType
	} else {
		streamHeaderType = clientStreamHeaderType
	}
	if fixedLenHeaderBs[0] != streamHeaderType {
		return 0, errors.Newf("invalid stream header type '%v', '%v expect",
			fixedLenHeaderBs[0], streamHeaderType)
	}
	err := validateUnixTimeInRange(fixedLenHeaderBs[1:])
	if err != nil {
		return 0, err
	}

	var lenStart int
	if c.isClient {
		saltSize := len(c.preSharedKey)
		lenStart = typeWithTimestampSize + saltSize
		receivedClientSalt := fixedLenHeaderBs[typeWithTimestampSize:lenStart]
		if !bytes.Equal(c.clientSalt, receivedClientSalt) {
			return 0, errors.New("incorrect client salt in response header")
		}
	} else {
		lenStart = typeWithTimestampSize
	}

	respPayloadSizeBs := fixedLenHeaderBs[lenStart:]
	return int(binary.BigEndian.Uint16(respPayloadSizeBs)), nil
}

func (c *conn) ReadFrom(r io.Reader) (n int64, err error) {
	payloadStart := lenFieldSize + c.aeadOverhead
	maxPayloadReadSize := payloadStart + maxChunkSize + c.aeadOverhead
	maxPayloadReadBs := pool.Get(maxPayloadReadSize)
	defer pool.Put(maxPayloadReadBs)

	if !c.hasWriteFirstPayload {
		c.hasWriteFirstPayload = true
		count, err := r.Read(maxPayloadReadBs)
		n += int64(count)
		if err != nil && !errors.IsIoEof(err) {
			return n, err
		}
		if c.isClient {
			_, err = c.writeClientFirstPayload(maxPayloadReadBs[:count])
		} else {
			_, err = c.writeServerFirstPayload(maxPayloadReadBs[:count])
		}
		if err != nil {
			return n, err
		}
	}

	for {
		count, err := r.Read(maxPayloadReadBs[payloadStart : payloadStart+maxChunkSize])
		n += int64(count)
		if err != nil {
			if errors.IsIoEof(err) {
				return n, nil
			}
			return n, errors.WithStack(err)
		}
		binary.BigEndian.PutUint16(maxPayloadReadBs, uint16(count))
		c.encryptInPlace(maxPayloadReadBs[:lenFieldSize])
		c.encryptInPlace(maxPayloadReadBs[payloadStart : payloadStart+count])

		_, err = c.TCPConn.Write(maxPayloadReadBs[:payloadStart+count+c.aeadOverhead])
		if err != nil {
			return n, err
		}
	}
}

func (c *conn) WriteTo(w io.Writer) (n int64, err error) {
	for {
		count, err := c.readOrWriteTo(nil, w)
		n += int64(count)
		if err != nil {
			if errors.IsIoEof(err) {
				return n, nil
			}
			return n, err
		}
	}
}

func (c *conn) setAEADReader(aead cipher.AEAD) {
	c.aeadReader = aead
	c.nonceReader = make([]byte, aead.NonceSize())
}

func (c *conn) setAEADWriter(aead cipher.AEAD) {
	c.aeadWriter = aead
	c.nonceWriter = make([]byte, aead.NonceSize())
}

func (c *conn) encrypt(dst []byte, src []byte) {
	c.aeadWriter.Seal(dst, c.nonceWriter, src, nil)
	incNonce(c.nonceWriter)
}

func (c *conn) encryptInPlace(src []byte) {
	c.encrypt(src[:0], src)
}

func (c *conn) decryptInPlace(src []byte) error {
	_, err := c.aeadReader.Open(src[:0], c.nonceReader, src, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	incNonce(c.nonceReader)
	return nil
}

func incNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}
