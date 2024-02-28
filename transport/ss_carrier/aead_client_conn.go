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

type aeadClientConn struct {
	*net.TCPConn
	accessAddr   *transport.SocketAddress
	preSharedKey []byte

	writerSalt  []byte
	aeadWriter  cipher.AEAD
	nonceWriter []byte

	aeadReader   cipher.AEAD
	nonceReader  []byte
	readerBuf    []byte
	aeadOverhead int

	hasWriteClientFirstPacket bool
	hasReadClientFirstPacket  bool
}

var _ net.Conn = new(aeadClientConn)
var _ io.ReaderFrom = new(aeadClientConn)
var _ io.WriterTo = new(aeadClientConn)

func newAEADClientConn(conn *net.TCPConn, accessAddr *transport.SocketAddress,
	preSharedKey []byte, writerSalt []byte, aeadOverhead int) *aeadClientConn {
	return &aeadClientConn{TCPConn: conn, accessAddr: accessAddr,
		preSharedKey: preSharedKey, writerSalt: writerSalt, aeadOverhead: aeadOverhead}
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
	maxPaddingSize = 900
	// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/60c3f41461a303ba3d7f8837065294699b1e0526/2022-1-shadowsocks-2022-edition.md#312-format
	// A payload chunk can have up to 0xFFFF (65535) bytes of unencrypted payload.
	maxChunkSize           = 65535
	clientStreamHeaderType = 0
	serverStreamHeaderType = 1

	lenFieldSize          = 2
	reqFixedLenHeaderSize = 1 + 8 + lenFieldSize
)

/*
Request stream chunk
+------------------------+---------------------------+
| encrypted length chunk |  encrypted payload chunk  |
+------------------------+---------------------------+
|   2B  + 16B AEAD tag   | variable length + 16B tag |
+------------------------+---------------------------+
*/

func (c *aeadClientConn) Write(p []byte) (n int, err error) {
	if !c.hasWriteClientFirstPacket {
		c.hasWriteClientFirstPacket = true
		return c.writeClientFirstPacket(p)
	}

	for canWriteCount := len(p); canWriteCount > 0; {
		var payloadBs []byte
		if canWriteCount > maxChunkSize {
			payloadBs = p[:maxChunkSize]
			p = p[maxChunkSize:]
			canWriteCount -= maxChunkSize
		} else {
			payloadBs = p
			canWriteCount = 0
		}

		payloadSize := len(payloadBs)
		payloadEncryptedSize := lenFieldSize + c.aeadOverhead + payloadSize + c.aeadOverhead
		payloadEncryptedBs := pool.Get(payloadEncryptedSize)
		binary.BigEndian.PutUint16(payloadEncryptedBs, uint16(payloadSize))
		c.encrypt(payloadEncryptedBs[:0], payloadEncryptedBs[:lenFieldSize])

		payloadStart := lenFieldSize + c.aeadOverhead
		c.encrypt(payloadEncryptedBs[payloadStart:payloadStart], payloadBs)

		count, err := c.TCPConn.Write(payloadEncryptedBs)
		pool.Put(payloadEncryptedBs)
		if err != nil {
			return n + count, err
		}
		// the total written count (payloadEncryptedBs) is less than the one (payloadSize) written into 'c.TCPConn'
		n += payloadSize
	}
	return
}

func (c *aeadClientConn) writeClientFirstPacket(payload []byte) (int, error) {
	payloadSize := len(payload)
	var paddingSize, paddingAndPayloadSize int
	if payloadSize <= 0 {
		paddingSize = rand.IntN(maxPaddingSize + 1)
		paddingAndPayloadSize = paddingSize
	} else {
		paddingSize = 0
		paddingAndPayloadSize = payloadSize
	}

	// Request variable-length header
	// +------+----------+-------+----------------+----------+-----------------+
	// | ATYP |  address |  port | padding length |  padding | initial payload |
	// +------+----------+-------+----------------+----------+-----------------+
	// |  1B  | variable | u16be |     u16be      | variable |    variable     |
	// +------+----------+-------+----------------+----------+-----------------+
	paddingOrPayloadStart := socks.SocksLikeAddrSizeInBytes(c.accessAddr) + lenFieldSize
	reqVarLenHeaderSize := paddingOrPayloadStart + paddingAndPayloadSize
	reqVarLenHeaderBs := pool.Get(reqVarLenHeaderSize)
	defer pool.Put(reqVarLenHeaderBs)
	reqVarLenHeaderBuf := bytes.NewBuffer(reqVarLenHeaderBs[:0])
	socks.WriteSocksLikeAddr(reqVarLenHeaderBuf, c.accessAddr)
	err := binary.Write(reqVarLenHeaderBuf, binary.BigEndian, uint16(paddingSize))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	if payloadSize < 0 {
		_, err = randutil.RandBytes(reqVarLenHeaderBs[paddingOrPayloadStart : paddingOrPayloadStart+paddingSize])
		if err != nil {
			return 0, err
		}
	} else {
		reqVarLenHeaderBuf.Write(payload[:payloadSize])
	}

	// Request fixed-length header
	// +------+------------------+--------+
	// | type |     timestamp    | length |
	// +------+------------------+--------+
	// |  1B  | u64be unix epoch |  u16be |
	// +------+------------------+--------+
	reqFixedLenHeaderBuf := bytes.NewBuffer(make([]byte, 0, reqFixedLenHeaderSize))
	reqFixedLenHeaderBuf.WriteByte(clientStreamHeaderType)
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint64(time.Now().Unix()))
	if err != nil {
		return 0, errors.WithStack(err)
	}
	err = binary.Write(reqFixedLenHeaderBuf, binary.BigEndian, uint16(reqVarLenHeaderSize))
	if err != nil {
		return 0, errors.WithStack(err)
	}

	reqSubkey := deriveSubkey(c.preSharedKey, c.writerSalt)
	reqAEAD, err := aeadCipher(reqSubkey)
	if err != nil {
		return 0, err
	}
	c.setAEADWriter(reqAEAD)

	saltSize := len(c.preSharedKey)
	reqVarLenHeaderEncryptedStart := saltSize + reqFixedLenHeaderSize + c.aeadOverhead
	reqHeaderEncryptedBs := pool.Get(reqVarLenHeaderEncryptedStart + reqVarLenHeaderSize + c.aeadOverhead)
	defer pool.Put(reqHeaderEncryptedBs)
	reqHeaderBuf := bytes.NewBuffer(reqHeaderEncryptedBs[:0])
	_, err = reqHeaderBuf.Write(c.writerSalt)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	c.encrypt(reqHeaderEncryptedBs[saltSize:saltSize], reqFixedLenHeaderBuf.Bytes())
	c.encrypt(reqHeaderEncryptedBs[reqVarLenHeaderEncryptedStart:reqVarLenHeaderEncryptedStart], reqVarLenHeaderBuf.Bytes())

	_, err = c.TCPConn.Write(reqHeaderEncryptedBs)
	if err != nil {
		return 0, errors.WithStack(err)
	}
	// the total written count (reqHeaderEncryptedBs) is less than the one (payloadSize) written into 'c.TCPConn'
	return payloadSize, nil
}

/*
https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md#312-format

Response stream chunk
+------------------------+---------------------------+
| encrypted length chunk |  encrypted payload chunk  |
----+--------------------+---------------------------+
|   2B + 16B AEAD tag    | variable length + 16B tag |
+------------------------+---------------------------+
*/
func (c *aeadClientConn) Read(b []byte) (n int, err error) {
	if !c.hasReadClientFirstPacket {
		c.hasReadClientFirstPacket = true
		return c.readClientFirstPacket(b)
	}

	if len(c.readerBuf) != 0 {
		n = copy(b, c.readerBuf)
		if n > 0 {
			c.readerBuf = c.readerBuf[n:]
			return
		}
	}

	payloadLenEncryptedSize := lenFieldSize + c.aeadOverhead
	_, payloadLenEncryptedBs, err := ioutil.ReadN(c.TCPConn, payloadLenEncryptedSize)
	if err != nil {
		return 0, err
	}
	err = c.decrypt(payloadLenEncryptedBs[:0], payloadLenEncryptedBs)
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
	err = c.decrypt(payloadEncryptedBs[:0], payloadEncryptedBs)
	if err != nil {
		return 0, err
	}

	return c.copyReadPayload(b, payloadEncryptedBs[:payloadSize])
}

func (c *aeadClientConn) readClientFirstPacket(b []byte) (int, error) {
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
	respSaltWithFixedLenHeaderEncryptedBs := pool.Get(saltSize + reqFixedLenHeaderSize + saltSize + c.aeadOverhead)
	defer pool.Put(respSaltWithFixedLenHeaderEncryptedBs)
	_, err = ioutil.ReadOnceExpectFull(c.TCPConn, respSaltWithFixedLenHeaderEncryptedBs)
	if err != nil && !errors.IsIoEof(err) {
		return 0, err
	}

	respSubkey := deriveSubkey(c.preSharedKey, respSaltWithFixedLenHeaderEncryptedBs[:saltSize])
	respAEAD, err := aeadCipher(respSubkey)
	if err != nil {
		return 0, err
	}
	c.setAEADReader(respAEAD)

	respFixedLenHeaderEncryptedBs := respSaltWithFixedLenHeaderEncryptedBs[saltSize:]
	err = c.decrypt(respFixedLenHeaderEncryptedBs[:0], respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}
	respPayloadSize, err := c.validateServerRespHeaderAndReturnPayloadLen(respFixedLenHeaderEncryptedBs)
	if err != nil {
		return 0, err
	}

	respPayloadEncryptedBs := pool.Get(respPayloadSize + c.aeadOverhead)
	pool.Put(respPayloadEncryptedBs)
	_, err = ioutil.ReadFull(c.TCPConn, respPayloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	err = c.decrypt(respPayloadEncryptedBs[:0], respPayloadEncryptedBs)
	if err != nil {
		return 0, err
	}

	return c.copyReadPayload(b, respPayloadEncryptedBs[:respPayloadSize])
}

func (c *aeadClientConn) copyReadPayload(b []byte, payloadBs []byte) (int, error) {
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
Response fixed-length header
+------+------------------+----------------+--------+
| type |     timestamp    |  request salt  | length |
+------+------------------+----------------+--------+
|  1B  | u64be unix epoch |     16/32B     |  u16be |
+------+------------------+----------------+--------+
*/
func (c *aeadClientConn) validateServerRespHeaderAndReturnPayloadLen(respFixedLenHeaderBs []byte) (int, error) {
	if respFixedLenHeaderBs[0] != serverStreamHeaderType {
		return 0, errors.Newf("invalid stream header type '%v' but '%v expected",
			respFixedLenHeaderBs[0], serverStreamHeaderType)
	}
	err := validateUnixTimeInRange(respFixedLenHeaderBs[1:])
	if err != nil {
		return 0, err
	}
	lenStart := 1 + 8 + len(c.writerSalt)
	receivedClientSalt := respFixedLenHeaderBs[1+8 : lenStart]
	if !bytes.Equal(c.writerSalt, receivedClientSalt) {
		return 0, errors.New("incorrect client salt in response header")
	}

	respPayloadSizeBs := respFixedLenHeaderBs[lenStart:]
	return int(binary.BigEndian.Uint16(respPayloadSizeBs)), nil
}

func (c *aeadClientConn) ReadFrom(r io.Reader) (n int64, err error) {
	if !c.hasWriteClientFirstPacket {
		c.hasWriteClientFirstPacket = true
		firstReqPayloadBs := pool.Get(maxChunkSize)
		count, err := r.Read(firstReqPayloadBs)
		n += int64(count)
		if err != nil && !errors.IsIoEof(err) {
			pool.Put(firstReqPayloadBs)
			return n, err
		}
		_, err = c.writeClientFirstPacket(firstReqPayloadBs[:count])
		pool.Put(firstReqPayloadBs)
		if err != nil {
			return n, err
		}
	}

	payloadStart := lenFieldSize + c.aeadOverhead
	payloadEncryptedSize := payloadStart + maxChunkSize + c.aeadOverhead
	payloadEncryptedBs := pool.Get(payloadEncryptedSize)
	defer pool.Put(payloadEncryptedBs)
	for {
		count, err := r.Read(payloadEncryptedBs[payloadStart : payloadStart+maxChunkSize])
		n += int64(count)
		// return if 'io.EOF'
		if err != nil {
			return n, err
		}
		binary.BigEndian.PutUint16(payloadEncryptedBs, uint16(count))
		c.encrypt(payloadEncryptedBs[:0], payloadEncryptedBs[:lenFieldSize])
		c.encrypt(payloadEncryptedBs[payloadStart:payloadStart],
			payloadEncryptedBs[payloadStart:payloadStart+count])

		_, err = c.TCPConn.Write(payloadEncryptedBs[:payloadStart+count+c.aeadOverhead])
		if err != nil {
			return n, err
		}
	}
}

func (c *aeadClientConn) WriteTo(w io.Writer) (n int64, err error) {
	if !c.hasReadClientFirstPacket {
		c.hasReadClientFirstPacket = true
		buf := pool.Get(maxChunkSize)
		_, err := c.readClientFirstPacket(buf)
		if err != nil {
			pool.Put(buf)
			return 0, err
		}
		count, err := w.Write(buf)
		pool.Put(buf)
		n += int64(count)
		if err != nil {
			return 0, err
		}
	}

	if len(c.readerBuf) > 0 {
		count, err := w.Write(c.readerBuf)
		c.readerBuf = c.readerBuf[count:]
		n += int64(count)
		if err != nil {
			return n, err
		}
	}

	payloadLenEncryptedBs := make([]byte, lenFieldSize+c.aeadOverhead)
	for {
		_, err = ioutil.ReadFull(c.TCPConn, payloadLenEncryptedBs)
		if err != nil {
			return 0, err
		}
		err = c.decrypt(payloadLenEncryptedBs[:0], payloadLenEncryptedBs)
		if err != nil {
			return 0, err
		}
		payloadSize := int(binary.BigEndian.Uint16(payloadLenEncryptedBs))

		payloadEncryptedBs := pool.Get(payloadSize + c.aeadOverhead)
		_, err = ioutil.ReadFull(c.TCPConn, payloadEncryptedBs)
		if err != nil {
			pool.Put(payloadEncryptedBs)
			return 0, err
		}
		err = c.decrypt(payloadEncryptedBs[:0], payloadEncryptedBs)
		if err != nil {
			pool.Put(payloadEncryptedBs)
			return 0, err
		}

		count, err := w.Write(payloadEncryptedBs[:payloadSize])
		pool.Put(payloadEncryptedBs)
		n += int64(count)
		if err != nil {
			return n, err
		}
	}
}

func (c *aeadClientConn) setAEADReader(aead cipher.AEAD) {
	c.aeadReader = aead
	c.nonceReader = make([]byte, aead.NonceSize())
}

func (c *aeadClientConn) setAEADWriter(aead cipher.AEAD) {
	c.aeadWriter = aead
	c.nonceWriter = make([]byte, aead.NonceSize())
}

func (c *aeadClientConn) encrypt(dst []byte, src []byte) {
	c.aeadWriter.Seal(dst, c.nonceWriter, src, nil)
	incNonce(c.nonceWriter)
}

func (c *aeadClientConn) decrypt(dst []byte, src []byte) error {
	_, err := c.aeadReader.Open(dst, c.nonceReader, src, nil)
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
