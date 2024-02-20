package ss_carrier

import (
	"crypto/cipher"
	"encoding/binary"
	"io"

	pool "github.com/libp2p/go-buffer-pool"
	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
)

type aeadReadWriteCloser struct {
	rwc         io.ReadWriteCloser
	aeadReader  cipher.AEAD
	nonceReader []byte
	readerBuf   []byte
	aeadWriter  cipher.AEAD
	nonceWriter []byte
}

var _ io.ReadWriteCloser = new(aeadReadWriteCloser)
var _ io.ReaderFrom = new(aeadReadWriteCloser)
var _ io.WriterTo = new(aeadReadWriteCloser)

func (rwc *aeadReadWriteCloser) setAEADReader(aead cipher.AEAD) {
	rwc.aeadReader = aead
	rwc.nonceReader = make([]byte, aead.NonceSize())
}

func (rwc *aeadReadWriteCloser) setAEADWriter(aead cipher.AEAD) {
	rwc.aeadWriter = aead
	rwc.nonceWriter = make([]byte, aead.NonceSize())
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
func (rwc *aeadReadWriteCloser) Read(p []byte) (n int, err error) {
	if len(rwc.readerBuf) != 0 {
		n = copy(p, rwc.readerBuf)
		if n > 0 {
			rwc.readerBuf = rwc.readerBuf[n:]
			return
		}
	}

	payloadLenEncryptedSize := lenFieldSize + rwc.aeadReader.Overhead()
	_, payloadLenEncryptedBs, err := ioutil.ReadN(rwc.rwc, payloadLenEncryptedSize)
	if err != nil {
		return 0, err
	}
	err = rwc.Decrypt(payloadLenEncryptedBs[:0], payloadLenEncryptedBs)
	if err != nil {
		return 0, err
	}
	payloadSize := int(binary.BigEndian.Uint16(payloadLenEncryptedBs))

	payloadEncryptedBs := pool.Get(payloadSize + rwc.aeadReader.Overhead())
	defer pool.Put(payloadEncryptedBs)
	_, err = ioutil.ReadFull(rwc.rwc, payloadEncryptedBs)
	if err != nil {
		return 0, err
	}
	err = rwc.Decrypt(payloadEncryptedBs[:0], payloadEncryptedBs)
	if err != nil {
		return 0, err
	}

	n = copy(p, payloadEncryptedBs[:payloadSize])
	if n < payloadSize {
		readerBufBs := make([]byte, payloadSize-n)
		copy(readerBufBs, payloadLenEncryptedBs[n:payloadSize])
		rwc.readerBuf = readerBufBs
	}
	return n, nil
}

/*
Request stream chunk
+------------------------+---------------------------+
| encrypted length chunk |  encrypted payload chunk  |
+------------------------+---------------------------+
|   2B  + 16B AEAD tag   | variable length + 16B tag |
+------------------------+---------------------------+
*/

// https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/60c3f41461a303ba3d7f8837065294699b1e0526/2022-1-shadowsocks-2022-edition.md#312-format
// A payload chunk can have up to 0xFFFF (65535) bytes of unencrypted payload.
const maxChunkSize = 65535

func (rwc *aeadReadWriteCloser) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return
	}
	for canWriteCount := len(p); canWriteCount > 0; {
		var payloadChunk []byte
		if canWriteCount > maxChunkSize {
			payloadChunk = p[:maxChunkSize]
			p = p[maxChunkSize:]
			canWriteCount -= maxChunkSize
		} else {
			payloadChunk = p
			canWriteCount = 0
		}

		payloadEncryptedSize := lenFieldSize + rwc.aeadWriter.Overhead() + len(payloadChunk) + rwc.aeadWriter.Overhead()
		payloadEncryptedBs := pool.Get(payloadEncryptedSize)
		binary.BigEndian.PutUint16(payloadEncryptedBs, uint16(len(payloadChunk)))
		rwc.Encrypt(payloadEncryptedBs[:0], payloadEncryptedBs[:lenFieldSize])

		payloadStart := lenFieldSize + rwc.aeadWriter.Overhead()
		rwc.Encrypt(payloadEncryptedBs[payloadStart:payloadStart], payloadChunk)

		count, err := rwc.rwc.Write(payloadEncryptedBs)
		pool.Put(payloadEncryptedBs)
		if err != nil {
			return n + count, errors.WithStack(err)
		}
		n += len(payloadChunk)
	}
	return
}

func (rwc *aeadReadWriteCloser) ReadFrom(r io.Reader) (n int64, err error) {
	payloadStart := lenFieldSize + rwc.aeadWriter.Overhead()
	payloadEncryptedSize := payloadStart + maxChunkSize + rwc.aeadWriter.Overhead()
	payloadEncryptedBs := pool.Get(payloadEncryptedSize)
	defer pool.Put(payloadEncryptedBs)
	for {
		count, err := r.Read(payloadEncryptedBs[payloadStart : payloadStart+maxChunkSize])
		n += int64(count)
		if err != nil {
			return n, errors.WithStack(err)
		}
		binary.BigEndian.PutUint16(payloadEncryptedBs, uint16(count))
		rwc.Encrypt(payloadEncryptedBs[:0], payloadEncryptedBs[:lenFieldSize])
		rwc.Encrypt(payloadEncryptedBs[payloadStart:payloadStart],
			payloadEncryptedBs[payloadStart:payloadStart+count])

		_, err = rwc.rwc.Write(payloadEncryptedBs[:payloadStart+count+rwc.aeadWriter.Overhead()])
		if err != nil {
			return n, errors.WithStack(err)
		}
	}
}

func (rwc *aeadReadWriteCloser) WriteTo(w io.Writer) (n int64, err error) {
	if len(rwc.readerBuf) > 0 {
		n, err := w.Write(rwc.readerBuf)
		rwc.readerBuf = rwc.readerBuf[n:]
		if err != nil {
			return int64(n), errors.WithStack(err)
		}
	}

	payloadLenEncryptedBs := make([]byte, lenFieldSize+rwc.aeadReader.Overhead())
	for {
		_, err := ioutil.ReadFull(rwc.rwc, payloadLenEncryptedBs)
		if err != nil {
			return 0, err
		}
		err = rwc.Decrypt(payloadLenEncryptedBs[:0], payloadLenEncryptedBs)
		if err != nil {
			return 0, err
		}
		payloadSize := int(binary.BigEndian.Uint16(payloadLenEncryptedBs))

		payloadEncryptedBs := pool.Get(payloadSize + rwc.aeadReader.Overhead())
		_, err = ioutil.ReadFull(rwc.rwc, payloadEncryptedBs)
		if err != nil {
			pool.Put(payloadEncryptedBs)
			return 0, err
		}
		err = rwc.Decrypt(payloadEncryptedBs[:0], payloadEncryptedBs)
		if err != nil {
			pool.Put(payloadEncryptedBs)
			return 0, err
		}

		count, err := w.Write(payloadEncryptedBs[:payloadSize])
		pool.Put(payloadEncryptedBs)
		n += int64(count)
		if err != nil {
			return n, errors.WithStack(err)
		}
	}
}

func (rwc *aeadReadWriteCloser) Close() error {
	return rwc.rwc.Close()
}

func (rwc *aeadReadWriteCloser) Encrypt(dst []byte, src []byte) {
	rwc.aeadWriter.Seal(dst, rwc.nonceWriter, src, nil)
	incNonce(rwc.nonceWriter)
}

func (rwc *aeadReadWriteCloser) Decrypt(dst []byte, src []byte) error {
	_, err := rwc.aeadReader.Open(dst, rwc.nonceReader, src, nil)
	if err != nil {
		return errors.WithStack(err)
	}
	incNonce(rwc.nonceReader)
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
