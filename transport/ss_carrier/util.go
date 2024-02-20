package ss_carrier

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"time"

	"github.com/ringo-is-a-color/heteroglossia/util/errors"
	"lukechampine.com/blake3"
)

func deriveSubkey(psk, salt []byte) []byte {
	keyMaterial := make([]byte, len(psk)+len(salt))
	copy(keyMaterial, psk)
	copy(keyMaterial[len(psk):], salt)
	key := make([]byte, len(psk))
	blake3.DeriveKey(key, "shadowsocks 2022 session subkey", keyMaterial)
	return key
}

func aeadCipher(subkey []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(subkey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	aead, err := cipher.NewGCM(block)
	return aead, errors.WithStack(err)
}

const MaxUnixTimeDiffInSecond = 30

func validateUnixTimeInRange(bs []byte) error {
	compared := int64(binary.BigEndian.Uint64(bs))
	now := time.Now().Unix()
	diff := max(compared, now) - min(compared, now)
	if diff > MaxUnixTimeDiffInSecond {
		return errors.Newf("unix time difference is over 30 seconds: received time was '%v' and now it is %v",
			compared, now)
	}
	return nil
}
