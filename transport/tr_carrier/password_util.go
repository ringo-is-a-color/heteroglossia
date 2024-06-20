package tr_carrier

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/ringo-is-a-color/heteroglossia/util/ioutil"
	"github.com/ringo-is-a-color/heteroglossia/util/log"
)

const (
	cr        = '\r'
	lf        = '\n'
	escapedLF = lf + 1
)

func replaceCRLF(passwordRaw [16]byte) [16]byte {
	var newPw [16]byte

	isCR := false
	for i, b := range passwordRaw {
		switch {
		case b == cr:
			isCR = true
			newPw[i] = b
		case isCR && b == lf:
			newPw[i] = escapedLF
			isCR = false
		default:
			newPw[i] = b
		}
	}
	return newPw
}

func toTrojanPassword(password string) [56]byte {
	var key [56]byte
	hash := sha256.New224()
	err := ioutil.Write_(hash, []byte(password))
	if err != nil {
		log.Fatal("unexpected code path", err)
	}
	hex.Encode(key[:], hash.Sum(nil))
	return key
}
