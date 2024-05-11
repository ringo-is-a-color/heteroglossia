package tr_carrier

import (
	"crypto/sha256"
	"encoding/hex"
)

const cr = '\r'
const lf = '\n'
const escapedLF = lf + 1

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
	hash.Write([]byte(password))
	hex.Encode(key[:], hash.Sum(nil))
	return key
}
