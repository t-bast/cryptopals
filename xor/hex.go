// Package xor contains xor-ing utilities.
package xor

import (
	"encoding/hex"
)

// Hex XORs two hex strings and returns the hex encoding of the result.
func Hex(s1, s2 string) string {
	b1, err := hex.DecodeString(s1)
	if err != nil {
		panic(err)
	}

	b2, err := hex.DecodeString(s2)
	if err != nil {
		panic(err)
	}

	b := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		b[i] = b1[i] ^ b2[i]
	}

	return hex.EncodeToString(b)
}
