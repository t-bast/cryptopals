package xor

import (
	"encoding/hex"

	"github.com/t-bast/cryptopals/score"
)

// DecryptSingle decrypts a hex-encoded string that has been XOR'd against a
// single character.
// It assumes that the message is english ASCII and uses letter frequency to
// select the most likely decrypted value.
// It returns the decrypted string and the key used.
func DecryptSingle(c string) (string, byte) {
	decoded, err := hex.DecodeString(c)
	if err != nil {
		panic(err)
	}

	return decryptSingle(decoded)
}

func decryptSingle(c []byte) (string, byte) {
	var key byte
	var best []byte
	var bestScore float32

	for b := 0; b < 256; b++ {
		b := byte(b)
		decrypted := make([]byte, len(c))
		for i := 0; i < len(decrypted); i++ {
			decrypted[i] = b ^ c[i]
		}

		s := score.LetterFrequency(decrypted)
		if s > bestScore {
			bestScore = s
			best = decrypted
			key = b
		}
	}

	return string(best), key
}
