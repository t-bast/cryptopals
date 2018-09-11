package oracle

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"time"

	"github.com/t-bast/cryptopals/cipher/block"
)

// ECBOracle encrypts using ECB with a fixed unknown key and a fixed plaintext
// suffix.
// The goal is to decrypt that plaintext suffix.
type ECBOracle struct {
	Key    []byte
	secret []byte
}

// NewECBOracle creates a random key and an oracle that uses that key.
func NewECBOracle() *ECBOracle {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	rand.Read(key)

	secret, _ := base64.StdEncoding.DecodeString("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	return &ECBOracle{Key: key, secret: secret}
}

// Encrypt the given message to which we append the secret message.
func (o *ECBOracle) Encrypt(message []byte) []byte {
	ecb := block.NewECB(o.Key)
	return ecb.Encrypt(append(message, o.secret...))
}

// DetectECBSecret extracts the secret message from the oracle.
func DetectECBSecret(oracle *ECBOracle) []byte {
	secretLength := len(oracle.Encrypt(nil))
	secret := make([]byte, secretLength)

	currentBlock := 0
	currentIndex := 0

	for currentBlock*16+currentIndex < secretLength {
		// Initialize mask with last known secret bytes, or fixed values.
		mask := make([]byte, 15)
		for i := 0; i < 15; i++ {
			if currentBlock*16+currentIndex >= 15-i {
				mask[i] = secret[currentBlock*16+currentIndex-15+i]
			} else {
				mask[i] = 'A'
			}
		}

		// Record encryption results for each possible byte added to the mask.
		dict := make([][]byte, 256)
		for i := 0; i < 256; i++ {
			dict[i] = oracle.Encrypt(append(mask[:], byte(i)))[0:16]
		}

		// Encrypt with the next unknown byte.
		e := oracle.Encrypt(mask[:15-currentIndex])

		// Find the pre-image in dictionary.
		for i, v := range dict {
			if bytes.Equal(v, e[16*currentBlock:16*(currentBlock+1)]) {
				secret[16*currentBlock+currentIndex] = byte(i)
				break
			}
		}

		currentIndex++
		if currentIndex == 16 {
			currentBlock++
			currentIndex = 0
		}
	}

	return secret
}
