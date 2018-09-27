package stream

import (
	"crypto/aes"
	"encoding/binary"

	"github.com/t-bast/cryptopals/score"
	"github.com/t-bast/cryptopals/xor"
)

// CTR implements CTR encryption using AES.
type CTR struct {
	key   []byte
	nonce []byte
}

// NewCTR creates a new CTR encryptor with the given key and nonce.
func NewCTR(key []byte, nonce uint64) *CTR {
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, nonce)

	return &CTR{
		key:   key,
		nonce: nonceBytes,
	}
}

// Encrypt a message in CTR mode.
func (e *CTR) Encrypt(message []byte) []byte {
	b, err := aes.NewCipher(e.key)
	if err != nil {
		panic(err)
	}

	blockCount := len(message) / 16
	if len(message)%16 != 0 {
		blockCount++
	}

	keystream := make([]byte, 16*blockCount)
	for i := uint64(0); i < uint64(blockCount); i++ {
		counterBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(counterBytes, i)

		start := i * 16
		end := start + 16
		b.Encrypt(keystream[start:end], append(e.nonce, counterBytes...))
	}

	return xor.Bytes(message, keystream[:len(message)])
}

// Decrypt a message in CTR mode.
func (e *CTR) Decrypt(ciphertext []byte) []byte {
	return e.Encrypt(ciphertext)
}

// PwnCTRNonceReuse takes multiples ciphertexts generated with the same nonce and
// figures out the keystream.
func PwnCTRNonceReuse(ciphertexts [][]byte) []byte {
	maxLength := 0
	for _, ciphertext := range ciphertexts {
		if len(ciphertext) > maxLength {
			maxLength = len(ciphertext)
		}
	}

	var keystream []byte
	for i := 0; i < maxLength; i++ {
		bestCandidate := byte(0)
		bestScore := float32(0)

		for j := 0; j < 256; j++ {
			currentScore := float32(0.0)
			for _, ciphertext := range ciphertexts {
				if len(ciphertext) < i+1 {
					continue
				}

				plain := ciphertext[i] ^ byte(j)
				if plain < 32 || 122 < plain {
					currentScore = 0
					break
				} else {
					currentScore += score.LetterFrequency([]byte{plain})
				}
			}

			if currentScore > bestScore {
				bestCandidate = byte(j)
				bestScore = currentScore
			}
		}

		keystream = append(keystream, bestCandidate)
	}

	return keystream
}