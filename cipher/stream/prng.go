package stream

import (
	"encoding/binary"

	"github.com/t-bast/cryptopals/prng"
	"github.com/t-bast/cryptopals/xor"
)

// PRNG implements a stream cipher from a pseudo-random number generator.
type PRNG struct {
	key uint16
}

// NewPRNG creates a new PRNG stream cipher.
func NewPRNG(key uint16) *PRNG {
	return &PRNG{key: key}
}

// Encrypt a message.
func (e *PRNG) Encrypt(message []byte) []byte {
	mt := prng.NewMT19937(int(e.key))

	blockCount := len(message) / 4
	if len(message)%4 != 0 {
		blockCount++
	}

	keystream := make([]byte, 4*blockCount)
	for i := 0; i < blockCount; i++ {
		start := i * 4
		end := start + 4
		binary.LittleEndian.PutUint32(keystream[start:end], uint32(mt.Rand()))
	}

	return xor.Bytes(message, keystream[:len(message)])
}

// Decrypt a message.
func (e *PRNG) Decrypt(ciphertext []byte) []byte {
	return e.Encrypt(ciphertext)
}
