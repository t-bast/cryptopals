package stream_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/stream"
)

func TestPRNG(t *testing.T) {
	enc := stream.NewPRNG(42)
	message := []byte("WELCOME TO THE JUNGLE")
	ciphertext := enc.Encrypt(message)
	decrypted := enc.Decrypt(ciphertext)

	assert.Equal(t, message, decrypted)
}
