package block_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/block"
)

func TestCBC(t *testing.T) {
	key := "YELLOW SUBMARINE"
	iv := [16]byte{0}
	cbc := block.NewCBC([]byte(key), iv[:])

	message := "Yellow, yellow submarine yellow!"
	encrypted := cbc.Encrypt([]byte(message))
	decrypted := cbc.Decrypt(encrypted)

	assert.Equal(t, message, string(decrypted))
}
