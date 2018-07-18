package block_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/block"
)

func TestECB(t *testing.T) {
	key := "YELLOW SUBMARINE"
	ecb := block.NewECB([]byte(key))
	message := "If rape, poison, dagger and fire," +
		"Have still not embroidered their pleasant designs" +
		"On the banal canvas of our pitiable destinies," +
		"It's because our soul, alas, is not bold enough!"

	encrypted := ecb.Encrypt([]byte(message))
	decrypted := ecb.Decrypt(encrypted)

	assert.Equal(t, message, string(decrypted))
}
