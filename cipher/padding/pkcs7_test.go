package padding_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/padding"
)

func TestPKCS7Padding(t *testing.T) {
	t.Run("single block", func(t *testing.T) {
		padded := padding.PKCS7([]byte("YELLOW SUBMARINE"), 20)
		assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padded)

		unpadded := padding.UnPKCS7(padded, 20)
		assert.Equal(t, []byte("YELLOW SUBMARINE"), unpadded)
	})

	t.Run("multiple blocks", func(t *testing.T) {
		padded := padding.PKCS7([]byte("YELLOW SUBMARINE"), 6)
		assert.Equal(t, []byte("YELLOW SUBMARINE\x02\x02"), padded)

		unpadded := padding.UnPKCS7(padded, 6)
		assert.Equal(t, []byte("YELLOW SUBMARINE"), unpadded)
	})

	t.Run("full padding block", func(t *testing.T) {
		padded := padding.PKCS7([]byte("YELLOW SUBMARINE"), 8)
		assert.Equal(t, []byte("YELLOW SUBMARINE\x08\x08\x08\x08\x08\x08\x08\x08"), padded)

		unpadded := padding.UnPKCS7(padded, 8)
		assert.Equal(t, []byte("YELLOW SUBMARINE"), unpadded)
	})

	t.Run("panics on invalid padding", func(t *testing.T) {
		assert.Panics(t, func() { padding.UnPKCS7([]byte("ICE ICE BABY\x05\x05\x05\x05"), 8) })
		assert.Panics(t, func() { padding.UnPKCS7([]byte("ICE ICE BABY\x01\x02\x03\x04"), 8) })
	})
}
