package stream_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/stream"
)

func TestEditCTR(t *testing.T) {
	key := "YELLOW SUBMARINE"
	enc := stream.NewCTR([]byte(key), 0)

	ciphertext := enc.Encrypt([]byte("It will never be the beauties that vignettes show, Those damaged products of a good-for-nothing age, Their feet shod with high shoes, hands holding castanets, Who can ever satisfy any heart like mine."))
	ciphertext2 := stream.EditCTR(ciphertext, []byte(key), 35, []byte("spongebob"))

	decrypted := enc.Decrypt(ciphertext2)
	assert.Equal(t, []byte("It will never be the beauties that spongebob show, Those damaged products of a good-for-nothing age, Their feet shod with high shoes, hands holding castanets, Who can ever satisfy any heart like mine."), decrypted)
}
