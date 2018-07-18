package set1

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/cipher/padding"
)

func TestSet2_Challenge1(t *testing.T) {
	padded := padding.PKCS7([]byte("YELLOW SUBMARINE"), 20)
	assert.Equal(t, []byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padded)
}
