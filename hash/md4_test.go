package hash_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/hash"
)

func TestMD4(t *testing.T) {
	h1 := hash.MD4Sum([]byte("YELLOW SUBMARINE"))
	h2 := hash.MD4Sum([]byte("YELLAW SUBMARINE"))

	assert.NotEqual(t, h1, h2)
}
