package rand_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/rand"
)

func TestMT19937(t *testing.T) {
	r := rand.NewMT19937(0)
	v1 := r.Rand()
	v2 := r.Rand()

	assert.NotEqual(t, v1, v2)
}
