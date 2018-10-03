package prng_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/prng"
)

func TestMT19937(t *testing.T) {
	t.Run("produces different values", func(t *testing.T) {
		r := prng.NewMT19937(0)
		v1 := r.Rand()
		v2 := r.Rand()

		assert.NotEqual(t, v1, v2)
	})

	t.Run("produces same value if same seed", func(t *testing.T) {
		r1 := prng.NewMT19937(42)
		v1 := r1.Rand()

		r2 := prng.NewMT19937(42)
		v2 := r2.Rand()

		assert.Equal(t, v1, v2)
	})
}
