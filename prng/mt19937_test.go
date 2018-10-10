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

	t.Run("untemper", func(t *testing.T) {
		y1 := 1<<31 + 1<<27 + 1<<16
		o1 := prng.MT19937Untemper(prng.MT19937Temper(y1))

		assert.Equal(t, y1, o1)

		y2 := 1<<25 + 1<<23 + 1<<19 + 1<<13 + 1<<7 + 1
		o2 := prng.MT19937Untemper(prng.MT19937Temper(y2))

		assert.Equal(t, y2, o2)
	})
}
