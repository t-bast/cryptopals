package distance_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/distance"
)

func TestHamming(t *testing.T) {
	assert.Equal(t, 37, distance.Hamming("this is a test", "wokka wokka!!!"))
}
