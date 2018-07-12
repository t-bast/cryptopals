package set1

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/xor"
)

func TestSet1_Challenge1(t *testing.T) {
	encoded := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	decoded, err := hex.DecodeString(encoded)
	require.NoError(t, err)

	b64 := base64.RawStdEncoding.EncodeToString(decoded)
	assert.Equal(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", b64)
}

func TestSet1_Challenge2(t *testing.T) {
	x := xor.Hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965")
	assert.Equal(t, "746865206b696420646f6e277420706c6179", x)
}
