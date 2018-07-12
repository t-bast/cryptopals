package set1

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChallenge1(t *testing.T) {
	encoded := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	decoded := make([]byte, len(encoded)/2)
	hex.Decode(decoded, []byte(encoded))

	b64 := base64.RawStdEncoding.EncodeToString(decoded)
	assert.Equal(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", b64)
}
