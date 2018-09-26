package challenge

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/stream"
	"github.com/t-bast/cryptopals/oracle"
)

func TestSet3_Challenge1(t *testing.T) {
	assert.NoError(t, oracle.DecryptWithPaddingOracle(oracle.NewPaddingOracle()))
}

func TestSet3_Challenge2(t *testing.T) {
	ciphertext, err := base64.StdEncoding.DecodeString("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
	require.NoError(t, err)

	key := "YELLOW SUBMARINE"
	nonce := uint64(0)

	ctr := stream.NewCTR([]byte(key), nonce)
	decrypted := ctr.Decrypt(ciphertext)

	assert.Equal(t, "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ", string(decrypted))
}
