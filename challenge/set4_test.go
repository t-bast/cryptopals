package challenge

import (
	"encoding/base64"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/block"
	"github.com/t-bast/cryptopals/cipher/stream"
	"github.com/t-bast/cryptopals/oracle"
)

func TestSet4_Challenge1(t *testing.T) {
	testData := filepath.Join("testdata", "1_7.txt")
	encrypted, err := ioutil.ReadFile(testData)
	require.NoError(t, err)

	encryptedBytes, err := base64.StdEncoding.DecodeString(string(encrypted))
	require.NoError(t, err)

	decrypted := block.NewECB([]byte("YELLOW SUBMARINE")).Decrypt(encryptedBytes)

	sk := "YELLOW SUBMARINE"
	ctr := stream.NewCTR([]byte(sk), 0)
	reencryptedBytes := ctr.Encrypt(decrypted)

	// Brute-force bytes one by one.
	plaintext := make([]byte, len(reencryptedBytes))
	for i := 0; i < len(reencryptedBytes); i++ {
		for b := byte(0); b <= byte(255); b++ {
			test := stream.EditCTR(reencryptedBytes, []byte(sk), i, []byte{b})
			if test[i] == reencryptedBytes[i] {
				plaintext[i] = b
				break
			}
		}
	}

	assert.Equal(t, decrypted, plaintext)
}

func TestSet4_Challenge2(t *testing.T) {
	o := oracle.NewCTROracle()

	// Instead of ; and = that are going to be replaced by the encrypt method,
	// we use the ascii char just below them.
	encrypted := o.Encrypt("\x3aadmin\x3ctrue\x3a")

	// Then we do some bit-flipping on the ciphertext to change our inserted
	// characters to ; and =.
	encrypted[32] ^= 1
	encrypted[38] ^= 1
	encrypted[43] ^= 1

	assert.True(t, o.CheckAdmin(encrypted))
}
