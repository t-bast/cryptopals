package set1

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
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

func TestSet1_Challenge3(t *testing.T) {
	decrypted, _ := xor.DecryptSingle("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	assert.Equal(t, "Cooking MC's like a pound of bacon", decrypted)
}

func TestSet1_Challenge4(t *testing.T) {
	testData := filepath.Join("testdata", "1_4.txt")
	f, _ := os.OpenFile(testData, os.O_RDONLY, os.ModePerm)
	defer f.Close()

	var bestCandidate string
	var bestScore float32

	reader := bufio.NewReader(f)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}

		candidate, score := xor.DecryptSingle(string(line))
		if score > bestScore {
			bestScore = score
			bestCandidate = candidate
		}
	}

	assert.Equal(t, "Now that the party is jumping\n", bestCandidate)
}

func TestSet1_Challenge5(t *testing.T) {
	encrypted := xor.EncryptWithRepeat(
		"ICE",
		"Burning 'em, if you ain't quick and nimble\n"+"I go crazy when I hear a cymbal")

	assert.Equal(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", encrypted)
}
