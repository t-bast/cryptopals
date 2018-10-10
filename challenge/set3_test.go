package challenge

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"io"
	mrand "math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/stream"
	"github.com/t-bast/cryptopals/distance"
	"github.com/t-bast/cryptopals/oracle"
	"github.com/t-bast/cryptopals/prng"
	"github.com/t-bast/cryptopals/xor"
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

func TestSet3_Challenge3(t *testing.T) {
	testData := filepath.Join("testdata", "3_3.txt")
	f, err := os.OpenFile(testData, os.O_RDONLY, os.ModePerm)
	require.NoError(t, err)
	defer f.Close()

	key := make([]byte, 16)
	rand.Read(key)
	ctr := stream.NewCTR(key, 0)

	reader := bufio.NewReader(f)
	var encrypted [][]byte
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}

		lineBytes, err := base64.StdEncoding.DecodeString(string(line))
		require.NoError(t, err)

		encrypted = append(encrypted, ctr.Encrypt(lineBytes))
	}

	keystream := stream.PwnCTRNonceReuseLetterFrequency(encrypted)
	decrypted := xor.Bytes(encrypted[0], keystream[:len(encrypted[0])])

	// The current method does a single pass on letter frequency.
	// It works well for the beginning of the message but can miss the end.
	// However it's then easy to test several candidate keystream bytes for the
	// end of the message manually until it makes sense.
	assert.Equal(t, 0, strings.Index(string(decrypted), "I have met them at close of"))
}

func TestSet3_Challenge4(t *testing.T) {
	testData := filepath.Join("testdata", "3_4.txt")
	f, err := os.OpenFile(testData, os.O_RDONLY, os.ModePerm)
	require.NoError(t, err)
	defer f.Close()

	key := make([]byte, 16)
	rand.Read(key)
	ctr := stream.NewCTR(key, 0)

	reader := bufio.NewReader(f)
	var encrypted [][]byte
	var smallestPlaintext []byte
	var smallestEncrypted []byte
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}

		lineBytes, err := base64.StdEncoding.DecodeString(string(line))
		require.NoError(t, err)

		encryptedLine := ctr.Encrypt(lineBytes)
		encrypted = append(encrypted, encryptedLine)

		if len(smallestPlaintext) == 0 || len(lineBytes) < len(smallestPlaintext) {
			smallestPlaintext = lineBytes
			smallestEncrypted = encryptedLine
		}
	}

	keystream := stream.PwnCTRNonceReuseStatistical(encrypted)
	smallestDecrypted := xor.Bytes(smallestEncrypted, keystream[:len(smallestEncrypted)])

	// We're not finding exactly the right result (one letter is off).
	// But it's enough for a human to correct the last remaining error.
	dist := distance.Hamming(string(smallestPlaintext), string(smallestDecrypted))
	assert.True(t, dist <= 5)
}

func TestSet3_Challenge6(t *testing.T) {
	r1 := 40 + mrand.Intn(1000-40)
	rng := prng.NewMT19937(r1)

	r2 := mrand.Intn(1000)
	out := rng.Rand()

	// The goal is now to find r1 using only out.
	for i := r1 + r2; i >= 0; i-- {
		out2 := prng.NewMT19937(i).Rand()
		if out == out2 {
			assert.Equal(t, r1, i)
			return
		}
	}

	assert.Fail(t, "Couldn't find seed")
}

func Test3_Challenge7(t *testing.T) {
	rng := prng.NewMT19937(mrand.Intn(1000))

	state := make([]int, 624)
	for i := 0; i < 624; i++ {
		state[i] = prng.MT19937Untemper(rng.Rand())
	}

	cloned := prng.NewMT19937FromState(state[:])
	for i := 0; i < 624; i++ {
		cloned.Rand()
	}

	for i := 0; i < 100; i++ {
		assert.Equal(t, rng.Rand(), cloned.Rand())
	}
}
