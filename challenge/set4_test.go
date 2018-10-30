package challenge

import (
	"encoding/base64"
	"encoding/binary"
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/block"
	"github.com/t-bast/cryptopals/cipher/stream"
	"github.com/t-bast/cryptopals/hash"
	"github.com/t-bast/cryptopals/mac"
	"github.com/t-bast/cryptopals/oracle"
	"github.com/t-bast/cryptopals/xor"
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

func TestSet4_Challenge3(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	cbc := block.NewCBC(key, key)

	ciphertext := cbc.Encrypt([]byte("Je laisse a Gavarni, poete des chloroses, Son tr"))
	var modified []byte
	modified = append(modified, ciphertext[:16]...)
	modified = append(modified, make([]byte, 16)...)
	modified = append(modified, ciphertext[:16]...)

	defer func() {
		r := recover().(map[string]string)
		recoveredKey := xor.Bytes([]byte(r["msg"][:16]), []byte(r["msg"][32:48]))
		assert.Equal(t, key, recoveredKey)
	}()

	cbc.Decrypt(modified)
	assert.Fail(t, "should have panicked")
}

func TestSet4_Challenge4(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	macer := mac.NewSha1Keyed(key)

	m1 := macer.Authenticate([]byte("Je laisse a Gavarni, poete des chloroses,"))
	m2 := macer.Authenticate([]byte("Je laisse a Gavarnu, poete des chloroses,"))

	assert.NotEqual(t, m1, m2)
}

func TestSet4_Challenge5(t *testing.T) {
	// The attacker doesn't know the key.
	key := []byte("YELLOW SUBMARINE")
	macer := mac.NewSha1Keyed(key)

	// But she knows the initial message and the length of the key.
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	m1 := macer.Authenticate(message)

	// And from only the original mac and the message, she's able to produce
	// a valid mac for a message that has ";admin=true" appended.
	h0 := binary.BigEndian.Uint32(m1[:4])
	h1 := binary.BigEndian.Uint32(m1[4:8])
	h2 := binary.BigEndian.Uint32(m1[8:12])
	h3 := binary.BigEndian.Uint32(m1[12:16])
	h4 := binary.BigEndian.Uint32(m1[16:])

	// Figure out the length of the mac-ed message (with key prefix).
	tmp := append(make([]byte, 16), message...)
	originalPadding := hash.Sha1Pad(tmp)
	tmp = append(tmp, originalPadding...)
	originalPaddedLen := len(tmp)

	fakeMessage := append(make([]byte, originalPaddedLen), []byte(";admin=true")...)
	paddedFake := append(fakeMessage, hash.Sha1Pad(fakeMessage)...)
	assert.Contains(t, string(paddedFake), ";admin=true")

	m2 := hash.Sha1SumInternal(paddedFake[originalPaddedLen:], h0, h1, h2, h3, h4)
	assert.Equal(t, m2, macer.Authenticate(append(
		message,
		append(originalPadding, []byte(";admin=true")...)...)))
}

func TestSet4_Challenge6(t *testing.T) {
	// The attacker doesn't know the key.
	key := []byte("YELLOW SUBMARINE")
	macer := mac.NewMD4Keyed(key)

	// But she knows the initial message and the length of the key.
	message := []byte("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
	m1 := macer.Authenticate(message)

	// And from only the original mac and the message, she's able to produce
	// a valid mac for a message that has ";admin=true" appended.
	a := binary.BigEndian.Uint32(m1[:4])
	b := binary.BigEndian.Uint32(m1[4:8])
	c := binary.BigEndian.Uint32(m1[8:12])
	d := binary.BigEndian.Uint32(m1[12:16])

	// Figure out the length of the mac-ed message (with key prefix).
	tmp := append(make([]byte, 16), message...)
	originalPadding := hash.MD4Pad(tmp)
	tmp = append(tmp, originalPadding...)
	originalPaddedLen := len(tmp)

	fakeMessage := append(make([]byte, originalPaddedLen), []byte(";admin=true")...)
	paddedFake := append(fakeMessage, hash.MD4Pad(fakeMessage)...)
	assert.Contains(t, string(paddedFake), ";admin=true")

	m2 := hash.MD4SumInternal(paddedFake[originalPaddedLen:], a, b, c, d)
	assert.Equal(t, m2, macer.Authenticate(append(
		message,
		append(originalPadding, []byte(";admin=true")...)...)))
}

func TestSet4_Challenge7(t *testing.T) {
	m := mac.NewSha1Hmac([]byte("YELLOW SUBMARINE"))
	message := []byte("Authenticatz plz")

	macPwn := make([]byte, 20)
LOOP:
	for i := 0; i < 20; i++ {
		// Baseline (needs two measures in case 0 was the valid byte).
		start := time.Now()
		macPwn[i] = 0
		ok := m.InsecureVerify(i, message, macPwn)
		total1 := time.Since(start)
		if ok {
			break LOOP
		}

		start = time.Now()
		macPwn[i] = 1
		ok = m.InsecureVerify(i, message, macPwn)
		total2 := time.Since(start)
		if ok {
			break LOOP
		}

		baseline := total1
		if total2 < total1 {
			baseline = total2
		}

		for j := byte(0); j <= byte(255); j++ {
			macPwn[i] = j
			start := time.Now()
			ok := m.InsecureVerify(i, message, macPwn)
			if ok {
				break LOOP
			}

			total := time.Since(start)
			if (total - baseline) > 2*time.Millisecond {
				break
			}
		}
	}

	assert.True(t, m.Verify(message, macPwn))
}
