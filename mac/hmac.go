package mac

import (
	"bytes"
	"crypto/sha1"
	"time"

	"github.com/t-bast/cryptopals/xor"
)

// Sha1Hmac creates a mac using the HMAC algorithm.
type Sha1Hmac struct {
	key     []byte
	okeypad []byte
	ikeypad []byte
}

// NewSha1Hmac creates a mac-er with a given key.
func NewSha1Hmac(key []byte) *Sha1Hmac {
	actualKey := key
	if len(actualKey) > 64 {
		hashedKey := sha1.Sum(actualKey)
		actualKey = hashedKey[:]
	}

	if len(actualKey) < 64 {
		actualKey = append(actualKey, make([]byte, 64-len(actualKey))...)
	}

	opad := make([]byte, 64)
	ipad := make([]byte, 64)
	for i := 0; i < 64; i++ {
		opad[i] = 0x5C
		ipad[i] = 0x36
	}

	return &Sha1Hmac{
		key:     actualKey,
		okeypad: xor.Bytes(actualKey, opad),
		ikeypad: xor.Bytes(actualKey, ipad),
	}
}

// Authenticate creates a mac for the given message.
func (m *Sha1Hmac) Authenticate(message []byte) []byte {
	h1 := sha1.Sum(append(m.ikeypad, message...))
	h2 := sha1.Sum(append(
		m.okeypad,
		h1[:]...,
	))

	return h2[:]
}

// Verify the mac of a given message.
func (m *Sha1Hmac) Verify(message, mac []byte) bool {
	expected := m.Authenticate(message)
	return bytes.Equal(expected, mac)
}

// InsecureVerify checks the mac for a given message but has a timing leak.
func (m *Sha1Hmac) InsecureVerify(index int, message, mac []byte) bool {
	expected := m.Authenticate(message)
	for i := 0; i < len(expected); i++ {
		if expected[i] != mac[i] {
			return false
		}

		if i >= (index - 1) {
			<-time.After(3 * time.Millisecond)
		}
	}

	return true
}
