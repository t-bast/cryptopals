package oracle

import (
	"math/rand"
	"strings"
	"time"

	"github.com/t-bast/cryptopals/cipher/block"
)

// CBCOracle encrypts data with a known prefix and suffix.
// It escapes some characters.
type CBCOracle struct {
	Key []byte
	IV  []byte
}

// NewCBCOracle creates a key for a CBC oracle.
func NewCBCOracle() *CBCOracle {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	rand.Read(key)

	iv := [16]byte{}

	return &CBCOracle{Key: key, IV: iv[:]}
}

// Encrypt a message, escaping ";" and "=" and adding prefix and suffix.
func (o *CBCOracle) Encrypt(plaintext string) []byte {
	temp := strings.Replace(plaintext, "=", "'='", -1)
	sanitized := strings.Replace(temp, ";", "';'", -1)
	toEncrypt := "comment1=cooking%20MCs;userdata=" + sanitized + ";comment2=%20like%20a%20pound%20of%20bacon"

	cbc := block.NewCBC(o.Key, o.IV)
	return cbc.Encrypt([]byte(toEncrypt))
}

// CheckAdmin decrypts the given ciphertext and checks if ";admin=true;" has
// been successfully inserted.
func (o *CBCOracle) CheckAdmin(ciphertext []byte) bool {
	cbc := block.NewCBC(o.Key, o.IV)
	decrypted := string(cbc.Decrypt(ciphertext))

	return strings.Index(decrypted, ";admin=true;") >= 0
}
