package oracle

import (
	"math/rand"
	"strings"
	"time"

	"github.com/t-bast/cryptopals/cipher/stream"
)

// CTROracle encrypts data with a known prefix and suffix.
// It escapes some characters.
type CTROracle struct {
	Key   []byte
	Nonce uint64
}

// NewCTROracle creates a key for a CTR oracle.
func NewCTROracle() *CTROracle {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	rand.Read(key)

	nonce := rand.Intn(1 << 31)

	return &CTROracle{Key: key, Nonce: uint64(nonce)}
}

// Encrypt a message, escaping ";" and "=" and adding prefix and suffix.
func (o *CTROracle) Encrypt(plaintext string) []byte {
	temp := strings.Replace(plaintext, "=", "'='", -1)
	sanitized := strings.Replace(temp, ";", "';'", -1)
	toEncrypt := "comment1=cooking%20MCs;userdata=" + sanitized + ";comment2=%20like%20a%20pound%20of%20bacon"

	ctr := stream.NewCTR(o.Key, o.Nonce)
	return ctr.Encrypt([]byte(toEncrypt))
}

// CheckAdmin decrypts the given ciphertext and checks if ";admin=true;" has
// been successfully inserted.
func (o *CTROracle) CheckAdmin(ciphertext []byte) bool {
	ctr := stream.NewCTR(o.Key, o.Nonce)
	decrypted := string(ctr.Decrypt(ciphertext))

	return strings.Index(decrypted, ";admin=true;") >= 0
}
