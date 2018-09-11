package oracle

import (
	"bytes"
	"math/rand"
	"strings"
	"time"

	"github.com/t-bast/cryptopals/cipher/block"
)

// BlockMode of encryption.
type BlockMode int

// Block encryption modes.
const (
	ECB BlockMode = 0
	CBC BlockMode = 1
)

// EncryptionOracle encrypts in a randomly chosen mode.
type EncryptionOracle struct {
	Mode BlockMode
}

// NewEncryptionOracle creates a new encryption oracles, with the block mode
// set.
func NewEncryptionOracle() *EncryptionOracle {
	rand.Seed(time.Now().UnixNano())
	toss := rand.Intn(2)

	return &EncryptionOracle{Mode: BlockMode(toss)}
}

// Encrypt oracle that uses ECB or CBC block encryption.
func (o *EncryptionOracle) Encrypt(message []byte) []byte {
	key := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	prefixLen := 5 + rand.Intn(6)
	prefix := make([]byte, prefixLen)
	rand.Read(prefix)
	suffixLen := 5 + rand.Intn(6)
	suffix := make([]byte, suffixLen)
	rand.Read(suffix)

	toEncrypt := append(prefix, message...)
	toEncrypt = append(toEncrypt, suffix...)

	if o.Mode == ECB {
		return block.NewECB(key).Encrypt(toEncrypt)
	}

	return block.NewCBC(key, iv).Encrypt(toEncrypt)
}

// DetectEncryptionMode detects which block encryption the given oracle uses.
func DetectEncryptionMode(oracle *EncryptionOracle) BlockMode {
	encrypted := oracle.Encrypt([]byte(strings.Repeat("B", 64)))
	if bytes.Equal(encrypted[16:32], encrypted[32:48]) {
		return ECB
	}

	return CBC
}
