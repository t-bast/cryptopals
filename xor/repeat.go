package xor

import (
	"encoding/hex"
)

// EncryptWithRepeat encrypts the given message with a repeating-key XOR.
// It returns the hex-encoded encrypted message.
func EncryptWithRepeat(key, message string) string {
	keyLen := len(key)
	encryptedBytes := []byte(message)
	for i := range encryptedBytes {
		encryptedBytes[i] ^= key[i%keyLen]
	}

	return hex.EncodeToString(encryptedBytes)
}
