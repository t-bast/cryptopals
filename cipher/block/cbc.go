package block

import (
	"github.com/t-bast/cryptopals/xor"
)

// CBC implements CBC encryption with AES.
type CBC struct {
	Key []byte
	IV  []byte
}

// NewCBC creates a new CBC encryptor with the given key and IV.
func NewCBC(key []byte, iv []byte) *CBC {
	return &CBC{Key: key, IV: iv}
}

// Encrypt the given message.
func (c *CBC) Encrypt(message []byte) []byte {
	blockLen := len(c.Key)
	ecb := NewECB(c.Key)
	v := make([]byte, len(c.IV))
	copy(v, c.IV)

	encrypted := make([]byte, len(message))
	for i := 0; i < len(message)/blockLen; i++ {
		start := i * blockLen
		end := start + blockLen
		block := ecb.Encrypt(xor.Bytes(message[start:end], v))
		copy(v, block)
		copy(encrypted[start:end], block)
	}

	return encrypted
}

// Decrypt the given ciphertext.
func (c *CBC) Decrypt(ciphertext []byte) []byte {
	blockLen := len(c.Key)
	ecb := NewECB(c.Key)
	v := make([]byte, len(c.IV))
	copy(v, c.IV)

	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext)/blockLen; i++ {
		start := i * blockLen
		end := start + blockLen
		block := xor.Bytes(ecb.Decrypt(ciphertext[start:end]), v)
		copy(decrypted[start:end], block[:])
		copy(v, ciphertext[start:end])
	}

	return decrypted
}
