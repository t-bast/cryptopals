package block

import (
	"crypto/aes"

	"github.com/t-bast/cryptopals/cipher/padding"
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
	b, err := aes.NewCipher(c.Key)
	if err != nil {
		panic(err)
	}

	blockLen := len(c.Key)
	v := make([]byte, len(c.IV))
	copy(v, c.IV)

	paddedMsg := padding.PKCS7(message, blockLen)
	encrypted := make([]byte, len(paddedMsg))
	for i := 0; i < len(paddedMsg)/blockLen; i++ {
		start := i * blockLen
		end := start + blockLen
		b.Encrypt(encrypted[start:end], xor.Bytes(paddedMsg[start:end], v))
		copy(v, encrypted[start:end])
	}

	return encrypted
}

// Decrypt the given ciphertext.
func (c *CBC) Decrypt(ciphertext []byte) []byte {
	b, err := aes.NewCipher(c.Key)
	if err != nil {
		panic(err)
	}

	blockLen := len(c.Key)
	v := make([]byte, len(c.IV))
	copy(v, c.IV)

	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext)/blockLen; i++ {
		start := i * blockLen
		end := start + blockLen
		block := make([]byte, blockLen)
		b.Decrypt(block, ciphertext[start:end])
		copy(decrypted[start:end], xor.Bytes(block, v))
		copy(v, ciphertext[start:end])
	}

	msg := padding.UnPKCS7(decrypted, blockLen)

	return msg
}
