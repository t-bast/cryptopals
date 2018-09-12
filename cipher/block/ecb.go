package block

import (
	"crypto/aes"

	"github.com/t-bast/cryptopals/cipher/padding"
)

// ECB implements ECB encryption with AES.
type ECB struct {
	Key []byte
}

// NewECB creates a new ECB encryptor with the given key.
func NewECB(key []byte) *ECB {
	return &ECB{Key: key}
}

// Encrypt encrypts the given message.
func (e *ECB) Encrypt(message []byte) []byte {
	b, err := aes.NewCipher(e.Key)
	if err != nil {
		panic(err)
	}

	paddedMsg := padding.PKCS7(message, len(e.Key))

	encrypted := make([]byte, len(paddedMsg))
	for i := 0; i < len(paddedMsg)/len(e.Key); i++ {
		start := i * len(e.Key)
		end := start + len(e.Key)
		b.Encrypt(encrypted[start:end], paddedMsg[start:end])
	}

	return encrypted
}

// Decrypt decrypts the given ciphertext.
func (e *ECB) Decrypt(ciphertext []byte) []byte {
	b, err := aes.NewCipher(e.Key)
	if err != nil {
		panic(err)
	}

	decrypted := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext)/len(e.Key); i++ {
		start := i * len(e.Key)
		end := start + len(e.Key)
		b.Decrypt(decrypted[start:end], ciphertext[start:end])
	}

	msg := padding.UnPKCS7(decrypted, len(e.Key))

	return msg
}
