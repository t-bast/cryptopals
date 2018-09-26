package oracle

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"

	"github.com/t-bast/cryptopals/cipher/block"
)

// PaddingOracle implements a padding oracle.
type PaddingOracle struct {
	key    []byte
	IV     []byte
	Secret []byte
}

// NewPaddingOracle creates a new padding oracle that can be attacked.
// It also provides the encrypted string that should be decrypted.
func NewPaddingOracle() (*PaddingOracle, []byte) {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	rand.Read(key)

	iv := make([]byte, 16)
	rand.Read(iv)

	secrets := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	secretIndex := rand.Intn(10)
	fmt.Printf("Secret index: %d\n", secretIndex)
	secret, err := base64.StdEncoding.DecodeString(secrets[secretIndex])
	if err != nil {
		panic(err)
	}

	cbc := block.NewCBC(key, iv[:])
	encrypted := cbc.Encrypt(secret)

	return &PaddingOracle{
		key:    key,
		IV:     iv[:],
		Secret: secret,
	}, encrypted
}

// CheckPadding decrypts the given ciphertext and checks if padding is valid.
func (o *PaddingOracle) CheckPadding(ciphertext []byte) (res bool) {
	defer func() {
		if r := recover(); r != nil {
			res = false
		}
	}()

	cbc := block.NewCBC(o.key, o.IV)
	cbc.Decrypt(ciphertext)
	res = true
	return
}

// DecryptWithPaddingOracle implements a padding oracle attack on CBC
// encryption.
func DecryptWithPaddingOracle(o *PaddingOracle, ciphertext []byte) error {
	var decrypted []byte
	blockCount := len(ciphertext) / 16

	fmt.Printf("Trying to decrypt: %s\n", o.Secret)
	fmt.Printf("Ciphertext contains %d blocks\n", blockCount)

	// We need to prepend the IV block to decrypt the first block.
	ciphertext = append(o.IV, ciphertext...)

	for blockNumber := 0; blockNumber < blockCount; blockNumber++ {
		decryptedBlock := decryptBlockWithPaddingOracle(o, ciphertext, blockNumber)
		decrypted = append(decrypted, decryptedBlock...)
	}

	if !bytes.Equal(o.Secret, decrypted[:len(o.Secret)]) {
		return fmt.Errorf("Invalid decryption:\nGot: %s\nWant: %s", decrypted, o.Secret)
	}

	return nil
}

func decryptBlockWithPaddingOracle(o *PaddingOracle, ciphertext []byte, blockNumber int) []byte {
	fmt.Printf("Decrypting block %d\n", blockNumber)
	decrypted := make([]byte, 16)

	for i := 0; i < 16; i++ {
		cipherPart := make([]byte, 16*2)
		copy(cipherPart, ciphertext[16*blockNumber:16*(blockNumber+2)])

		// Insert previously found bytes.
		for j := 0; j < i; j++ {
			cipherPart[len(cipherPart)-16-1-j] = cipherPart[len(cipherPart)-16-1-j] ^ decrypted[16-1-j] ^ byte(i+1)
		}

		found := false
	guessLoop:
		// Guess the current byte.
		for g := decrypted[16-1-i] + 1; g <= 125; g++ {
			encryptedGuess := make([]byte, len(cipherPart))
			copy(encryptedGuess, cipherPart)
			encryptedGuess[len(encryptedGuess)-16-1-i] = encryptedGuess[len(encryptedGuess)-16-1-i] ^ g ^ byte(i+1)

			found = o.CheckPadding(encryptedGuess)
			if found {
				fmt.Printf("[%d] Found byte %c (%d)\n", i, g, g)
				decrypted[16-1-i] = g
				break guessLoop
			}
		}

		if !found {
			i -= 2
		}
	}

	fmt.Printf("Decrypted block %d: %s\n", blockNumber, decrypted)
	return decrypted
}
