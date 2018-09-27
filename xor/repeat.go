package xor

import (
	"encoding/base64"
	"encoding/hex"
	"sort"

	"github.com/t-bast/cryptopals/distance"
	"github.com/t-bast/cryptopals/score"
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

// DecryptWithRepeat decrypts the given ciphertext that was encrypted with
// repeating-key XOR.
// The ciphertext is expected to be in base64 encoding.
func DecryptWithRepeat(ciphertext string) string {
	b, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		panic(err)
	}

	var bestScore float32
	var best []byte

	keySizes := keySizeCandidates(b)
	for _, keySize := range keySizes {
		decrypted := decryptWithRepeat(keySize, b)
		score := score.LetterFrequency(decrypted)
		if bestScore < score {
			bestScore = score
			best = decrypted
		}
	}

	return string(best)
}

// decryptWithRepeat finds the most likely key with the given size and decrypts
// the ciphertext with that key.
func decryptWithRepeat(keySize int, ciphertext []byte) []byte {
	// Get the key from block transposition.
	key := make([]byte, keySize)
	for i := 0; i < keySize; i++ {
		var block []byte
		for j := 0; j < len(ciphertext)/keySize; j++ {
			block = append(block, ciphertext[i+j*keySize])
		}

		_, key[i] = decryptSingle(block)
	}

	// Decrypt.
	decrypted := make([]byte, len(ciphertext))
	for i, b := range ciphertext {
		decrypted[i] = b ^ key[i%keySize]
	}

	return decrypted
}

type keySize struct {
	Value int
	Score float32
}

type byScore []keySize

func (s byScore) Len() int {
	return len(s)
}

func (s byScore) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s byScore) Less(i, j int) bool {
	return s[i].Score <= s[j].Score
}

// keySizeCandidates returns the most likely key sizes of an encrypted message
// that uses repeating-key XOR.
func keySizeCandidates(b []byte) []int {
	var candidates byScore
	for i := 2; i <= 60; i++ {
		d1 := distance.Hamming(string(b[:i]), string(b[i:2*i]))
		d2 := distance.Hamming(string(b[:i]), string(b[2*i:3*i]))
		d3 := distance.Hamming(string(b[:i]), string(b[3*i:4*i]))
		d4 := distance.Hamming(string(b[i:2*i]), string(b[2*i:3*i]))
		d5 := distance.Hamming(string(b[i:2*i]), string(b[3*i:4*i]))
		d6 := distance.Hamming(string(b[2*i:3*i]), string(b[3*i:4*i]))
		d := float32(d1+d2+d3+d4+d5+d6) / 6

		candidates = append(candidates, keySize{
			Value: i,
			Score: d / float32(i),
		})
	}

	sort.Sort(candidates)

	return []int{candidates[0].Value, candidates[1].Value, candidates[2].Value}
}
