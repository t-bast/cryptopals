package oracle

import (
	"bytes"
	"math/rand"
)

// ECBOracle2 encrypts using ECB with a fixed unknown key, a fixed plaintext
// suffix and a variable plaintext prefix.
// The goal is to decrypt that plaintext suffix.
type ECBOracle2 struct {
	o      *ECBOracle
	prefix []byte
}

// NewECBOracle2 creates an ECBOracle with a variable prefix.
func NewECBOracle2() *ECBOracle2 {
	o := NewECBOracle()

	prefixLen := rand.Intn(64)
	prefix := make([]byte, prefixLen)
	rand.Read(prefix)

	return &ECBOracle2{o: o, prefix: prefix}
}

// Encrypt the given message to which we append the secret message and prepend
// the random prefix.
func (o *ECBOracle2) Encrypt(message []byte) []byte {
	return o.o.Encrypt(append(o.prefix, message...))
}

// DetectECBSecret2 extracts the secret message from the oracle.
func DetectECBSecret2(oracle *ECBOracle2) []byte {
	// It's basically the same algorithm as the previous one once we know the
	// length of the random prefix.
	// We can easily figure this out by inserting characters and seeing which
	// encrypted blocks change.

	blockLen := 16
	prefixLen := detectPrefixLen(oracle)
	blockOffset := prefixLen/blockLen + 1
	maskOffset := make([]byte, blockLen-(prefixLen%blockLen))

	secretLength := len(oracle.Encrypt(maskOffset)) - prefixLen
	secret := make([]byte, secretLength)

	currentBlock := 0
	currentIndex := 0

	for currentBlock*blockLen+currentIndex < secretLength {
		// Initialize mask with last known secret bytes, or fixed values.
		mask := make([]byte, blockLen-1)
		for i := 0; i < blockLen-1; i++ {
			if currentBlock*blockLen+currentIndex >= blockLen-i-1 {
				mask[i] = secret[currentBlock*blockLen+currentIndex-blockLen+i+1]
			} else {
				mask[i] = 'A'
			}
		}

		// Record encryption results for each possible byte added to the mask.
		dict := make([][]byte, 256)
		for i := 0; i < 256; i++ {
			dict[i] = oracle.Encrypt(append(maskOffset, append(mask[:], byte(i))...))[blockOffset*blockLen : (blockOffset+1)*blockLen]
		}

		// Encrypt with the next unknown byte.
		e := oracle.Encrypt(append(maskOffset, mask[:blockLen-currentIndex-1]...))

		// Find the pre-image in dictionary.
		for i, v := range dict {
			if bytes.Equal(v, e[blockLen*(blockOffset+currentBlock):blockLen*(blockOffset+currentBlock+1)]) {
				secret[blockLen*currentBlock+currentIndex] = byte(i)
				break
			}
		}

		currentIndex++
		if currentIndex == blockLen {
			currentBlock++
			currentIndex = 0
		}
	}

	return secret
}

func detectPrefixLen(oracle *ECBOracle2) int {
	blockLen := 16

	blockProbe1 := oracle.Encrypt([]byte{1})
	blockProbe2 := oracle.Encrypt([]byte{2})
	diffBlock := 0
	for ; ; diffBlock++ {
		start := diffBlock * blockLen
		end := start + blockLen
		if !bytes.Equal(blockProbe1[start:end], blockProbe2[start:end]) {
			break
		}
	}

	blockOffset := 1
	for ; ; blockOffset++ {
		probe1 := make([]byte, blockOffset)
		probe2 := make([]byte, blockOffset)
		probe2[blockOffset-1] = 1

		e1 := oracle.Encrypt(probe1)
		e2 := oracle.Encrypt(probe2)

		start := (diffBlock + 1) * blockLen
		end := start + blockLen
		if !bytes.Equal(e1[start:end], e2[start:end]) {
			break
		}
	}

	prefixLen := diffBlock*blockLen + (blockLen - blockOffset + 1)
	return prefixLen
}
