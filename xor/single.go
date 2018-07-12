package xor

import (
	"encoding/hex"
)

var (
	// letterFrequency in the english language.
	// See http://norvig.com/mayzner.html.
	letterFrequency = map[byte]float32{
		'a': 8.04,
		'b': 1.48,
		'c': 3.34,
		'd': 3.82,
		'e': 12.49,
		'f': 2.40,
		'g': 1.87,
		'h': 5.05,
		'i': 7.57,
		'j': 0.16,
		'k': 0.54,
		'l': 4.07,
		'm': 2.51,
		'n': 7.23,
		'o': 7.64,
		'p': 2.14,
		'q': 0.12,
		'r': 6.28,
		's': 6.51,
		't': 9.28,
		'u': 2.73,
		'v': 1.05,
		'w': 1.68,
		'x': 0.23,
		'y': 1.66,
		'z': 0.09,
		' ': 25.0, // couldn't find data for this one but it's important
	}
)

// DecryptSingle decrypts a hex-encoded string that has been XOR'd against a
// single character.
// It assumes that the message is english ASCII and uses letter frequency to
// select the most likely decrypted value.
func DecryptSingle(c string) string {
	decoded, err := hex.DecodeString(c)
	if err != nil {
		panic(err)
	}

	var best []byte
	var bestScore float32

	for b := 0; b < 256; b++ {
		b := byte(b)
		decrypted := make([]byte, len(decoded))
		for i := 0; i < len(decrypted); i++ {
			decrypted[i] = b ^ decoded[i]
		}

		s := score(decrypted)
		if s > bestScore {
			bestScore = s
			best = decrypted
		}
	}

	return string(best)
}

// score a decryption candidate using letter frequency.
func score(decrypted []byte) float32 {
	res := float32(0)
	for _, b := range decrypted {
		if 65 <= b && b <= 90 {
			b = b + 32
		}

		freq, ok := letterFrequency[b]
		if ok {
			res += freq
		}
	}

	return res
}
