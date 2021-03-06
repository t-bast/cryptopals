package hash

import (
	"encoding/binary"
	"math/bits"
)

// Sha1Sum computes the sha1 digest of the given message.
func Sha1Sum(message []byte) []byte {
	// Pre-processing

	preproc := append(message, Sha1Pad(message)...)

	// Processing

	h0 := uint32(0x67452301)
	h1 := uint32(0xEFCDAB89)
	h2 := uint32(0x98BADCFE)
	h3 := uint32(0x10325476)
	h4 := uint32(0xC3D2E1F0)

	return Sha1SumInternal(preproc, h0, h1, h2, h3, h4)
}

// Sha1SumInternal computes the sha1 digest of the given message.
// It feeds the given values to the internal registers.
// The message needs to be correctly pre-processed.
func Sha1SumInternal(message []byte, h0, h1, h2, h3, h4 uint32) []byte {
	for i := 0; i < len(message)/64; i++ {
		w := make([]uint32, 80)
		for j := 0; j < 16; j++ {
			w[j] = binary.BigEndian.Uint32(message[64*i+4*j : 64*i+4*(j+1)])
		}
		for j := 16; j < 80; j++ {
			w[j] = bits.RotateLeft32(w[j-3]^w[j-8]^w[j-14]^w[j-16], 1)
		}

		a := uint32(h0)
		b := uint32(h1)
		c := uint32(h2)
		d := uint32(h3)
		e := uint32(h4)

		for ii := 0; ii < 80; ii++ {
			var f, k uint32
			if ii < 20 {
				f = (b & c) | ((^b) & d)
				k = 0x5A827999
			} else if ii < 40 {
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			} else if ii < 60 {
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			} else {
				f = b ^ c ^ d
				k = 0xCA62C1D6
			}

			temp := uint32(bits.RotateLeft32(a, 5) + f + e + k + w[ii])
			e = d
			d = c
			c = bits.RotateLeft32(b, 30)
			b = a
			a = temp
		}

		h0 = h0 + a
		h1 = h1 + b
		h2 = h2 + c
		h3 = h3 + d
		h4 = h4 + e
	}

	// Produce the final hash value (big-endian) as a 160-bit number
	hh := make([]byte, 20)
	binary.BigEndian.PutUint32(hh[:4], h0)
	binary.BigEndian.PutUint32(hh[4:8], h1)
	binary.BigEndian.PutUint32(hh[8:12], h2)
	binary.BigEndian.PutUint32(hh[12:16], h3)
	binary.BigEndian.PutUint32(hh[16:], h4)

	return hh[:]
}

// Sha1Pad produces the padding sha-1 internally uses.
func Sha1Pad(message []byte) []byte {
	ml := 8 * len(message)
	padding := []byte{0x80}

	for {
		if ((len(message)+len(padding))*8)%512 == 448 {
			break
		}

		padding = append(padding, 0x00)
	}

	lenSuffix := make([]byte, 8)
	binary.BigEndian.PutUint64(lenSuffix, uint64(ml))

	return append(padding, lenSuffix...)
}
