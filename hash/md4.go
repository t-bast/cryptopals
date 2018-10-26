package hash

import (
	"encoding/binary"
	"math/bits"
)

// MD4Sum computes the MD4 digest of the given message.
func MD4Sum(message []byte) []byte {
	// Pre-processing (same padding as SHA1)
	preproc := append(message, MD4Pad(message)...)

	a := uint32(0x01234567)
	b := uint32(0x89abcdef)
	c := uint32(0xfedcba98)
	d := uint32(0x76543210)

	return MD4SumInternal(preproc, a, b, c, d)
}

// MD4SumInternal computes the MD4 digest of the given message.
// It feeds the given values to the internal registers.
// The message needs to be correctly pre-processed.
func MD4SumInternal(message []byte, a, b, c, d uint32) []byte {
	for i := 0; i < len(message)/64; i++ {
		x := make([]uint32, 16)
		for j := 0; j < 16; j++ {
			x[j] = binary.BigEndian.Uint32(message[64*i+4*j : 64*i+4*(j+1)])
		}

		aa := a
		bb := b
		cc := c
		dd := d

		// Round 1.
		a = bits.RotateLeft32(a+md4F(b, c, d)+x[0], 3)
		d = bits.RotateLeft32(d+md4F(a, b, c)+x[1], 7)
		c = bits.RotateLeft32(c+md4F(d, a, b)+x[2], 11)
		b = bits.RotateLeft32(b+md4F(c, d, a)+x[3], 19)

		a = bits.RotateLeft32(a+md4F(b, c, d)+x[4], 3)
		d = bits.RotateLeft32(d+md4F(a, b, c)+x[5], 7)
		c = bits.RotateLeft32(c+md4F(d, a, b)+x[6], 11)
		b = bits.RotateLeft32(b+md4F(c, d, a)+x[7], 19)

		a = bits.RotateLeft32(a+md4F(b, c, d)+x[8], 3)
		d = bits.RotateLeft32(d+md4F(a, b, c)+x[9], 7)
		c = bits.RotateLeft32(c+md4F(d, a, b)+x[10], 11)
		b = bits.RotateLeft32(b+md4F(c, d, a)+x[11], 19)

		a = bits.RotateLeft32(a+md4F(b, c, d)+x[12], 3)
		d = bits.RotateLeft32(d+md4F(a, b, c)+x[13], 7)
		c = bits.RotateLeft32(c+md4F(d, a, b)+x[14], 11)
		b = bits.RotateLeft32(b+md4F(c, d, a)+x[15], 19)

		// Round 2.
		a = bits.RotateLeft32(a+md4G(b, c, d)+x[0]+0x5A827999, 3)
		d = bits.RotateLeft32(d+md4G(a, b, c)+x[4]+0x5A827999, 5)
		c = bits.RotateLeft32(c+md4G(d, a, b)+x[8]+0x5A827999, 9)
		b = bits.RotateLeft32(b+md4G(c, d, a)+x[12]+0x5A827999, 13)

		a = bits.RotateLeft32(a+md4G(b, c, d)+x[1]+0x5A827999, 3)
		d = bits.RotateLeft32(d+md4G(a, b, c)+x[5]+0x5A827999, 5)
		c = bits.RotateLeft32(c+md4G(d, a, b)+x[9]+0x5A827999, 9)
		b = bits.RotateLeft32(b+md4G(c, d, a)+x[13]+0x5A827999, 13)

		a = bits.RotateLeft32(a+md4G(b, c, d)+x[2]+0x5A827999, 3)
		d = bits.RotateLeft32(d+md4G(a, b, c)+x[6]+0x5A827999, 5)
		c = bits.RotateLeft32(c+md4G(d, a, b)+x[10]+0x5A827999, 9)
		b = bits.RotateLeft32(b+md4G(c, d, a)+x[14]+0x5A827999, 13)

		a = bits.RotateLeft32(a+md4G(b, c, d)+x[3]+0x5A827999, 3)
		d = bits.RotateLeft32(d+md4G(a, b, c)+x[7]+0x5A827999, 5)
		c = bits.RotateLeft32(c+md4G(d, a, b)+x[11]+0x5A827999, 9)
		b = bits.RotateLeft32(b+md4G(c, d, a)+x[15]+0x5A827999, 13)

		// Round 3.
		a = bits.RotateLeft32(a+md4H(b, c, d)+x[0]+0x6ED9EBA1, 3)
		d = bits.RotateLeft32(d+md4H(a, b, c)+x[8]+0x6ED9EBA1, 9)
		c = bits.RotateLeft32(c+md4H(d, a, b)+x[4]+0x6ED9EBA1, 11)
		b = bits.RotateLeft32(b+md4H(c, d, a)+x[12]+0x6ED9EBA1, 15)

		a = bits.RotateLeft32(a+md4H(b, c, d)+x[2]+0x6ED9EBA1, 3)
		d = bits.RotateLeft32(d+md4H(a, b, c)+x[10]+0x6ED9EBA1, 9)
		c = bits.RotateLeft32(c+md4H(d, a, b)+x[6]+0x6ED9EBA1, 11)
		b = bits.RotateLeft32(b+md4H(c, d, a)+x[14]+0x6ED9EBA1, 15)

		a = bits.RotateLeft32(a+md4H(b, c, d)+x[1]+0x6ED9EBA1, 3)
		d = bits.RotateLeft32(d+md4H(a, b, c)+x[9]+0x6ED9EBA1, 9)
		c = bits.RotateLeft32(c+md4H(d, a, b)+x[5]+0x6ED9EBA1, 11)
		b = bits.RotateLeft32(b+md4H(c, d, a)+x[13]+0x6ED9EBA1, 15)

		a = bits.RotateLeft32(a+md4H(b, c, d)+x[3]+0x6ED9EBA1, 3)
		d = bits.RotateLeft32(d+md4H(a, b, c)+x[11]+0x6ED9EBA1, 9)
		c = bits.RotateLeft32(c+md4H(d, a, b)+x[7]+0x6ED9EBA1, 11)
		b = bits.RotateLeft32(b+md4H(c, d, a)+x[15]+0x6ED9EBA1, 15)

		// Finalize.
		a += aa
		b += bb
		c += cc
		d += dd
	}

	// Produce the final hash value (big-endian) as a 128-bit number.
	hh := make([]byte, 16)
	binary.BigEndian.PutUint32(hh[:4], a)
	binary.BigEndian.PutUint32(hh[4:8], b)
	binary.BigEndian.PutUint32(hh[8:12], c)
	binary.BigEndian.PutUint32(hh[12:16], d)

	return hh[:]
}

// MD4Pad produces the padding MD4 internally uses.
func MD4Pad(message []byte) []byte {
	// Same padding as SHA-1.
	return Sha1Pad(message)
}

func md4F(x, y, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func md4G(x, y, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func md4H(x, y, z uint32) uint32 {
	return x ^ y ^ z
}
