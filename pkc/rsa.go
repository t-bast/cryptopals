package pkc

import (
	"crypto/rand"
	"math/big"
)

// RSA implements the RSA crypto-system.
type RSA struct {
	n *big.Int
	e *big.Int
	d *big.Int
}

// NewRSA generates primes for an instance of RSA.
// The result is a private key and public key for a specific secure channel.
func NewRSA() *RSA {
	for {
		p, err := rand.Prime(rand.Reader, 128)
		if err != nil {
			panic(err)
		}

		q, err := rand.Prime(rand.Reader, 128)
		if err != nil {
			panic(err)
		}

		n := new(big.Int).Mul(p, q)
		et := new(big.Int).Mul(
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)),
		)
		e := big.NewInt(3)
		d := new(big.Int).ModInverse(e, et)

		if d != nil {
			return &RSA{
				n: n,
				e: e,
				d: d,
			}
		}
	}
}

// PublicKey returns the RSA public key.
func (r *RSA) PublicKey() (*big.Int, *big.Int) {
	return r.e, r.n
}

// Encrypt a plaintext to the RSA instance.
func (r *RSA) Encrypt(plaintext []byte) []byte {
	m := new(big.Int).SetBytes(plaintext)
	c := new(big.Int).Exp(m, r.e, r.n)
	return c.Bytes()
}

// Decrypt a ciphertext.
func (r *RSA) Decrypt(ciphertext []byte) []byte {
	c := new(big.Int).SetBytes(ciphertext)
	m := new(big.Int).Exp(c, r.d, r.n)
	return m.Bytes()
}
