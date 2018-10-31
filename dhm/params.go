package dhm

import (
	"crypto/rand"
	"math/big"
)

// Params contains parameters for a Diffie-Hellman-Merkle key exchange.
// We use the field of integers as the underlying group.
type Params struct {
	G *big.Int
	P *big.Int
}

// New sets up key exchange parameters.
func New(g *big.Int, p *big.Int) *Params {
	return &Params{G: g, P: p}
}

// GenerateKeys generates a private key and the associated public key.
func (p *Params) GenerateKeys() (*big.Int, *big.Int) {
	sk, err := rand.Int(rand.Reader, p.P)
	if err != nil {
		panic(err)
	}

	pk := new(big.Int).Exp(p.G, sk, p.P)
	return sk, pk
}

// SharedSecret from the key exchange.
// You should provide your private key and the other party's public key.
// You should not use this secret directly. Instead, derive a private key
// in a secure way.
func (p *Params) SharedSecret(sk *big.Int, pk *big.Int) []byte {
	s := new(big.Int).Exp(pk, sk, p.P)
	return s.Bytes()
}
