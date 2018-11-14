package password

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// SRPServer2 is a simplified server in the Secure Remote Password protocol.
// See https://cryptopals.com/sets/5/challenges/38.
type SRPServer2 struct {
	n *big.Int
	g *big.Int
	k *big.Int

	salt *big.Int
	u    *big.Int
	v    *big.Int
	b    *big.Int
}

// NewSRPServer2 simulates a server accepting a user sign-up.
func NewSRPServer2(n, g, k *big.Int, email string, password string) *SRPServer2 {
	salt, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	h := sha256.Sum256(append(salt.Bytes(), []byte(password)...))
	x := new(big.Int).SetBytes(h[:])
	v := new(big.Int).Exp(g, x, n)

	return &SRPServer2{
		n:    n,
		g:    g,
		k:    k,
		salt: salt,
		v:    v,
	}
}

// CreateKey creates a Diffie-Hellman-Merkle-like key.
func (srp *SRPServer2) CreateKey() (*big.Int, *big.Int, *big.Int) {
	var err error
	srp.b, err = rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	bPub := new(big.Int).Exp(
		srp.g,
		srp.b,
		srp.n,
	)

	uBytes := make([]byte, 128)
	rand.Read(uBytes)
	srp.u = new(big.Int).SetBytes(uBytes)

	return srp.salt, bPub, srp.u
}

// ValidateSecretMac validates the client secret's mac.
func (srp *SRPServer2) ValidateSecretMac(aPub *big.Int, mac []byte) error {
	s := new(big.Int).Exp(
		new(big.Int).Mul(
			aPub,
			new(big.Int).Exp(srp.v, srp.u, srp.n),
		),
		srp.b,
		srp.n,
	)

	k := sha256.Sum256(s.Bytes())
	macer := hmac.New(sha256.New, srp.salt.Bytes())
	expectedMac := macer.Sum(k[:])

	if !bytes.Equal(expectedMac, mac) {
		return errors.New("invalid secret")
	}

	return nil
}
