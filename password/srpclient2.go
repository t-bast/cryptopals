package password

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

// SRPClient2 is a simplified client in the Secure Remote Password protocol.
// See https://cryptopals.com/sets/5/challenges/38.
type SRPClient2 struct {
	n *big.Int
	g *big.Int
	k *big.Int

	Email    string
	password string
	a        *big.Int
}

// NewSRPClient2 simulates a user sign-up.
func NewSRPClient2(n, g, k *big.Int, email string, password string) *SRPClient2 {
	return &SRPClient2{
		n:        n,
		g:        g,
		k:        k,
		Email:    email,
		password: password,
	}
}

// CreateKey creates a Diffie-Hellman-Merkle-like key.
func (srp *SRPClient2) CreateKey() *big.Int {
	var err error
	srp.a, err = rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	aPub := new(big.Int).Exp(
		srp.g,
		srp.a,
		srp.n,
	)

	return aPub
}

// ComputeSecret computes the shared secret and sends an hmac of it using the
// salt as key.
func (srp *SRPClient2) ComputeSecret(salt *big.Int, bPub *big.Int, u *big.Int) []byte {
	xh := sha256.Sum256(append(salt.Bytes(), []byte(srp.password)...))
	x := new(big.Int).SetBytes(xh[:])

	s := new(big.Int).Exp(
		bPub,
		new(big.Int).Add(
			srp.a,
			new(big.Int).Mul(u, x),
		),
		srp.n,
	)

	k := sha256.Sum256(s.Bytes())
	macer := hmac.New(sha256.New, salt.Bytes())
	return macer.Sum(k[:])
}
