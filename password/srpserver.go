package password

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// SRPServer is a server in the Secure Remote Password protocol.
type SRPServer struct {
	n *big.Int
	g *big.Int
	k *big.Int

	salt *big.Int
	v    *big.Int
	b    *big.Int
}

// NewSRPServer simulates a server accepting a user sign-up.
func NewSRPServer(n, g, k *big.Int, email string, password string) *SRPServer {
	salt, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	h := sha256.Sum256(append(salt.Bytes(), []byte(password)...))
	x := new(big.Int).SetBytes(h[:])
	v := new(big.Int).Exp(g, x, n)

	return &SRPServer{
		n:    n,
		g:    g,
		k:    k,
		salt: salt,
		v:    v,
	}
}

// CreateKey creates a Diffie-Hellman-Merkle-like key.
func (srp *SRPServer) CreateKey() (*big.Int, *big.Int) {
	var err error
	srp.b, err = rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		panic(err)
	}

	bPub := new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Mul(srp.k, srp.v),
			new(big.Int).Exp(srp.g, srp.b, srp.n),
		),
		srp.n,
	)

	return srp.salt, bPub
}

// ValidateSecretMac validates the client secret's mac.
func (srp *SRPServer) ValidateSecretMac(aPub *big.Int, mac []byte) error {
	bPub := new(big.Int).Mod(
		new(big.Int).Add(
			new(big.Int).Mul(srp.k, srp.v),
			new(big.Int).Exp(srp.g, srp.b, srp.n),
		),
		srp.n,
	)
	uh := sha256.Sum256(append(aPub.Bytes(), bPub.Bytes()...))
	u := new(big.Int).SetBytes(uh[:])

	s := new(big.Int).Exp(
		new(big.Int).Mul(
			aPub,
			new(big.Int).Exp(srp.v, u, srp.n),
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
