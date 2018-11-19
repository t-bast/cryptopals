package challenge

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/pkc"
)

func TestSet6_Challenge1(t *testing.T) {
	r := pkc.NewRSA()
	message := []byte("Aimer et mourir")
	ciphertext := r.Encrypt(message)
	c := new(big.Int).SetBytes(ciphertext)

	e, n := r.PublicKey()
	s, _ := rand.Int(rand.Reader, n)
	c2 := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(s, e, n),
			c,
		),
		n,
	)

	p2 := new(big.Int).SetBytes(r.Decrypt(c2.Bytes()))
	p := new(big.Int).Mod(
		new(big.Int).Mul(
			p2,
			new(big.Int).ModInverse(s, n),
		),
		n,
	)

	// This is why RSA really needs a padding scheme ;)
	assert.Equal(t, message, p.Bytes())
}
