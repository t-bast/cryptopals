package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/t-bast/cryptopals/cipher/block"
	"github.com/t-bast/cryptopals/dhm"
	"github.com/t-bast/cryptopals/password"
	"github.com/t-bast/cryptopals/pkc"
)

func TestSet5_Challenge1(t *testing.T) {
	g := big.NewInt(2)
	p, ok := new(big.Int).SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff", 16)
	require.True(t, ok)

	params := dhm.New(g, p)
	aliceSecret, alicePublic := params.GenerateKeys()
	bobSecret, bobPublic := params.GenerateKeys()

	aliceKey := params.SharedSecret(aliceSecret, bobPublic)
	bobKey := params.SharedSecret(bobSecret, alicePublic)

	assert.Equal(t, aliceKey, bobKey)
}

func TestSet5_Challenge2(t *testing.T) {
	/* Public parameters. */

	g := big.NewInt(2)
	p := big.NewInt(37)
	params := dhm.New(g, p)

	/* Secret parameters from participants. */

	aliceSecret, _ := params.GenerateKeys()
	bobSecret, _ := params.GenerateKeys()

	/* Implement a MITM attack on a communication protocol. */

	// A -> M: p, g, A
	// Nothing to do.

	// M -> B: p, g, p
	bobAlicePublic := p

	// B -> M: B
	// Nothing to do.

	// M -> A: p
	aliceBobPublic := p

	// A -> M: AES-CBC(SHA1(s)[0:16], IV=random(16), message) + IV
	aliceSharedKey := sha1.Sum(params.SharedSecret(aliceSecret, aliceBobPublic))
	aliceIV := make([]byte, 16)
	rand.Read(aliceIV)

	aliceCBC := block.NewCBC(aliceSharedKey[0:16], aliceIV)
	aliceEncrypted := aliceCBC.Encrypt([]byte("Ma jeunesse ne fut qu'un ténébreux orage"))

	// M -> B: simply relay while reading decrypted plaintext.
	mallorySharedKey := sha1.Sum(big.NewInt(0).Bytes())
	malloryCBC := block.NewCBC(mallorySharedKey[0:16], aliceIV)
	intercepted := malloryCBC.Decrypt(aliceEncrypted)
	assert.Equal(t, []byte("Ma jeunesse ne fut qu'un ténébreux orage"), intercepted)

	// B -> M: AES-CBC(SHA1(s)[0:16], IV=random(16), alice's message) + IV
	bobSharedKey := sha1.Sum(params.SharedSecret(bobSecret, bobAlicePublic))
	bobIV := make([]byte, 16)
	rand.Read(bobIV)

	// Bob is able to read Alice's message so doesn't suspect anything.
	bobDecrypted := block.NewCBC(bobSharedKey[0:16], aliceIV).Decrypt(aliceEncrypted)
	assert.Equal(t, []byte("Ma jeunesse ne fut qu'un ténébreux orage"), bobDecrypted)

	bobCBC := block.NewCBC(bobSharedKey[0:16], bobIV)
	bobEncrypted := bobCBC.Encrypt([]byte("Traversé çà et là par de brillants soleils;"))

	// M -> A: simply relay while reading decrypted plaintext.
	malloryCBC = block.NewCBC(mallorySharedKey[0:16], bobIV)
	intercepted = malloryCBC.Decrypt(bobEncrypted)
	assert.Equal(t, []byte("Traversé çà et là par de brillants soleils;"), intercepted)

	// Alice is able to read Bob's message so doesn't suspect anything.
	aliceDecrypted := block.NewCBC(aliceSharedKey[0:16], bobIV).Decrypt(bobEncrypted)
	assert.Equal(t, []byte("Traversé çà et là par de brillants soleils;"), aliceDecrypted)
}

func TestSet5_Challenge3(t *testing.T) {
	/* Expected public parameters. */

	p := big.NewInt(37)

	testCases := []struct {
		modifiedG      *big.Int
		decryptMallory func(t *testing.T, encrypted []byte, iv []byte) []byte
	}{{
		modifiedG: big.NewInt(1),
		decryptMallory: func(t *testing.T, encrypted []byte, iv []byte) []byte {
			// Bob's public key will always be 1, so Alice's shared secret
			// always ends up being 1 too.
			sharedKey := sha1.Sum(big.NewInt(1).Bytes())
			cbc := block.NewCBC(sharedKey[0:16], iv)
			return cbc.Decrypt(encrypted)
		},
	}, {
		modifiedG: p,
		decryptMallory: func(t *testing.T, encrypted []byte, iv []byte) []byte {
			// Bob's public key will always be 0, so Alice's shared secret
			// always ends up being 0 too.
			sharedKey := sha1.Sum(big.NewInt(0).Bytes())
			cbc := block.NewCBC(sharedKey[0:16], iv)
			return cbc.Decrypt(encrypted)
		},
	}, {
		modifiedG: new(big.Int).Sub(p, big.NewInt(1)),
		decryptMallory: func(t *testing.T, encrypted []byte, iv []byte) (res []byte) {
			// Bob's public key will be (-1)^sk(alice).
			// Alice's shared key will be (-1)^(sk(alice)*sk(alice)).
			// If Alice's private key is 1, this will be (p-1).
			// Otherwise (in most cases) it will be 1.
			sharedKey := sha1.Sum(big.NewInt(1).Bytes())
			cbc := block.NewCBC(sharedKey[0:16], iv)

			defer func() {
				if r := recover(); r != nil {
					// If we're here that means alice's private key is 1.
					// And thus its shared key will be (p-1).
					sharedKey := sha1.Sum(new(big.Int).Sub(p, big.NewInt(1)).Bytes())
					cbc := block.NewCBC(sharedKey[0:16], iv)
					res = cbc.Decrypt(encrypted)
				}
			}()

			res = cbc.Decrypt(encrypted)
			return
		},
	}}

	for _, tt := range testCases {
		t.Run(tt.modifiedG.String(), func(t *testing.T) {
			// A -> M: p, g
			aliceParams := dhm.New(tt.modifiedG, p)
			aliceSecret, alicePublic := aliceParams.GenerateKeys()

			// M -> B: p, modified g
			bobParams := dhm.New(tt.modifiedG, p)
			bobSecret, bobPublic := bobParams.GenerateKeys()

			// B -> A: ACK
			// Nothing to do.

			// A -> B: A
			bobSharedSecret := sha1.Sum(bobParams.SharedSecret(bobSecret, alicePublic))

			// B -> A: B
			aliceSharedSecret := sha1.Sum(aliceParams.SharedSecret(aliceSecret, bobPublic))

			// A -> B: AES-CBC(SHA1(s)[0:16], iv=random(16), message) + iv
			aliceIV := make([]byte, 16)
			rand.Read(aliceIV)
			aliceCBC := block.NewCBC(aliceSharedSecret[0:16], aliceIV)
			aliceEncrypted := aliceCBC.Encrypt([]byte("Une fleur qui ressemble à mon rouge idéal."))

			// Mallory can intercept and decrypt.
			malloryDecrypted := tt.decryptMallory(t, aliceEncrypted, aliceIV)
			assert.Equal(t, []byte("Une fleur qui ressemble à mon rouge idéal."), malloryDecrypted)

			// B -> A: AES-CBC(SHA1(s)[0:16], iv=random(16), message) + iv
			bobIV := make([]byte, 16)
			rand.Read(bobIV)
			bobCBC := block.NewCBC(bobSharedSecret[0:16], bobIV)
			bobEncrypted := bobCBC.Encrypt([]byte("Car je ne puis trouver parmi ces pâles roses"))

			malloryDecrypted = tt.decryptMallory(t, bobEncrypted, bobIV)
			assert.Equal(t, []byte("Car je ne puis trouver parmi ces pâles roses"), malloryDecrypted)
		})
	}
}

func TestSet5_Challenge4(t *testing.T) {
	n := big.NewInt(37)
	g := big.NewInt(2)
	k := big.NewInt(3)

	c := password.NewSRPClient(n, g, k, "alice@iacr.org", "bob is my lover")
	s := password.NewSRPServer(n, g, k, "alice@iacr.org", "bob is my lover")

	cPub := c.CreateKey()
	salt, sPub := s.CreateKey()

	secretMac := c.ComputeSecret(salt, sPub)
	err := s.ValidateSecretMac(cPub, secretMac)
	assert.NoError(t, err)
}

func TestSet5_Challenge5(t *testing.T) {
	n := big.NewInt(37)
	g := big.NewInt(2)
	k := big.NewInt(3)

	s := password.NewSRPServer(n, g, k, "alice@iacr.org", "bob is my lover")
	salt, _ := s.CreateKey()

	// The client has an invalid password, but will be able to login.
	// Any time the client sends a public key that equals 0 mod(N)
	// this ends up with S = 0 server-side.
	// So sending HMAC-SHA256(0, salt) will always be accepted.
	backdoorHash := sha256.Sum256(big.NewInt(0).Bytes())
	backdoor := hmac.New(sha256.New, salt.Bytes()).Sum(backdoorHash[:])

	err := s.ValidateSecretMac(big.NewInt(0), backdoor)
	assert.NoError(t, err)

	err = s.ValidateSecretMac(n, backdoor)
	assert.NoError(t, err)
}

func TestSet5_Challenge6(t *testing.T) {
	n := big.NewInt(37)
	g := big.NewInt(2)
	k := big.NewInt(3)

	c := password.NewSRPClient2(n, g, k, "alice@iacr.org", "bob is my lover")
	s := password.NewSRPServer2(n, g, k, "alice@iacr.org", "bob is my lover")

	cPub := c.CreateKey()
	salt, sPub, u := s.CreateKey()

	secretMac := c.ComputeSecret(salt, sPub, u)
	err := s.ValidateSecretMac(cPub, secretMac)
	assert.NoError(t, err)

	// MITM attack can recover the password from the mac by manipulating b, B,
	// u and the salt.
	// We send salt=0, b=1 (B=g) and u=1.
	// This way, client-side S becomes g**(a+x).
	// We can then use an offline dictionary to try passwords, compute x,
	// compute the client-side value of S until it matches.
	maliciousSalt := big.NewInt(0)
	maliciousPub := g
	maliciousU := big.NewInt(1)

	pwnedMac := c.ComputeSecret(maliciousSalt, maliciousPub, maliciousU)
	pwnedPassword := ""
	passwordDB := []string{"I hate Bob", "I'm sleeping with Dave", "bob is my lover", "who is that bob anyway?"}
	for _, pwd := range passwordDB {
		xh := sha256.Sum256(append(maliciousSalt.Bytes(), []byte(pwd)...))
		x := new(big.Int).SetBytes(xh[:])
		s := new(big.Int).Mod(
			new(big.Int).Mul(
				cPub,
				new(big.Int).Exp(g, x, n),
			),
			n,
		)
		k := sha256.Sum256(s.Bytes())
		macAttempt := hmac.New(sha256.New, maliciousSalt.Bytes()).Sum(k[:])
		if bytes.Equal(pwnedMac, macAttempt) {
			pwnedPassword = pwd
			break
		}
	}

	assert.Equal(t, "bob is my lover", pwnedPassword)
}

func TestSet5_Challenge7(t *testing.T) {
	r := pkc.NewRSA()
	message := []byte("une charogne infâme")
	encrypted := r.Encrypt(message)
	decrypted := r.Decrypt(encrypted)

	assert.Equal(t, message, decrypted)
}

func TestSet5_Challenge8(t *testing.T) {
	r1 := pkc.NewRSA()
	_, n1 := r1.PublicKey()
	r2 := pkc.NewRSA()
	_, n2 := r2.PublicKey()
	r3 := pkc.NewRSA()
	_, n3 := r3.PublicKey()

	message := []byte("Moisir parmi les ossements.")
	c1 := r1.Encrypt(message)
	assert.Equal(t, message, r1.Decrypt(c1))
	c2 := r2.Encrypt(message)
	assert.Equal(t, message, r2.Decrypt(c2))
	c3 := r3.Encrypt(message)
	assert.Equal(t, message, r3.Decrypt(c3))

	ms1 := new(big.Int).Mul(n2, n3)
	ms2 := new(big.Int).Mul(n1, n3)
	ms3 := new(big.Int).Mul(n1, n2)

	result := new(big.Int).Add(
		new(big.Int).Mul(
			new(big.Int).Mul(new(big.Int).SetBytes(c1), ms1),
			new(big.Int).ModInverse(ms1, n1),
		),
		new(big.Int).Add(
			new(big.Int).Mul(
				new(big.Int).Mul(new(big.Int).SetBytes(c2), ms2),
				new(big.Int).ModInverse(ms2, n2),
			),
			new(big.Int).Mul(
				new(big.Int).Mul(new(big.Int).SetBytes(c3), ms3),
				new(big.Int).ModInverse(ms3, n3),
			),
		),
	)

	modResult := new(big.Int).Mod(
		result,
		new(big.Int).Mul(n1, new(big.Int).Mul(n2, n3)),
	)

	decrypted, _ := cubeRoot(modResult)

	assert.Equal(t, message, decrypted.Bytes())
}

func cubeRoot(i *big.Int) (cbrt *big.Int, rem *big.Int) {
	var (
		n0    = big.NewInt(0)
		n1    = big.NewInt(1)
		n2    = big.NewInt(2)
		n3    = big.NewInt(3)
		guess = new(big.Int).Div(i, n2)
		dx    = new(big.Int)
		absDx = new(big.Int)
		minDx = new(big.Int).Abs(i)
		step  = new(big.Int).Abs(new(big.Int).Div(guess, n2))
		cube  = new(big.Int)
	)
	for {
		cube.Exp(guess, n3, nil)
		dx.Sub(i, cube)
		cmp := dx.Cmp(n0)
		if cmp == 0 {
			return guess, n0
		}

		absDx.Abs(dx)
		switch absDx.Cmp(minDx) {
		case -1:
			minDx.Set(absDx)
		case 0:
			return guess, dx
		}

		switch cmp {
		case -1:
			guess.Sub(guess, step)
		case +1:
			guess.Add(guess, step)
		}

		step.Div(step, n2)
		if step.Cmp(n0) == 0 {
			step.Set(n1)
		}
	}
}
