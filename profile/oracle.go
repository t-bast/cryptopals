package profile

import (
	"math/rand"
	"time"

	"github.com/t-bast/cryptopals/cipher/block"
)

// UserProfileOracle encrypts user profiles.
type UserProfileOracle struct {
	key []byte
}

// NewUserProfileOracle creates a fixed key for encryption.
func NewUserProfileOracle() *UserProfileOracle {
	rand.Seed(time.Now().UnixNano())
	key := make([]byte, 16)
	rand.Read(key)

	return &UserProfileOracle{
		key: key,
	}
}

// Encrypt a user profile.
func (o *UserProfileOracle) Encrypt(p *UserProfile) []byte {
	ecb := block.NewECB(o.key)
	return ecb.Encrypt([]byte(p.String()))
}

// Decrypt a user profile.
func (o *UserProfileOracle) Decrypt(encrypted []byte) *UserProfile {
	ecb := block.NewECB(o.key)
	decrypted := ecb.Decrypt(encrypted)
	return Unstring(string(decrypted))
}

// CreateAdminProfile creates an admin profile by exploiting flaws in ECB.
func CreateAdminProfile(o *UserProfileOracle) *UserProfile {
	// Find the encrypted block for "admin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B".
	e1 := o.Encrypt(NewUserProfile("AAAAAAAAAAadmin\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B\x0B"))

	// Replace it in a valid ciphertext where the "user" part is isolated at the end.
	e2 := o.Encrypt(NewUserProfile("pwned@bar.com"))
	e := make([]byte, len(e2))
	copy(e, e2)
	copy(e[32:], e1[16:32])

	return o.Decrypt(e)
}
