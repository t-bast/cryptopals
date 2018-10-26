package mac

import "github.com/t-bast/cryptopals/hash"

// MD4Keyed creates a mac by pre-pending a secret key and taking the md4 hash
// of the result.
type MD4Keyed struct {
	key []byte
}

// NewMD4Keyed creates a mac-er with a given key.
func NewMD4Keyed(key []byte) *MD4Keyed {
	return &MD4Keyed{key: key}
}

// Authenticate creates a mac for the given message.
func (m *MD4Keyed) Authenticate(message []byte) []byte {
	return hash.MD4Sum(append(m.key, message...))
}
