package mac

import "github.com/t-bast/cryptopals/hash"

// Sha1Keyed creates a mac by appending a secret key and taking the sha1 hash
// of the result.
type Sha1Keyed struct {
	key []byte
}

// NewSha1Keyed creates a mac-er with a given key.
func NewSha1Keyed(key []byte) *Sha1Keyed {
	return &Sha1Keyed{key: key}
}

// Authenticate creates a mac for the given message.
func (m *Sha1Keyed) Authenticate(message []byte) []byte {
	return hash.Sha1Sum(append(m.key, message...))
}
