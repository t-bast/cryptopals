package mac_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/mac"
)

func TestSha1Hmac(t *testing.T) {
	m := mac.NewSha1Hmac([]byte("YELLOW SUBMARINE"))
	message := []byte("Car je ne puis trouver parmi ces pales roses")
	hmac := m.Authenticate(message)
	assert.True(t, m.Verify(message, hmac))
}
