package profile_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/profile"
)

func TestUserProfile(t *testing.T) {
	t.Run("string and unstring", func(t *testing.T) {
		p := profile.NewUserProfile("foo@bar.com")
		ps := p.String()
		assert.Equal(t, "email=foo@bar.com&uid=10&role=user", ps)

		pp := profile.Unstring(ps)
		assert.Equal(t, p.Email, pp.Email)
		assert.Equal(t, p.UID, pp.UID)
		assert.Equal(t, p.Role, pp.Role)
	})

	t.Run("escapes characters", func(t *testing.T) {
		p := profile.NewUserProfile("foo@bar.com&role=admin")
		assert.Equal(t, "foo@bar.comroleadmin", p.Email)
		assert.Equal(t, "email=foo@bar.comroleadmin&uid=10&role=user", p.String())
	})
}
