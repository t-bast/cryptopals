package encoding_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/t-bast/cryptopals/encoding"
)

func TestFormEncoding(t *testing.T) {
	t.Run("encode and decode", func(t *testing.T) {
		data := encoding.FormDecode("foo=bar&baz=qux&zap=zazzle")
		assert.Equal(t, "bar", data["foo"])
		assert.Equal(t, "qux", data["baz"])
		assert.Equal(t, "zazzle", data["zap"])

		encoded := encoding.FormEncode(data)
		assert.Equal(t, data, encoding.FormDecode(encoded))
	})

	t.Run("escapes characters", func(t *testing.T) {
		data := map[string]string{
			"foo&foo": "bar=bar",
		}

		encoded := encoding.FormEncode(data)
		assert.Equal(t, "foofoo=barbar", encoded)
	})

	t.Run("profile", func(t *testing.T) {
		data := encoding.ProfileFor("foo@bar.com")
		assert.True(t, strings.Contains(data, "email=foo@bar.com"))
		assert.True(t, strings.Contains(data, "uid=10"))
		assert.True(t, strings.Contains(data, "role=user"))
	})
}
