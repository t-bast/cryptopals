package encoding

import (
	"fmt"
	"strings"
)

// FormEncode encodes data as form key-value pairs.
func FormEncode(data map[string]string) string {
	res := ""
	for k, v := range data {
		saneK := strings.Replace(strings.Replace(k, "&", "", -1), "=", "", -1)
		saneV := strings.Replace(strings.Replace(v, "&", "", -1), "=", "", -1)

		res += fmt.Sprintf("%s=%s&", saneK, saneV)
	}

	return res[:len(res)-1]
}

// FormDecode decodes form key-value data.
func FormDecode(data string) map[string]string {
	res := make(map[string]string)
	parts := strings.Split(data, "&")
	for _, part := range parts {
		kv := strings.Split(part, "=")
		res[kv[0]] = kv[1]
	}

	return res
}

// ProfileFor form-encodes a user profile.
func ProfileFor(email string) string {
	data := map[string]string{
		"email": email,
		"uid":   "10",
		"role":  "user",
	}

	return FormEncode(data)
}
