package profile

import (
	"fmt"
	"strconv"
	"strings"
)

// UserProfile fakes a user profile with access rights.
type UserProfile struct {
	Email string
	UID   int
	Role  string
}

// NewUserProfile creates a new user profile with default role.
func NewUserProfile(email string) *UserProfile {
	sanitized := strings.Replace(strings.Replace(email, "&", "", -1), "=", "", -1)
	return &UserProfile{
		Email: sanitized,
		UID:   10,
		Role:  "user",
	}
}

// String version of the user profile.
func (p *UserProfile) String() string {
	return fmt.Sprintf("email=%s&uid=%d&role=%s", p.Email, p.UID, p.Role)
}

// Unstring decodes a stringified user profile.
func Unstring(userProfile string) *UserProfile {
	p := &UserProfile{}
	parts := strings.Split(userProfile, "&")
	for _, part := range parts {
		kv := strings.Split(part, "=")
		switch kv[0] {
		case "email":
			p.Email = kv[1]
		case "uid":
			uid, _ := strconv.ParseInt(kv[1], 10, 32)
			p.UID = int(uid)
		case "role":
			p.Role = kv[1]
		}
	}

	return p
}
