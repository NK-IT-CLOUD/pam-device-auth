package user

import (
	"testing"
)

func TestIsValidUsername(t *testing.T) {
	valid := []string{"admin", "testuser", "a", "user-name", "user_name", "_hidden"}
	invalid := []string{"", "Root", "123start", "has space", "way-too-long-username-that-exceeds-the-maximum", "special!char", "-start"}

	for _, u := range valid {
		if !validUsername.MatchString(u) {
			t.Errorf("%q should be valid", u)
		}
	}
	for _, u := range invalid {
		if validUsername.MatchString(u) {
			t.Errorf("%q should be invalid", u)
		}
	}
}
