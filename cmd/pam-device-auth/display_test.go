package main

import "testing"

// IdP-supplied strings (verification URI, user code) are written to the SSH
// client's terminal via the PAM conversation. A compromised IdP must not be
// able to inject terminal escape sequences (ANSI CSI, OSC-52 clipboard,
// C0/C1 controls) through that channel.
func TestSanitizeDisplay_StripsControlBytes(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain URL untouched", "https://sso.example.com/device?user_code=ABCD-EFGH", "https://sso.example.com/device?user_code=ABCD-EFGH"},
		{"ESC stripped", "https://x\x1b]52;c;evil\x07.com", "https://x?]52;c;evil?.com"},
		{"CSI C1 raw byte stripped", "AB\x9b31mCD", "AB?31mCD"},
		{"CSI C1 UTF-8 rune stripped", "AB31mCD", "AB?31mCD"},
		{"newline stripped", "code\nFLUSH:fake prompt", "code?FLUSH:fake prompt"},
		{"carriage return stripped", "real\rfake", "real?fake"},
		{"DEL stripped", "ab\x7fcd", "ab?cd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeDisplay(tt.in); got != tt.want {
				t.Errorf("sanitizeDisplay(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
