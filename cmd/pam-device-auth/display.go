package main

import (
	"strings"
	"unicode/utf8"
)

// sanitizeDisplay scrubs an IdP-supplied value before it is written to the SSH
// client's terminal via the PAM conversation. Every C0/C1 control byte and DEL
// becomes '?': ESC/CSI/OSC would execute on the user's terminal, and a raw
// newline would let a hostile IdP forge extra lines in the line-based
// stdout protocol the C module parses (e.g. a fake "FLUSH:" prompt).
func sanitizeDisplay(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		// RuneError covers invalid UTF-8 bytes (e.g. a raw 0x9b CSI), which
		// must not pass through as-is.
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) || r == utf8.RuneError {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
