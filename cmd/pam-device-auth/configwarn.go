package main

import (
	"fmt"
	"io"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// configWarningLines returns the findings of config.Load (unknown keys,
// unsupported allowed_algorithms entries) as message lines. A login logs them
// and goes on; --check, --enable and --setup-ldap treat each as a blocker.
func configWarningLines(cfg *config.Config) []string {
	var lines []string
	for _, w := range cfg.Warnings() {
		lines = append(lines, "config: "+w)
	}
	return lines
}

// reportConfigWarnings prints the findings as preflight blockers and returns
// their number.
func reportConfigWarnings(cfg *config.Config, out io.Writer) int {
	lines := configWarningLines(cfg)
	for _, line := range lines {
		fmt.Fprintf(out, "  [FAIL] %s\n", line)
	}
	return len(lines)
}
