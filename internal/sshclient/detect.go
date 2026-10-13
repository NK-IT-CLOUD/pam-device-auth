// Package sshclient decides per SSH client whether to show the Unicode QR
// code.
//
// Whether the block characters survive depends on the client, not on the
// server: Win32-OpenSSH and portable OpenSSH < 10 built without libbsd (for
// example Termux) escape UTF-8 bytes, so the QR arrives garbled, also on an
// OpenSSH 10 server. Distribution builds (Ubuntu, Debian, Fedora, Red Hat),
// PuTTY (no vis() at all) and OpenSSH 10+ (openbsd-compat/vis.c keeps UTF-8)
// render it.
//
// Detection: the Go binary's parent process (PPID) is the sshd session that
// handled this connection. Its journal entries contain the client version
// string logged at connection time (debug1; the managed sshd drop-in forces it
// with LogVerbose kex.c:kex_exchange_identification():*, which OpenSSH 10.2's
// sshd-session still logs).
package sshclient

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// QRDecision determines whether to render the Unicode QR code and returns the
// detected client version (scrubbed, "unknown" if none was found; empty when
// show_qr is set) and the reason for the decision:
//
//	Config "show_qr": true  → always show,  reason "configured"
//	Config "show_qr": false → never show,   reason "configured"
//	Config omitted          → per client,   reason "client" (clientRendersQR)
//
// An explicit show_qr skips the client detection.
func QRDecision(showQRConfig *bool) (show bool, client, reason string) {
	if showQRConfig != nil {
		return *showQRConfig, "", "configured"
	}
	client = detectClient()
	return clientRendersQR(client), client, "client"
}

// detectClient returns the SSH client version string by walking the process
// tree upward from PPID, querying journalctl at each level until the client
// version is found. The walk goes by PID and parent PID (journal field _PID,
// /proc/<pid>/stat), not by process name, so it covers every sshd layout,
// including sshd-session on OpenSSH 10.
//
// Example, the OpenSSH 9.x process tree during PAM auth:
//
//	sshd[preauth] (PID A, logs client version)  ← grandparent
//	  └── sshd[session] (PID B, runs PAM)       ← parent
//	        └── pam-device-auth (PID C)          ← us
//
// The client version is logged during preauth (PID A), but PAM runs in
// the post-auth child (PID B). We need to walk up to find it.
func detectClient() string {
	pid := os.Getppid()

	// One deadline for the whole walk: the up-to-4 journalctl calls must not
	// add more than 2 s in total to the login.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for i := 0; i < 4 && pid > 1; i++ {
		if ctx.Err() != nil {
			break
		}
		out, err := exec.CommandContext(ctx, "/usr/bin/journalctl",
			fmt.Sprintf("_PID=%d", pid), "-o", "cat", "--no-pager").Output()

		if err == nil {
			if version := parseClientVersion(string(out)); version != "" {
				return version
			}
		}

		// Read parent's PPID to walk up
		statContent, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			break
		}
		ppid, err := parsePPID(string(statContent))
		if err != nil || ppid <= 1 {
			break
		}
		pid = ppid
	}

	return "unknown"
}

// parsePPID extracts the PPID (field 4) from /proc/<pid>/stat content.
func parsePPID(statContent string) (int, error) {
	rp := strings.LastIndex(statContent, ")")
	if rp < 0 || rp+2 >= len(statContent) {
		return 0, fmt.Errorf("malformed /proc/stat")
	}
	fields := strings.Fields(statContent[rp+2:])
	if len(fields) < 2 {
		return 0, fmt.Errorf("malformed /proc/stat: too few fields")
	}
	return strconv.Atoi(fields[1])
}

// utf8SafePatterns lists SSH client version substrings of clients whose
// vis() keeps UTF-8 intact (libbsd-linked distribution builds) or that have no
// vis() at all (PuTTY).
var utf8SafePatterns = []string{
	"Ubuntu",
	"Debian",
	"Fedora",
	"Red Hat",
	"RHEL",
	"PuTTY",
}

// clientRendersQR reports whether the SSH client with this version string
// renders the Unicode QR: Win32-OpenSSH (any version) never does; a
// distribution build or PuTTY (case-insensitive substring) does; otherwise a
// plain "OpenSSH_<major>…" banner does from major 10 on. Every other or unknown
// client gets no QR (link and code are always shown).
func clientRendersQR(version string) bool {
	lower := strings.ToLower(version)
	if strings.Contains(lower, "openssh_for_windows") {
		return false
	}
	for _, pattern := range utf8SafePatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	rest, ok := strings.CutPrefix(version, "OpenSSH_")
	if !ok {
		return false
	}
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	major, err := strconv.Atoi(rest[:n])
	return err == nil && major >= 10
}

// parseClientVersion extracts the SSH client version from journalctl output.
func parseClientVersion(journalOutput string) string {
	needle := "remote software version "
	lower := strings.ToLower(journalOutput)
	idx := strings.Index(lower, needle)
	if idx < 0 {
		return ""
	}
	start := idx + len(needle)
	if start > len(journalOutput) {
		return ""
	}
	rest := journalOutput[start:]
	end := strings.IndexAny(rest, "\n\r")
	if end < 0 {
		end = len(rest)
	}
	if end > 128 {
		end = 128
	}
	return scrubControlBytes(strings.TrimSpace(rest[:end]))
}

// scrubControlBytes makes the extracted version string safe to log or display:
// the journalctl output embeds the SSH client's banner, i.e. attacker-
// influenced bytes that must not carry terminal control sequences.
func scrubControlBytes(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
