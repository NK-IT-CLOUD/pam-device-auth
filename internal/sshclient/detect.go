// Package sshclient decides whether to show Unicode QR codes based on the
// SSH client's strnvis() behavior.
//
// OpenSSH 10+ fixed openbsd-compat/vis.c to preserve UTF-8 — QR works for
// all clients. On OpenSSH 9.x, only clients connecting through a server
// with libbsd (Ubuntu, Debian, Fedora) or no vis at all (PuTTY) render
// QR correctly. Win32-OpenSSH and Termux escape UTF-8 bytes.
//
// Detection: the Go binary's parent process (PPID) is the sshd session
// that handled this connection. Its journalctl logs contain the client
// version string logged at connection time.
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

// ShouldShowQR determines whether to render the Unicode QR code.
//
//	Config "show_qr": true  → always show
//	Config "show_qr": false → never show
//	Config omitted          → auto: OpenSSH 10+ always, 9.x per client allowlist
func ShouldShowQR(showQRConfig *bool) bool {
	if showQRConfig != nil {
		return *showQRConfig
	}

	// OpenSSH 10+ fixed vis() — QR works for all clients
	if sshdMajor(getSSHDVersion()) >= 10 {
		return true
	}

	// OpenSSH 9.x — check client version via parent PID's journal
	version := detectClient()
	return hasUTF8SafeVis(version)
}

// detectClient returns the SSH client version string by walking the process
// tree upward from PPID, querying journalctl at each level until the client
// version is found.
//
// OpenSSH 9.x process tree during PAM auth:
//
//	sshd[preauth] (PID A, logs client version)  ← grandparent
//	  └── sshd[session] (PID B, runs PAM)       ← parent
//	        └── pam-device-auth (PID C)          ← us
//
// The client version is logged during preauth (PID A), but PAM runs in
// the post-auth child (PID B). We need to walk up to find it.
func detectClient() string {
	pid := os.Getppid()

	for i := 0; i < 4 && pid > 1; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		out, err := exec.CommandContext(ctx, "/usr/bin/journalctl",
			fmt.Sprintf("_PID=%d", pid), "-o", "cat", "--no-pager").Output()
		cancel()

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

// getSSHDVersion returns the local sshd version string.
func getSSHDVersion() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "/usr/sbin/sshd", "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

// sshdMajor extracts the major version number from an sshd version string.
func sshdMajor(version string) int {
	idx := strings.Index(version, "OpenSSH_")
	if idx < 0 {
		return 0
	}
	rest := version[idx+len("OpenSSH_"):]
	dot := strings.IndexAny(rest, ".p")
	if dot < 0 {
		dot = len(rest)
	}
	major, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0
	}
	return major
}

// utf8SafePatterns lists SSH client version substrings that indicate
// a UTF-8-safe vis() implementation or no vis() at all.
var utf8SafePatterns = []string{
	"Ubuntu",  // libbsd-linked sshd
	"Debian",  // libbsd-linked sshd
	"Fedora",  // libbsd-linked sshd
	"Red Hat", // RHEL
	"RHEL",    // RHEL alternate
	"PuTTY",   // no vis() — passes UTF-8 through
}

// hasUTF8SafeVis returns true if the SSH client version indicates
// UTF-8 will survive the server's strnvis() call.
func hasUTF8SafeVis(version string) bool {
	if version == "" || version == "unknown" {
		return false
	}
	lower := strings.ToLower(version)
	for _, pattern := range utf8SafePatterns {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
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
	return strings.TrimSpace(rest[:end])
}
