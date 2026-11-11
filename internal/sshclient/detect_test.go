package sshclient

import (
	"strings"
	"testing"
)

func TestParseClientVersion(t *testing.T) {
	tests := []struct {
		name    string
		journal string
		want    string
	}{
		{"Ubuntu OpenSSH", "debug1: Remote software version OpenSSH_9.6p1 Ubuntu-3ubuntu13.15\nother line", "OpenSSH_9.6p1 Ubuntu-3ubuntu13.15"},
		{"Windows OpenSSH", "debug1: Remote software version OpenSSH_for_Windows_9.5\n", "OpenSSH_for_Windows_9.5"},
		{"PuTTY", "debug1: Remote software version PuTTY_Release_0.80\n", "PuTTY_Release_0.80"},
		{"bare OpenSSH (Termux)", "debug1: Remote software version OpenSSH_10.2\n", "OpenSSH_10.2"},
		{"Debian OpenSSH", "debug1: Remote software version OpenSSH_9.7p1 Debian-5\n", "OpenSSH_9.7p1 Debian-5"},
		{"LogVerbose-forced line", "debug1: kex.c:kex_exchange_identification():1680 (pid=82873): Remote protocol version 2.0, remote software version OpenSSH_for_Windows_9.5\n", "OpenSSH_for_Windows_9.5"},
		{"case insensitive", "DEBUG1: REMOTE SOFTWARE VERSION MyClient_1.0\n", "MyClient_1.0"},
		{"no match", "some other log line\nanother line\n", ""},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseClientVersion(tt.journal)
			if got != tt.want {
				t.Errorf("parseClientVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseClientVersion_LongVersionCapped(t *testing.T) {
	longVersion := strings.Repeat("A", 200)
	journal := "debug1: Remote software version " + longVersion + "\n"
	got := parseClientVersion(journal)
	if len(got) != 128 {
		t.Errorf("version length = %d, want capped at 128", len(got))
	}
}

// The QR decision depends on the client alone: distribution builds, PuTTY
// and plain OpenSSH 10+ keep UTF-8 intact; Win32-OpenSSH (any version), plain
// OpenSSH < 10 and unknown clients escape it or may, so they get no QR.
func TestClientRendersQR(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"OpenSSH_10.2p1 Ubuntu-2ubuntu3.6", true},
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13", true},
		{"OpenSSH_9.7p1 Debian-5", true},
		{"OpenSSH_9.4p1 Fedora-9.4p1-1.fc39", true},
		{"OpenSSH_8.7p1 Red Hat", true},
		{"OpenSSH_9.9p1 rhel-9", true},
		{"OpenSSH_10.0", true},
		{"OpenSSH_10.2", true},
		{"OpenSSH_11.0p1", true},
		{"OpenSSH_9.9", false},
		{"OpenSSH_9.0", false},
		{"OpenSSH_for_Windows_9.5", false},
		{"OpenSSH_for_Windows_10.0", false},
		{"PuTTY_Release_0.83", true},
		{"OpenSSH_", false},
		{"OpenSSH_x10", false},
		{"MyClient OpenSSH_10.0", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := clientRendersQR(tt.version); got != tt.want {
				t.Errorf("clientRendersQR(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

// An explicit show_qr wins and skips the client detection.
func TestQRDecision_ConfigOverride(t *testing.T) {
	for _, want := range []bool{true, false} {
		show, client, reason := QRDecision(&want)
		if show != want || client != "" || reason != "configured" {
			t.Errorf("QRDecision(%v) = (%v, %q, %q), want (%v, \"\", \"configured\")", want, show, client, reason, want)
		}
	}
}

// The version string is extracted from journalctl output that embeds the
// client banner — attacker-influenced bytes. The function's contract is
// "safe to log/display": control bytes must not survive extraction.
func TestParseClientVersion_StripsControlBytes(t *testing.T) {
	out := "Connection from x\nremote software version SSH-2.0-Evil\x1b]52;c;ZXZpbA==\x07Client\nnext line"
	got := parseClientVersion(out)
	if got == "" {
		t.Fatal("expected a version string")
	}
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control byte %q survived in %q", r, got)
		}
	}
}

// PIDs are reused: without a bound the journal also returns the lines of an
// earlier process with the same PID, from another boot.
func TestJournalArgsLimitToThisBoot(t *testing.T) {
	got := journalArgs(4711)
	want := []string{"-b", "_PID=4711", "-o", "cat", "--no-pager"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("journalArgs(4711) = %v, want %v", got, want)
	}
}

// Within one boot a PID can be reused as well; the newest line is the one of
// the connection that asks.
func TestParseClientVersion_NewestWins(t *testing.T) {
	out := "debug1: Remote protocol version 2.0, remote software version OpenSSH_for_Windows_9.5\n" +
		"Connection closed\n" +
		"debug1: Remote protocol version 2.0, remote software version OpenSSH_10.2p1 Ubuntu-2ubuntu3\n" +
		"Postponed keyboard-interactive/pam\n"
	if got := parseClientVersion(out); got != "OpenSSH_10.2p1 Ubuntu-2ubuntu3" {
		t.Errorf("parseClientVersion() = %q, want the newest client version", got)
	}
}
