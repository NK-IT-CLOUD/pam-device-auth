package sshclient

import (
	"strings"
	"testing"
)

func TestSSHDMajor(t *testing.T) {
	tests := []struct {
		version string
		want    int
	}{
		{"OpenSSH_10.0p2 Debian-7+deb13u1, OpenSSL 3.5.5", 10},
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.15, OpenSSL 3.0.13", 9},
		{"OpenSSH_10.2", 10},
		{"OpenSSH_8.9p1", 8},
		{"OpenSSH_11.0p1", 11},
		{"not openssh at all", 0},
		{"", 0},
	}
	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := sshdMajor(tt.version); got != tt.want {
				t.Errorf("sshdMajor(%q) = %d, want %d", tt.version, got, tt.want)
			}
		})
	}
}

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

func TestHasUTF8SafeVis(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"OpenSSH_9.6p1 Ubuntu-3ubuntu13.15", true},
		{"OpenSSH_9.7p1 Debian-5", true},
		{"OpenSSH_9.4p1 Fedora-9.4p1-1.fc39", true},
		{"PuTTY_Release_0.80", true},
		{"OpenSSH_for_Windows_9.5", false},
		{"OpenSSH_10.2", false},
		{"OpenSSH_9.0", false},
		{"unknown", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := hasUTF8SafeVis(tt.version); got != tt.want {
				t.Errorf("hasUTF8SafeVis(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestShouldShowQR_ConfigOverride(t *testing.T) {
	trueVal := true
	falseVal := false

	if !ShouldShowQR(&trueVal) {
		t.Error("ShouldShowQR(true) should return true")
	}
	if ShouldShowQR(&falseVal) {
		t.Error("ShouldShowQR(false) should return false")
	}
}
