package main

import (
	"errors"
	"testing"
)

var errRead = errors.New("read failed")

func TestDecideIPGate(t *testing.T) {
	cases := []struct {
		name    string
		dir     bool
		clients []string
		readErr error
		rhost   string
		allow   bool
	}{
		{"local user exempt", false, nil, nil, "1.2.3.4", true},
		{"dir no clients -> allow", true, nil, nil, "1.2.3.4", true},
		{"dir clients match -> allow", true, []string{"10.0.0.0/8"}, nil, "10.0.0.5", true},
		{"dir clients no match -> deny", true, []string{"10.0.0.0/8"}, nil, "192.168.1.1", false},
		{"dir clients read error -> fail-closed deny", true, nil, errRead, "10.0.0.5", false},
		{"dir clients empty rhost -> fail-closed deny", true, []string{"10.0.0.0/8"}, nil, "", false},
		{"local user exempt even with read error", false, nil, errRead, "1.2.3.4", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := decideIPGate(c.dir, c.clients, c.readErr, c.rhost); got != c.allow {
				t.Fatalf("decideIPGate = %v, want %v", got, c.allow)
			}
		})
	}
}

func TestIsLocalUser(t *testing.T) {
	passwd := []byte("root:x:0:0:root:/root:/bin/bash\n" +
		"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"\n" +
		"# a comment line, should be skipped\n" +
		"malformed-line-no-colon\n" +
		":x:1000:1000::/home:/bin/bash\n" +
		"sshd:x:64:64::/run/sshd:/usr/sbin/nologin\r\n")

	cases := []struct {
		name string
		user string
		want bool
	}{
		{"root present -> local", "root", true},
		{"other local system account present -> local", "daemon", true},
		{"CRLF-terminated line still matches", "sshd", true},
		{"directory-only user absent -> not local", "nk", false},
		{"empty user never matches", "", false},
		{"malformed line without colon does not panic or match", "malformed-line-no-colon", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isLocalUser(passwd, c.user); got != c.want {
				t.Fatalf("isLocalUser(%q) = %v, want %v", c.user, got, c.want)
			}
		})
	}

	if isLocalUser([]byte{}, "root") {
		t.Fatal("isLocalUser on empty passwd content must not match anyone")
	}
}

func TestIsDirectoryUser(t *testing.T) {
	// root is exempted before any file access, so this must never error even
	// on a system where /etc/passwd is unreadable in the test sandbox.
	isDir, err := isDirectoryUser("root")
	if err != nil {
		t.Fatalf("isDirectoryUser(root) error = %v, want nil", err)
	}
	if isDir {
		t.Fatal("isDirectoryUser(root) = true, want false (root is always exempt/local)")
	}
}

func TestParseBusctlClients(t *testing.T) {
	// busctl --json=short GetUserAttr output shape (a{sv} clients -> string array)
	js := []byte(`{"type":"a{sv}","data":[{"clients":{"type":"as","data":["10.0.0.1","10.1.0.0/16"]}}]}`)
	got, err := parseBusctlClients(js)
	if err != nil || len(got) != 2 || got[0] != "10.0.0.1" || got[1] != "10.1.0.0/16" {
		t.Fatalf("parseBusctlClients = %v, %v", got, err)
	}

	// no clients attr -> empty, no error (live-verified shape for a directory
	// user with no "clients" attribute set)
	if g, err := parseBusctlClients([]byte(`{"type":"a{sv}","data":[{}]}`)); err != nil || len(g) != 0 {
		t.Fatalf("empty attrs = %v, %v", g, err)
	}

	// live-verified full multi-entry shape
	full := []byte(`{"type":"a{sv}","data":[{"clients":{"type":"as","data":["10.0.99.203","10.0.99.204","10.1.1.2","10.0.20.2","10.1.66.0/24"]}}]}`)
	if g, err := parseBusctlClients(full); err != nil || len(g) != 5 || g[4] != "10.1.66.0/24" {
		t.Fatalf("full clients = %v, %v", g, err)
	}

	// malformed JSON -> error
	if _, err := parseBusctlClients([]byte(`not json`)); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
