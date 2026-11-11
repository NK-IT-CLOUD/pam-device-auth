package main

import (
	"reflect"
	"slices"
	"testing"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/logger"
)

func TestLoginNameError(t *testing.T) {
	for _, name := range []string{"", "-H", "--address=unixexec:path=/tmp/x", "-"} {
		if err := loginNameError(name); err == nil {
			t.Errorf("loginNameError(%q) = nil, want an error", name)
		}
	}
	for _, name := range []string{"alice", "john.doe", "a-b", "svc_backup", "10002"} {
		if err := loginNameError(name); err != nil {
			t.Errorf("loginNameError(%q) = %v, want nil", name, err)
		}
	}
}

func TestPasswdEntryName(t *testing.T) {
	for out, want := range map[string]string{
		"carol:*:10002:6000::/home/carol:/bin/bash\n":    "carol",
		"alice:x:1:1::/:/bin/sh\nbob:x:2:2::/:/bin/sh\n": "alice",
		"":           "",
		"\n":         "",
		"no-colon\n": "",
		":x:1:1::/:": "",
	} {
		if got := passwdEntryName([]byte(out)); got != want {
			t.Errorf("passwdEntryName(%q) = %q, want %q", out, got, want)
		}
	}
}

// getent looks an all-digit key up as a UID and SSSD may match a name without
// regard to case: only an entry that carries the requested name counts.
func TestNSSAnswerMatches(t *testing.T) {
	entry := []byte("carol:*:10002:6000::/home/carol:/bin/bash\n")
	for name, want := range map[string]bool{"carol": true, "10002": false, "Carol": false, "car": false} {
		if got := nssAnswerMatches(entry, name); got != want {
			t.Errorf("nssAnswerMatches(entry of carol, %q) = %v, want %v", name, got, want)
		}
	}
	if nssAnswerMatches(nil, "alice") {
		t.Error("an empty answer must not match")
	}
}

func TestNSSLookup_NumericNameIsNotTheUser(t *testing.T) {
	// What `getent -s sss passwd -- 10002` prints when uid 10002 is carol.
	stubGetent(t, "carol:*:10002:6000::/home/carol:/bin/bash\n", 0)
	found, err := nssLookup("10002")
	if err != nil || found {
		t.Fatalf("nssLookup(\"10002\") = %v, %v; want not found: the entry belongs to another name", found, err)
	}
}

func TestDirectoryUserIDs_NameMustMatch(t *testing.T) {
	stubGetent(t, "carol:*:10002:6000::/home/carol:/bin/bash\n", 0)
	if _, _, err := directoryUserIDs("10002"); err == nil {
		t.Fatal("directoryUserIDs(\"10002\") accepted the entry of another name")
	}
	uid, gid, err := directoryUserIDs("carol")
	if err != nil || uid != 10002 || gid != 6000 {
		t.Fatalf("directoryUserIDs(\"carol\") = %d, %d, %v; want 10002, 6000", uid, gid, err)
	}
}

func TestSSSPasswdLookup_NameMustMatch(t *testing.T) {
	stubGetent(t, "carol:*:10002:6000::/home/carol:/bin/bash\n", 0)
	if _, _, ok := sssPasswdLookup("10002"); ok {
		t.Fatal("sssPasswdLookup(\"10002\") accepted the entry of another name")
	}
	if uid, gid, ok := sssPasswdLookup("carol"); !ok || uid != 10002 || gid != 6000 {
		t.Fatalf("sssPasswdLookup(\"carol\") = %d, %d, %v; want 10002, 6000, true", uid, gid, ok)
	}
}

// busctl parses options anywhere on its command line: "--" before the verb
// makes every later argument data.
func TestBusctlClientsArgs(t *testing.T) {
	args := busctlClientsArgs("alice")
	call := slices.Index(args, "call")
	if call < 1 || args[call-1] != "--" {
		t.Fatalf("\"--\" must come directly before \"call\": %v", args)
	}
	sas := slices.Index(args, "sas")
	if sas < 0 || sas+1 >= len(args) || args[sas+1] != "alice" {
		t.Fatalf("the user must follow the signature \"sas\": %v", args)
	}
	if want := []string{"alice", "1", "clients"}; !reflect.DeepEqual(args[len(args)-3:], want) {
		t.Fatalf("args end with %v, want %v", args[len(args)-3:], want)
	}
}

func TestSplitMembers(t *testing.T) {
	members, skipped := splitMembers("alice,-H,bob,--address=x")
	if want := []string{"alice", "bob"}; !reflect.DeepEqual(members, want) {
		t.Errorf("members = %v, want %v", members, want)
	}
	if want := []string{"-H", "--address=x"}; !reflect.DeepEqual(skipped, want) {
		t.Errorf("skipped = %v, want %v", skipped, want)
	}
	if members, skipped := splitMembers(""); members != nil || skipped != nil {
		t.Errorf("splitMembers(\"\") = %v, %v; want nil, nil", members, skipped)
	}
}

func TestPamAccount_RefusesDashName(t *testing.T) {
	log, err := logger.NewLogger("", false)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	read := func(string) ([]string, error) { called = true; return nil, nil }
	if code := pamAccount(log, "--address=unixexec:path=/tmp/x", "192.0.2.10", read); code != 1 {
		t.Errorf("pamAccount() = %d, want 1 (deny)", code)
	}
	if called {
		t.Error("the allowlist reader ran for a name that looks like an option")
	}
}
