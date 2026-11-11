package main

import (
	"errors"
	"os/user"
	"testing"
)

// The log belongs to root:adm where the group exists (Debian, Ubuntu, Rocky,
// Fedora); a host without it keeps root's group. Any other lookup failure is
// an error, never a silent "no group".
func TestLogGroupID(t *testing.T) {
	orig := lookupGroup
	t.Cleanup(func() { lookupGroup = orig })

	lookupGroup = func(name string) (*user.Group, error) {
		if name != "adm" {
			t.Errorf("looked up group %q, want adm", name)
		}
		return &user.Group{Gid: "4", Name: "adm"}, nil
	}
	if gid, err := logGroupID(); err != nil || gid != 4 {
		t.Errorf("logGroupID() = %d, %v; want 4", gid, err)
	}

	lookupGroup = func(name string) (*user.Group, error) { return nil, user.UnknownGroupError(name) }
	if gid, err := logGroupID(); err != nil || gid != -1 {
		t.Errorf("logGroupID() without the group = %d, %v; want -1 and no error", gid, err)
	}

	lookupGroup = func(string) (*user.Group, error) { return nil, errors.New("open /etc/group: permission denied") }
	if _, err := logGroupID(); err == nil {
		t.Error("logGroupID() must fail when the group database cannot be read")
	}

	lookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: "four"}, nil }
	if _, err := logGroupID(); err == nil {
		t.Error("logGroupID() must fail on a gid that is no number")
	}
}
