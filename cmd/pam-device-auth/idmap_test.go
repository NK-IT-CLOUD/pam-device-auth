package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseIDMapAndIDMapped(t *testing.T) {
	host := parseIDMap("         0          0 4294967295\n")
	lxc := parseIDMap("         0     100000      65536\n")
	nested := parseIDMap("0 100000 1000\n1000 1000 1\n1001 101001 64535\n")
	for _, c := range []struct {
		name   string
		ranges []idMapRange
		id     int64
		want   bool
	}{
		{"host maps everything", host, 2000200000, true},
		{"lxc maps below 65536", lxc, 65535, true},
		{"lxc rejects 65536", lxc, 65536, false},
		{"lxc rejects sssd default idmap", lxc, 200513, false},
		{"nested second range", nested, 1000, true},
		{"nested third range", nested, 60000, true},
		{"empty map maps nothing", nil, 0, false},
	} {
		if got := idMapped(c.ranges, c.id); got != c.want {
			t.Errorf("%s: idMapped(%d) = %v, want %v", c.name, c.id, got, c.want)
		}
	}
}

func TestParseIDMapIgnoresGarbage(t *testing.T) {
	if r := parseIDMap("x y z\n0 0\n\n"); len(r) != 0 {
		t.Fatalf("garbage parsed as %v", r)
	}
}

func TestIDMapReport(t *testing.T) {
	lxc := parseIDMap("0 100000 65536\n")
	ids := map[string][2]int64{
		"alice": {10001, 6000},
		"bob":   {10002, 6000},
		"carol": {200513, 200513},
		"dave":  {10003, 70000},
	}
	lookup := func(user string) (int64, int64, error) {
		v, ok := ids[user]
		if !ok {
			return 0, 0, errors.New("exit status 2")
		}
		return v[0], v[1], nil
	}
	for _, c := range []struct {
		name           string
		members        []string
		wantChecked    int
		wantOutside    []string
		wantUnresolved []string
	}{
		{"all inside, duplicates counted once", []string{"alice", "bob", "alice"}, 2, nil, nil},
		{"one uid outside", []string{"alice", "carol"}, 2, []string{"carol (uid 200513, gid 200513)"}, nil},
		{"gid outside", []string{"dave"}, 1, []string{"dave (uid 10003, gid 70000)"}, nil},
		{"one lookup error", []string{"alice", "ghost"}, 1, nil, []string{"ghost"}},
		{"no members", nil, 0, nil, nil},
	} {
		checked, outside, unresolved := idMapReport(c.members, lookup, lxc, lxc)
		if checked != c.wantChecked || !reflect.DeepEqual(outside, c.wantOutside) || !reflect.DeepEqual(unresolved, c.wantUnresolved) {
			t.Errorf("%s: got (%d, %q, %q), want (%d, %q, %q)", c.name,
				checked, outside, unresolved, c.wantChecked, c.wantOutside, c.wantUnresolved)
		}
	}
}
