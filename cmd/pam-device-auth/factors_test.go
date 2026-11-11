package main

import (
	"reflect"
	"strings"
	"testing"
)

// sshd reads AuthenticationMethods as a list of alternatives separated by
// whitespace; the methods of one alternative are joined by commas.
func TestMethodsRequire2FA(t *testing.T) {
	for am, want := range map[string]bool{
		"publickey,keyboard-interactive:pam":           true,
		"keyboard-interactive:pam,publickey":           true,
		"publickey,keyboard-interactive":               true,
		"publickey keyboard-interactive:pam":           false, // either factor alone
		"publickey,keyboard-interactive:pam publickey": false, // the second alternative is the key alone
		"publickey":          false,
		"any":                false,
		"":                   false,
		"publickey,password": false,
	} {
		if got := methodsRequire2FA(am); got != want {
			t.Errorf("methodsRequire2FA(%q) = %v, want %v", am, got, want)
		}
	}
}

func TestMethodsKeyOnly(t *testing.T) {
	for am, want := range map[string]bool{
		"publickey":                          true,
		"publickey publickey":                true,
		"publickey password":                 false,
		"publickey,keyboard-interactive:pam": false,
		"":                                   false,
		"any":                                false,
	} {
		if got := methodsKeyOnly(am); got != want {
			t.Errorf("methodsKeyOnly(%q) = %v, want %v", am, got, want)
		}
	}
}

// A connection spec of `sshd -T -C` is a comma-separated list of key=value
// pairs: a name with one of these characters cannot be written into it.
func TestConnSpecUser(t *testing.T) {
	if spec, ok := connSpecUser("alice"); !ok || spec != "user=alice" {
		t.Errorf("connSpecUser(\"alice\") = %q, %v; want \"user=alice\", true", spec, ok)
	}
	for _, name := range []string{"a,addr=192.0.2.1", "a=b", "a b", "a\tb", ""} {
		if spec, ok := connSpecUser(name); ok {
			t.Errorf("connSpecUser(%q) = %q, true; want not usable", name, spec)
		}
	}
}

func TestFactorReport(t *testing.T) {
	methods := map[string]string{
		"user=alice": "publickey,keyboard-interactive:pam",
		"user=bob":   "publickey keyboard-interactive:pam",
		"user=svc":   "publickey",
		"user=svc2":  "publickey,keyboard-interactive:pam",
	}
	methodsFor := func(spec string) (string, bool) {
		am, ok := methods[spec]
		return am, ok
	}
	access := []string{"alice", "bob", "svc", "x,y", "ghost"}
	service := []string{"svc", "svc2"}

	twoFactor, keyOnly, weak, notEvaluated := factorReport(access, service, methodsFor)

	if want := []string{"alice"}; !reflect.DeepEqual(twoFactor, want) {
		t.Errorf("twoFactor = %v, want %v", twoFactor, want)
	}
	if want := []string{"svc"}; !reflect.DeepEqual(keyOnly, want) {
		t.Errorf("keyOnly = %v, want %v", keyOnly, want)
	}
	// bob may use either factor alone; svc2 is in a service group but sshd
	// asks it for both factors, which automation cannot give.
	if want := []string{"bob (publickey keyboard-interactive:pam)", "svc2 (publickey,keyboard-interactive:pam)"}; !reflect.DeepEqual(weak, want) {
		t.Errorf("weak = %v, want %v", weak, want)
	}
	// "x,y" cannot be written into a connection spec; for "ghost" sshd -T gave no answer.
	if want := []string{"x,y", "ghost"}; !reflect.DeepEqual(notEvaluated, want) {
		t.Errorf("notEvaluated = %v, want %v", notEvaluated, want)
	}
}

// factorReport reads the methods through the same `sshd -T -C` call the rest
// of --check uses.
func TestFactorReport_ReadsSshdT(t *testing.T) {
	orig := sshdTOutput
	t.Cleanup(func() { sshdTOutput = orig })
	sshdTOutput = func(args ...string) ([]byte, error) {
		am := "publickey,keyboard-interactive:pam"
		if strings.Join(args, " ") == "-T -C user=bob" {
			am = "publickey"
		}
		return []byte("port 22\nauthenticationmethods " + am + "\nusepam yes\n"), nil
	}
	methodsFor := func(spec string) (string, bool) { return sshdParamFor("authenticationmethods", spec) }

	twoFactor, _, weak, _ := factorReport([]string{"alice", "bob"}, nil, methodsFor)

	if want := []string{"alice"}; !reflect.DeepEqual(twoFactor, want) {
		t.Errorf("twoFactor = %v, want %v", twoFactor, want)
	}
	if want := []string{"bob (publickey)"}; !reflect.DeepEqual(weak, want) {
		t.Errorf("weak = %v, want %v", weak, want)
	}
}
