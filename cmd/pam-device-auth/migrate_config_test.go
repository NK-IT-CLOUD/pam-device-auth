package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// migrateBase is a valid 0.6.x config whose ldap block has no profile. The
// bind password carries characters encoding/json would escape by default
// (<, >, &) and a \u escape, to pin that values are carried over verbatim.
const migrateBase = `{
    "issuer_url": "https://sso.example.com/realms/r",
    "client_id": "ssh-server",
    "required_role": "ssh-access",
    "auth_timeout": 120,
    "allowed_algorithms": ["RS256"],
    "ldap": {
        "uri": "ldaps://ldap.example.com:636",
        "base_dn": "dc=example,dc=com",
        "bind_dn": "uid=nss-ro,ou=people,dc=example,dc=com",
        "bind_password": "p<w>&dä",
        "access_group": "ssh-access",
        "admin_group": "ssh-admin",
        "service_account_groups": ["ssh-service"]
        PROFILE
    }
}
`

// migrateInput returns migrateBase with profileLine inserted after the last
// ldap member ("" = no profile key).
func migrateInput(profileLine string) string {
	if profileLine != "" {
		profileLine = "," + profileLine
	}
	return strings.Replace(migrateBase, "PROFILE", profileLine, 1)
}

// writeConfig writes content to a fresh config.json with mode and returns its path.
func writeConfig(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil { // umask
		t.Fatal(err)
	}
	return path
}

// assertUntouched fails unless path still holds want with the given mtime and
// no backup exists next to it.
func assertUntouched(t *testing.T, path, want string, mtime time.Time) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("config changed:\n%s\nwant:\n%s", got, want)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.ModTime().Equal(mtime) {
		t.Errorf("config mtime changed: %v -> %v", mtime, fi.ModTime())
	}
	if _, err := os.Lstat(path + migrateBackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup %s exists (err=%v), want none", path+migrateBackupSuffix, err)
	}
}

func mtimeOf(t *testing.T, path string) time.Time {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.ModTime()
}

func ownerOf(t *testing.T, path string) (uid, gid uint32) {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := fi.Sys().(*syscall.Stat_t)
	return st.Uid, st.Gid
}

func decodeAny(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return m
}

// A 0.6.x config without ldap.profile (documented as lldap) gets
// "profile": "lldap"; the backup is the original byte for byte with the same
// mode and owner, and every other value is unchanged.
func TestMigrateConfigAddsProfile(t *testing.T) {
	for _, c := range []struct{ name, profileLine string }{
		{"absent", ""},
		{"null", `"profile": null`},
		{"empty", `"profile": ""`},
	} {
		t.Run(c.name, func(t *testing.T) {
			in := migrateInput(c.profileLine)
			path := writeConfig(t, in, 0600)
			uid, gid := ownerOf(t, path)

			changed, err := migrateConfig(path)
			if err != nil || !changed {
				t.Fatalf("migrateConfig = %v, %v; want true, nil", changed, err)
			}

			out, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fi, _ := os.Stat(path)
			if fi.Mode().Perm() != 0600 {
				t.Errorf("config mode = %v, want 0600", fi.Mode().Perm())
			}
			if u, g := ownerOf(t, path); u != uid || g != gid {
				t.Errorf("config owner = %d:%d, want %d:%d", u, g, uid, gid)
			}
			backup := path + migrateBackupSuffix
			bk, err := os.ReadFile(backup)
			if err != nil {
				t.Fatalf("backup: %v", err)
			}
			if string(bk) != in {
				t.Errorf("backup differs from the original:\n%s", bk)
			}
			bfi, _ := os.Stat(backup)
			if bfi.Mode().Perm() != 0600 {
				t.Errorf("backup mode = %v, want 0600", bfi.Mode().Perm())
			}
			if u, g := ownerOf(t, backup); u != uid || g != gid {
				t.Errorf("backup owner = %d:%d, want %d:%d", u, g, uid, gid)
			}

			got, want := decodeAny(t, out), decodeAny(t, []byte(in))
			gotLDAP := got["ldap"].(map[string]any)
			if gotLDAP["profile"] != "lldap" {
				t.Errorf("ldap.profile = %#v, want \"lldap\"", gotLDAP["profile"])
			}
			delete(gotLDAP, "profile")
			delete(want["ldap"].(map[string]any), "profile")
			if !reflect.DeepEqual(got, want) {
				t.Errorf("values changed:\n got %#v\nwant %#v", got, want)
			}
			// Values are carried over as written: no HTML escaping, the \u
			// escape stays.
			if !bytes.Contains(out, []byte(`"p<w>&dä"`)) {
				t.Errorf("bind_password not carried over verbatim:\n%s", out)
			}
		})
	}
}

// The migration keeps a 0644 mode as it is (same mode as the original).
func TestMigrateConfigKeepsMode(t *testing.T) {
	path := writeConfig(t, migrateInput(""), 0644)
	if changed, err := migrateConfig(path); err != nil || !changed {
		t.Fatalf("migrateConfig = %v, %v", changed, err)
	}
	for _, p := range []string{path, path + migrateBackupSuffix} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0644 {
			t.Errorf("%s mode = %v, want 0644", p, fi.Mode().Perm())
		}
	}
}

// A config that already names its profile (every AD install, and lldap set
// explicitly) is not touched: same bytes, same mtime, no backup.
func TestMigrateConfigADUntouched(t *testing.T) {
	for _, p := range []string{"ad", "lldap"} {
		t.Run(p, func(t *testing.T) {
			in := migrateInput(`"profile": "` + p + `"`)
			path := writeConfig(t, in, 0600)
			mt := mtimeOf(t, path)
			changed, err := migrateConfig(path)
			if err != nil || changed {
				t.Fatalf("migrateConfig = %v, %v; want false, nil", changed, err)
			}
			assertUntouched(t, path, in, mt)
		})
	}
}

// The config loader matches keys case-insensitively, so 0.6.x read
// "Profile": "ad" as the ad profile and "LDAP" as the ldap block. The
// migration must see them the same way: an AD config stays untouched, and an
// "LDAP" block without a profile is migrated under its own key. Two keys that
// differ only in case are ambiguous and refused.
func TestMigrateConfigKeysCaseInsensitive(t *testing.T) {
	t.Run("Profile ad untouched", func(t *testing.T) {
		in := migrateInput(`"Profile": "ad"`)
		path := writeConfig(t, in, 0600)
		mt := mtimeOf(t, path)
		if changed, err := migrateConfig(path); err != nil || changed {
			t.Fatalf("migrateConfig = %v, %v; want false, nil", changed, err)
		}
		assertUntouched(t, path, in, mt)
	})
	t.Run("LDAP block migrated", func(t *testing.T) {
		in := strings.Replace(migrateInput(`"PROFILE": null`), `"ldap"`, `"LDAP"`, 1)
		path := writeConfig(t, in, 0600)
		if changed, err := migrateConfig(path); err != nil || !changed {
			t.Fatalf("migrateConfig = %v, %v; want true, nil", changed, err)
		}
		out, _ := os.ReadFile(path)
		got := decodeAny(t, out)
		l, ok := got["LDAP"].(map[string]any)
		if !ok || l["profile"] != "lldap" || len(got) != len(decodeAny(t, []byte(in))) {
			t.Fatalf("migrated config = %s", out)
		}
		if _, ok := l["PROFILE"]; ok {
			t.Errorf("the null PROFILE key is still there: %s", out)
		}
	})
	for _, c := range []struct{ name, in, want string }{
		{"two profile keys", migrateInput(`"profile": "", "Profile": "ad"`), `ldap has more than one "profile" key`},
		{"two ldap keys", `{"ldap": {}, "LDAP": {"profile": "ad"}}`, `has more than one "ldap" key`},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.in, 0600)
			mt := mtimeOf(t, path)
			if _, err := migrateConfig(path); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			assertUntouched(t, path, c.in, mt)
		})
	}
}

// The loader (encoding/json into config.Config) merges duplicate object keys,
// the migration's map keeps only the last one. A config the loader reads
// differently after the migration (besides ldap.profile) is refused before
// anything is written: an AD block followed by an empty duplicate would flip
// the host to lldap, a duplicated attributes object would drop an attribute.
func TestMigrateConfigRefusesDuplicateKeys(t *testing.T) {
	for _, c := range []struct{ name, in string }{
		{"ad block, then an empty duplicate", strings.Replace(migrateInput(`"profile": "ad"`), "    }\n}\n", "    },\n    \"ldap\": {}\n}\n", 1)},
		{"nested duplicate attributes", migrateInput(`"attributes": {"username": "uid"}, "attributes": {"ssh_key": "sshPublicKey"}`)},
		// The loader takes the last of "uri"/"URI"; the sorted output puts
		// "URI" first.
		{"nested keys that differ only in case", migrateInput(`"URI": "ldaps://other.example.com:636"`)},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.in, 0600)
			mt := mtimeOf(t, path)
			changed, err := migrateConfig(path)
			if err == nil || changed || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("migrateConfig = %v, %v; want an error naming %s and the duplicate keys", changed, err, path)
			}
			assertUntouched(t, path, c.in, mt)
		})
	}
}

// verifyMigrated must not dereference a missing ldap block: an error, no panic.
func TestVerifyMigratedNoLDAPBlock(t *testing.T) {
	path := writeConfig(t, migrateInput(""), 0600)
	fi, _ := os.Stat(path)
	uid, gid := ownerOf(t, path)
	noLDAP := `{"issuer_url": "https://sso.example.com/realms/r", "client_id": "c", "required_role": "r"}`
	if err := verifyMigrated(path, []byte(noLDAP), fi.Mode().Perm(), int(uid), int(gid)); err == nil || !strings.Contains(err.Error(), "no ldap block") {
		t.Errorf("verifyMigrated = %v, want a no-ldap-block error", err)
	}
}

// Without a directory block there is no profile to set; "ldap": null decodes
// to no block, as in 0.6.x.
func TestMigrateConfigNoLDAPBlock(t *testing.T) {
	for _, in := range []string{
		`{"issuer_url": "https://sso.example.com/realms/r", "client_id": "c", "required_role": "r"}`,
		`{"issuer_url": "https://sso.example.com/realms/r", "client_id": "c", "required_role": "r", "ldap": null}`,
	} {
		path := writeConfig(t, in, 0600)
		mt := mtimeOf(t, path)
		changed, err := migrateConfig(path)
		if err != nil || changed {
			t.Fatalf("%s: migrateConfig = %v, %v; want false, nil", in, changed, err)
		}
		assertUntouched(t, path, in, mt)
	}
}

func TestMigrateConfigInvalidJSON(t *testing.T) {
	in := `{"issuer_url": "https://sso.example.com", "ldap": {"uri": `
	path := writeConfig(t, in, 0600)
	mt := mtimeOf(t, path)
	if _, err := migrateConfig(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want an error naming %s", err, path)
	}
	assertUntouched(t, path, in, mt)
}

// Every input migrateConfig cannot migrate is an error that leaves the file
// as it is and writes no backup.
func TestMigrateConfigRefuses(t *testing.T) {
	for _, c := range []struct{ name, in, want string }{
		{"unknown profile", migrateInput(`"profile": "openldap"`), `ldap.profile must be "lldap" or "ad", got "openldap"`},
		{"profile wrong case", migrateInput(`"profile": "AD"`), `ldap.profile must be "lldap" or "ad", got "AD"`},
		{"profile not a string", migrateInput(`"profile": 5`), "ldap.profile must be a string"},
		{"ldap is a string", `{"issuer_url": "https://sso.example.com/realms/r", "ldap": "x"}`, "ldap must be a JSON object"},
		{"ldap is an array", `{"issuer_url": "https://sso.example.com/realms/r", "ldap": []}`, "ldap must be a JSON object"},
		{"top level not an object", `[]`, "must be a JSON object"},
	} {
		t.Run(c.name, func(t *testing.T) {
			path := writeConfig(t, c.in, 0600)
			mt := mtimeOf(t, path)
			changed, err := migrateConfig(path)
			if err == nil || changed || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), path) {
				t.Fatalf("migrateConfig = %v, %v; want an error naming %s with %q", changed, err, path, c.want)
			}
			assertUntouched(t, path, c.in, mt)
		})
	}
}

func TestMigrateConfigMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if _, err := migrateConfig(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("err = %v, want an error naming %s", err, path)
	}
	if _, err := os.Lstat(path + migrateBackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup created for a missing config")
	}
}

// An existing backup is never overwritten: it may be the only copy of an
// older config.
func TestMigrateConfigBackupExists(t *testing.T) {
	in := migrateInput("")
	path := writeConfig(t, in, 0600)
	backup := path + migrateBackupSuffix
	if err := os.WriteFile(backup, []byte("older"), 0600); err != nil {
		t.Fatal(err)
	}
	mt := mtimeOf(t, path)
	if _, err := migrateConfig(path); err == nil || !strings.Contains(err.Error(), backup) {
		t.Fatalf("err = %v, want an error naming %s", err, backup)
	}
	if b, _ := os.ReadFile(backup); string(b) != "older" {
		t.Errorf("backup overwritten: %q", b)
	}
	if got, _ := os.ReadFile(path); string(got) != in || !mtimeOf(t, path).Equal(mt) {
		t.Errorf("config changed")
	}
}

// A migrated config that the loader rejects (here: no required_role) is rolled
// back: the original content and mode are back, the backup is gone, and the
// error names the loader's complaint.
func TestMigrateConfigRollsBackWhenLoadFails(t *testing.T) {
	in := strings.Replace(migrateInput(""), `"required_role": "ssh-access",`, "", 1)
	path := writeConfig(t, in, 0640)
	changed, err := migrateConfig(path)
	if err == nil || changed || !strings.Contains(err.Error(), "required_role is required") {
		t.Fatalf("migrateConfig = %v, %v; want the loader error", changed, err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != in {
		t.Errorf("original not restored:\n%s", got)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0640 {
		t.Errorf("mode = %v, want 0640", fi.Mode().Perm())
	}
	if _, err := os.Lstat(path + migrateBackupSuffix); !os.IsNotExist(err) {
		t.Errorf("backup left behind after rollback")
	}
}

// A symlinked config is refused: the atomic rename would replace the link
// with a file.
func TestMigrateConfigRefusesSymlink(t *testing.T) {
	in := migrateInput("")
	target := writeConfig(t, in, 0600)
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := migrateConfig(path); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("err = %v, want a not-a-regular-file error", err)
	}
	if fi, err := os.Lstat(path); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("symlink replaced")
	}
	if got, _ := os.ReadFile(target); string(got) != in {
		t.Errorf("target changed")
	}
}

// --migrate-config prints the change (with the backup path) or nothing, and
// exits 1 with a FAIL line on an error.
func TestRunMigrateConfig(t *testing.T) {
	path := writeConfig(t, migrateInput(""), 0600)
	var out, errOut bytes.Buffer
	if code := runMigrateConfig(path, &out, &errOut); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	if want := `config: set ldap.profile = "lldap" (backup ` + path + migrateBackupSuffix + ")\n"; out.String() != want || errOut.Len() != 0 {
		t.Errorf("stdout %q stderr %q, want %q", out.String(), errOut.String(), want)
	}

	out.Reset()
	if code := runMigrateConfig(path, &out, &errOut); code != 0 || out.Len() != 0 || errOut.Len() != 0 {
		t.Errorf("second run: exit %d stdout %q stderr %q; want silent success", code, out.String(), errOut.String())
	}

	bad := writeConfig(t, migrateInput(`"profile": "openldap"`), 0600)
	out.Reset()
	if code := runMigrateConfig(bad, &out, &errOut); code != 1 || out.Len() != 0 ||
		!strings.HasPrefix(errOut.String(), "FAIL: ") || !strings.Contains(errOut.String(), `ldap.profile must be "lldap" or "ad", got "openldap"`) {
		t.Errorf("invalid profile: exit %d stdout %q stderr %q", code, out.String(), errOut.String())
	}
}
