package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"syscall"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/config"
)

// migrateBackupSuffix names the copy of the config --migrate-config keeps
// before it adds ldap.profile.
const migrateBackupSuffix = ".pre-0.7.0"

// runMigrateConfig is --migrate-config, run once by the package's postinst
// on upgrade: it prints the change or nothing and returns the exit code.
func runMigrateConfig(path string, stdout, stderr io.Writer) int {
	changed, err := migrateConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL: %v\n", err)
		return 1
	}
	if changed {
		fmt.Fprintf(stdout, "config: set ldap.profile = %q (backup %s)\n", config.LDAPProfileLLDAP, path+migrateBackupSuffix)
	}
	return 0
}

// migrateConfig sets ldap.profile = "lldap" in a config from 0.6.x, which
// documented an unset (null or "") profile as lldap. A config without an ldap
// block, or with "lldap" or "ad" set, is not touched. Any other profile and
// any input it cannot read is an error that leaves the file as it is. Keys
// match case-insensitively, as in the config loader (configKey).
//
// Before anything is written, checkOnlyProfileChanged requires that the
// loader reads the migrated config exactly like the original plus the
// profile; a config with duplicate keys can fail that and is an error that
// leaves the file as it is. The migration writes path+migrateBackupSuffix (never over an existing one),
// then the new config atomically, both with the original's mode and owner,
// and verifies the result with config.Load and validateLDAPProfile. If that
// fails the original is restored and the backup removed. Values are decoded
// as json.RawMessage, so each value is carried over as written; whitespace
// and key order are not (keys come out sorted).
func migrateConfig(path string) (changed bool, err error) {
	orig, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read config: %w", err)
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(orig, &top); err != nil {
		return false, fmt.Errorf("%s: must be a JSON object: %w", path, err)
	}
	ldapKey, raw, err := configKey(top, "ldap")
	if err != nil {
		return false, fmt.Errorf("%s: config %w", path, err)
	}
	if ldapKey == "" || bytes.Equal(raw, []byte("null")) { // null decodes to no ldap block
		return false, nil
	}
	var ldap map[string]json.RawMessage
	if err := json.Unmarshal(raw, &ldap); err != nil || ldap == nil {
		return false, fmt.Errorf("%s: ldap must be a JSON object", path)
	}
	profileKey, p, err := configKey(ldap, "profile")
	if err != nil {
		return false, fmt.Errorf("%s: ldap %w", path, err)
	}
	if profileKey != "" && !bytes.Equal(p, []byte("null")) {
		var profile string
		if err := json.Unmarshal(p, &profile); err != nil {
			return false, fmt.Errorf("%s: ldap.profile must be a string, got %s", path, p)
		}
		if profile != "" {
			if err := validateLDAPProfile(&config.LDAPConfig{Profile: profile}); err != nil {
				return false, fmt.Errorf("%s: %w", path, err)
			}
			return false, nil
		}
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file (%s); set ldap.profile by hand", path, fi.Mode().Type())
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false, fmt.Errorf("%s: cannot read the owner", path)
	}
	mode, uid, gid := fi.Mode().Perm(), int(st.Uid), int(st.Gid)

	if profileKey != "" {
		delete(ldap, profileKey) // a null or "" profile, possibly in another case
	}
	ldap["profile"] = json.RawMessage(`"` + config.LDAPProfileLLDAP + `"`)
	if top[ldapKey], err = encodeConfigJSON(ldap, ""); err != nil {
		return false, err
	}
	migrated, err := encodeConfigJSON(top, "\n")
	if err != nil {
		return false, err
	}
	if err := checkOnlyProfileChanged(orig, migrated); err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}

	backup := path + migrateBackupSuffix
	if err := writeBackup(backup, orig, mode, uid, gid); err != nil {
		return false, err
	}
	if err = verifyMigrated(path, migrated, mode, uid, gid); err == nil {
		return true, nil
	}
	if rerr := writeOwned(path, orig, mode, uid, gid); rerr != nil {
		return false, fmt.Errorf("%w (could NOT restore %s: %v; the original is in %s)", err, path, rerr, backup)
	}
	if rerr := os.Remove(backup); rerr != nil {
		return false, fmt.Errorf("%w (restored %s; could not remove %s: %v)", err, path, backup, rerr)
	}
	return false, fmt.Errorf("%w (restored %s)", err, path)
}

// configKey finds name in m the way the config loader (encoding/json into a
// struct) does: case-insensitively. It returns the key as written ("" when
// absent); two keys that differ only in case are an error, as which one the
// loader uses is not obvious.
func configKey(m map[string]json.RawMessage, name string) (key string, raw json.RawMessage, err error) {
	for k, v := range m {
		if !strings.EqualFold(k, name) {
			continue
		}
		if key != "" {
			return "", nil, fmt.Errorf("has more than one %q key (%q, %q); keep one", name, key, k)
		}
		key, raw = k, v
	}
	return key, raw, nil
}

// checkOnlyProfileChanged decodes the original and the migrated config the
// way the loader does (encoding/json into config.Config) and requires them to
// be equal once the original's unset ldap.profile is read as "lldap". The
// migration rewrites the config through maps, which keep only the last of two
// duplicate keys, and keeps keys that differ only in case side by side in
// sorted order; the loader merges duplicate objects and takes the last
// case-variant. Without this check such a config would silently change, for
// example an "ad" ldap block followed by an empty duplicate would become
// lldap, or a duplicated attributes object would lose an attribute.
func checkOnlyProfileChanged(orig, migrated []byte) error {
	var before, after config.Config
	if err := json.Unmarshal(orig, &before); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	if err := json.Unmarshal(migrated, &after); err != nil {
		return fmt.Errorf("parse migrated config: %w", err)
	}
	if before.LDAP != nil && before.LDAP.Profile == "" {
		before.LDAP.Profile = config.LDAPProfileLLDAP
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("the config loader would read more than ldap.profile differently after the migration " +
			"(duplicate keys, or keys that differ only in case); keep one of each, then run --migrate-config again")
	}
	return nil
}

// verifyMigrated writes the migrated config and checks it with the loader of
// --check and the profile rule.
func verifyMigrated(path string, migrated []byte, mode os.FileMode, uid, gid int) error {
	if err := writeOwned(path, migrated, mode, uid, gid); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("%s after migration: %w", path, err)
	}
	if cfg.LDAP == nil {
		return fmt.Errorf("%s after migration: no ldap block", path)
	}
	return validateLDAPProfile(cfg.LDAP)
}

// encodeConfigJSON encodes v indented and without HTML escaping, so the raw
// values inside keep their bytes. suffix "" drops the encoder's newline.
func encodeConfigJSON(v any, suffix string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "    ")
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("encode config: %w", err)
	}
	return append(bytes.TrimRight(b.Bytes(), "\n"), suffix...), nil
}

// writeBackup creates backup with content, mode and owner; an existing file is
// an error, never overwritten. A failed write removes the partial backup.
func writeBackup(backup string, content []byte, mode os.FileMode, uid, gid int) (err error) {
	f, err := os.OpenFile(backup, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("backup %s already exists; move it away and run --migrate-config again", backup)
	}
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("close backup %s: %w", backup, cerr)
		}
		if err != nil {
			os.Remove(backup)
		}
	}()
	if err = f.Chown(uid, gid); err != nil {
		return fmt.Errorf("backup %s: %w", backup, err)
	}
	if err = f.Chmod(mode); err != nil {
		return fmt.Errorf("backup %s: %w", backup, err)
	}
	if _, err = f.Write(content); err != nil {
		return fmt.Errorf("backup %s: %w", backup, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("backup %s: %w", backup, err)
	}
	return nil
}

// writeOwned writes path atomically with mode and owner.
func writeOwned(path string, content []byte, mode os.FileMode, uid, gid int) error {
	if err := atomicWriteFile(path, content, mode); err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
