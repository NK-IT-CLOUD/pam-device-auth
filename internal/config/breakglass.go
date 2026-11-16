package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"slices"
)

// BreakGlass holds the settings for local emergency accounts: the accounts
// that log in with their local SSH key while the directory, SSSD or the
// identity provider is down (break_glass_users) and the client addresses they
// may come from (break_glass_sources; empty means any address).
type BreakGlass struct {
	Users   []string
	Sources []string
}

// BreakGlass returns the break-glass settings of a loaded config.
func (c *Config) BreakGlass() BreakGlass {
	return BreakGlass{Users: c.BreakGlassUsers, Sources: c.BreakGlassSources}
}

// Has reports whether user is listed in break_glass_users. The match is exact.
func (b BreakGlass) Has(user string) bool { return slices.Contains(b.Users, user) }

// LoadBreakGlass reads break_glass_users and break_glass_sources from the
// config file and validates these two keys only. The account phase uses it: a
// mistake in another key, which stops every OIDC login, must not take the
// emergency accounts with it. A file that is not JSON is an error, and so is
// an invalid entry in one of the two keys.
func LoadBreakGlass(path string) (BreakGlass, error) {
	if path == "" {
		path = DefaultConfigPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return BreakGlass{}, fmt.Errorf("read config: %w", err)
	}
	var keys struct {
		Users   []string `json:"break_glass_users"`
		Sources []string `json:"break_glass_sources"`
	}
	if err := json.Unmarshal(data, &keys); err != nil {
		return BreakGlass{}, fmt.Errorf("parse config: %w", err)
	}
	if err := validateBreakGlass(keys.Users, keys.Sources); err != nil {
		return BreakGlass{}, err
	}
	return BreakGlass{Users: keys.Users, Sources: keys.Sources}, nil
}

// breakGlassUserRe is the name of a local account as useradd creates it by
// default. The names are written into an sshd pattern list (Match User),
// where '*', '?', '!' and ',' have a meaning, and SSSD can answer a lookup
// without regard to case while the helper compares names exactly.
var breakGlassUserRe = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// validateBreakGlass checks break_glass_users and break_glass_sources. root
// is not a break-glass account: root_login controls it.
func validateBreakGlass(users, sources []string) error {
	for i, u := range users {
		switch {
		case !breakGlassUserRe.MatchString(u):
			return fmt.Errorf("break_glass_users entry %q must be a local account name [a-z_][a-z0-9_-]* of at most 32 characters", u)
		case u == "root":
			return fmt.Errorf("break_glass_users must not list root; root_login controls root")
		case slices.Contains(users[:i], u):
			return fmt.Errorf("break_glass_users lists %q twice", u)
		}
	}
	for i, s := range sources {
		if err := breakGlassSourceError(s); err != nil {
			return err
		}
		if slices.Contains(sources[:i], s) {
			return fmt.Errorf("break_glass_sources lists %q twice", s)
		}
	}
	return nil
}

// breakGlassSourceError says why s cannot be written into an sshd address
// list (Match Address), nil when it can: an IP address, or a CIDR range in its
// network form. sshd refuses a range with bits set after the prefix length and
// reads anything else as a pattern.
func breakGlassSourceError(s string) error {
	if addr, err := netip.ParseAddr(s); err == nil && addr.Zone() == "" {
		if addr.Is4In6() {
			return fmt.Errorf("break_glass_sources entry %q is an IPv4-mapped IPv6 address; write %s", s, addr.Unmap())
		}
		return nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return fmt.Errorf("break_glass_sources entry %q must be an IP address or a CIDR range", s)
	}
	if p.Addr().Is4In6() {
		ipv4 := "the IPv4 form"
		if p.Bits() >= 96 {
			ipv4 = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96).Masked().String()
		}
		return fmt.Errorf("break_glass_sources entry %q is an IPv4-mapped IPv6 address; write %s", s, ipv4)
	}
	if p.Masked() != p {
		return fmt.Errorf("break_glass_sources entry %q has bits set after its prefix length; write %s", s, p.Masked())
	}
	return nil
}
