package main

import "testing"

func TestMatchesAllowedIP_ExactMatch(t *testing.T) {
	allowed := []string{"198.51.100.2", "192.0.2.202", "192.0.2.12"}
	if !matchesAllowedIP("198.51.100.2", allowed) {
		t.Error("should match exact IP")
	}
	if !matchesAllowedIP("192.0.2.12", allowed) {
		t.Error("should match last IP")
	}
}

func TestMatchesAllowedIP_NoMatch(t *testing.T) {
	allowed := []string{"198.51.100.2", "192.0.2.202"}
	if matchesAllowedIP("203.0.113.1", allowed) {
		t.Error("should not match unknown IP")
	}
}

func TestMatchesAllowedIP_CIDR(t *testing.T) {
	allowed := []string{"198.51.100.0/24", "203.0.113.0/24"}
	if !matchesAllowedIP("198.51.100.2", allowed) {
		t.Error("198.51.100.2 should match 198.51.100.0/24")
	}
	if !matchesAllowedIP("203.0.113.50", allowed) {
		t.Error("203.0.113.50 should match 203.0.113.0/24")
	}
	if matchesAllowedIP("192.0.2.1", allowed) {
		t.Error("192.0.2.1 should not match any CIDR")
	}
}

func TestMatchesAllowedIP_MixedIPAndCIDR(t *testing.T) {
	allowed := []string{"198.51.100.2", "203.0.113.0/24"}
	if !matchesAllowedIP("198.51.100.2", allowed) {
		t.Error("should match exact IP")
	}
	if !matchesAllowedIP("203.0.113.1", allowed) {
		t.Error("should match CIDR")
	}
	if matchesAllowedIP("198.51.100.3", allowed) {
		t.Error("198.51.100.3 should not match")
	}
}

func TestMatchesAllowedIP_EmptyList(t *testing.T) {
	if matchesAllowedIP("198.51.100.2", []string{}) {
		t.Error("should not match empty list")
	}
}

func TestMatchesAllowedIP_InvalidClientIP(t *testing.T) {
	if matchesAllowedIP("not-an-ip", []string{"198.51.100.0/24"}) {
		t.Error("invalid client IP should not match")
	}
}

func TestMatchesAllowedIP_InvalidCIDR(t *testing.T) {
	// Invalid CIDR should be skipped, not crash
	if matchesAllowedIP("198.51.100.2", []string{"invalid/cidr"}) {
		t.Error("invalid CIDR should not match")
	}
	// But exact IP still works alongside invalid CIDR
	if !matchesAllowedIP("198.51.100.2", []string{"invalid/cidr", "198.51.100.2"}) {
		t.Error("should still match exact IP after invalid CIDR")
	}
}

func TestMatchesAllowedIP_IPv6(t *testing.T) {
	allowed := []string{"::1", "fd00::/8"}
	if !matchesAllowedIP("::1", allowed) {
		t.Error("should match IPv6 loopback")
	}
	if !matchesAllowedIP("fd00::1", allowed) {
		t.Error("should match fd00::/8 CIDR")
	}
}

func TestCanRenderQR(t *testing.T) {
	short := "https://sso.example.com/device?user_code=ABCD-EFGH"
	if !canRenderQR(short) {
		t.Error("short URL should be renderable")
	}
	long := "https://very-long-sso-provider.example.com/auth/realms/very-long-realm/protocol/openid-connect/auth/device?user_code=VERY-LONG"
	if canRenderQR(long) {
		t.Error("long URL should not be renderable")
	}
}

// On dual-stack sshd, PAM_RHOST may arrive as an IPv4-mapped IPv6 address
// ("::ffff:198.51.100.21") while the OIDC allowlist holds the plain IPv4 form (or
// vice versa). The exact-match branch must compare parsed addresses, not raw
// strings, or legitimate users get intermittent hard-denies.
func TestMatchesAllowedIP_IPv4MappedIPv6ExactMatch(t *testing.T) {
	if !matchesAllowedIP("::ffff:198.51.100.21", []string{"198.51.100.21"}) {
		t.Error("IPv4-mapped client against plain IPv4 allowlist entry should match")
	}
	if !matchesAllowedIP("198.51.100.21", []string{"::ffff:198.51.100.21"}) {
		t.Error("plain IPv4 client against IPv4-mapped allowlist entry should match")
	}
	if matchesAllowedIP("::ffff:198.51.100.22", []string{"198.51.100.21"}) {
		t.Error("different addresses must not match")
	}
}
