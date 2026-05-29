package main

import "testing"

func TestMatchesAllowedIP_ExactMatch(t *testing.T) {
	allowed := []string{"10.0.20.2", "10.0.99.202", "10.1.1.2"}
	if !matchesAllowedIP("10.0.20.2", allowed) {
		t.Error("should match exact IP")
	}
	if !matchesAllowedIP("10.1.1.2", allowed) {
		t.Error("should match last IP")
	}
}

func TestMatchesAllowedIP_NoMatch(t *testing.T) {
	allowed := []string{"10.0.20.2", "10.0.99.202"}
	if matchesAllowedIP("192.168.1.1", allowed) {
		t.Error("should not match unknown IP")
	}
}

func TestMatchesAllowedIP_CIDR(t *testing.T) {
	allowed := []string{"10.0.0.0/16", "192.168.1.0/24"}
	if !matchesAllowedIP("10.0.20.2", allowed) {
		t.Error("10.0.20.2 should match 10.0.0.0/16")
	}
	if !matchesAllowedIP("192.168.1.50", allowed) {
		t.Error("192.168.1.50 should match 192.168.1.0/24")
	}
	if matchesAllowedIP("172.16.0.1", allowed) {
		t.Error("172.16.0.1 should not match any CIDR")
	}
}

func TestMatchesAllowedIP_MixedIPAndCIDR(t *testing.T) {
	allowed := []string{"10.0.20.2", "192.168.0.0/16"}
	if !matchesAllowedIP("10.0.20.2", allowed) {
		t.Error("should match exact IP")
	}
	if !matchesAllowedIP("192.168.1.1", allowed) {
		t.Error("should match CIDR")
	}
	if matchesAllowedIP("10.0.20.3", allowed) {
		t.Error("10.0.20.3 should not match")
	}
}

func TestMatchesAllowedIP_EmptyList(t *testing.T) {
	if matchesAllowedIP("10.0.20.2", []string{}) {
		t.Error("should not match empty list")
	}
}

func TestMatchesAllowedIP_InvalidClientIP(t *testing.T) {
	if matchesAllowedIP("not-an-ip", []string{"10.0.0.0/8"}) {
		t.Error("invalid client IP should not match")
	}
}

func TestMatchesAllowedIP_InvalidCIDR(t *testing.T) {
	// Invalid CIDR should be skipped, not crash
	if matchesAllowedIP("10.0.20.2", []string{"invalid/cidr"}) {
		t.Error("invalid CIDR should not match")
	}
	// But exact IP still works alongside invalid CIDR
	if !matchesAllowedIP("10.0.20.2", []string{"invalid/cidr", "10.0.20.2"}) {
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
