package discovery

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFetchSuccess(t *testing.T) {
	endpoints := map[string]interface{}{
		"issuer":                        "https://sso.example.com/realms/test",
		"token_endpoint":                "https://sso.example.com/realms/test/protocol/openid-connect/token",
		"device_authorization_endpoint": "https://sso.example.com/realms/test/protocol/openid-connect/auth/device",
		"jwks_uri":                      "https://sso.example.com/realms/test/protocol/openid-connect/certs",
		"authorization_endpoint":        "https://sso.example.com/realms/test/protocol/openid-connect/auth",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/realms/test/.well-known/openid-configuration" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(endpoints)
	}))
	defer srv.Close()

	result, err := Fetch(context.Background(), srv.Client(), srv.URL, "test")
	if err != nil {
		t.Fatalf("Fetch() error: %v", err)
	}

	if result.Issuer != "https://sso.example.com/realms/test" {
		t.Errorf("Issuer = %q", result.Issuer)
	}
	if result.TokenEndpoint != "https://sso.example.com/realms/test/protocol/openid-connect/token" {
		t.Errorf("TokenEndpoint = %q", result.TokenEndpoint)
	}
	if result.DeviceAuthorizationEndpoint != "https://sso.example.com/realms/test/protocol/openid-connect/auth/device" {
		t.Errorf("DeviceAuthorizationEndpoint = %q", result.DeviceAuthorizationEndpoint)
	}
	if result.JwksURI != "https://sso.example.com/realms/test/protocol/openid-connect/certs" {
		t.Errorf("JwksURI = %q", result.JwksURI)
	}
}

func TestFetchMissingFields(t *testing.T) {
	tests := []struct {
		name     string
		response map[string]interface{}
	}{
		{"missing token_endpoint", map[string]interface{}{
			"issuer":                        "x",
			"device_authorization_endpoint": "x",
			"jwks_uri":                      "x",
		}},
		{"missing device_authorization_endpoint", map[string]interface{}{
			"issuer":         "x",
			"token_endpoint": "x",
			"jwks_uri":       "x",
		}},
		{"missing jwks_uri", map[string]interface{}{
			"issuer":                        "x",
			"token_endpoint":                "x",
			"device_authorization_endpoint": "x",
		}},
		{"missing issuer", map[string]interface{}{
			"token_endpoint":                "x",
			"device_authorization_endpoint": "x",
			"jwks_uri":                      "x",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(tt.response)
			}))
			defer srv.Close()

			_, err := Fetch(context.Background(), srv.Client(), srv.URL, "test")
			if err == nil {
				t.Error("Fetch() should have returned error for missing field")
			}
		})
	}
}

func TestFetchServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := Fetch(context.Background(), srv.Client(), srv.URL, "test")
	if err == nil {
		t.Error("Fetch() should fail on 500")
	}
}

func TestFetchUnreachable(t *testing.T) {
	_, err := Fetch(context.Background(), &http.Client{Timeout: 100 * time.Millisecond}, "http://127.0.0.1:1", "test")
	if err == nil {
		t.Error("Fetch() should fail for unreachable server")
	}
}
