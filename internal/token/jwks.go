package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/NK-IT-CLOUD/pam-device-auth/internal/oidccache"
)

// defaultFetchTimeout bounds a metadata fetch when the caller passes neither a
// context deadline nor an http.Client timeout. A variable so tests can shrink it.
var defaultFetchTimeout = 10 * time.Second

// ErrUnknownKeyID is wrapped by Validate when the token's kid is not present
// in the supplied key set. Callers serving keys from the on-disk cache use it
// to decide that a live JWKS refetch (key rotation) is worth one retry.
var ErrUnknownKeyID = errors.New("unknown key ID")

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksResponse struct {
	Keys []jwk `json:"keys"`
}

// FetchJWKS fetches JWKS live from the given URI and returns a map of
// kid -> public key. It does not touch the on-disk cache.
func FetchJWKS(ctx context.Context, client *http.Client, jwksURI string) (map[string]crypto.PublicKey, error) {
	body, err := FetchJWKSRaw(ctx, client, jwksURI)
	if err != nil {
		return nil, err
	}
	return ParseJWKS(body)
}

// FetchJWKSCached serves the key set from the on-disk metadata cache when a
// fresh entry for issuer exists, otherwise calls RefreshJWKS. A cached body
// goes through ParseJWKS exactly like a live response. cached reports whether
// the keys came from disk, so the caller can decide that an unknown kid
// warrants one live refetch. debugf receives non-fatal cache diagnostics;
// nil disables them.
func FetchJWKSCached(ctx context.Context, client *http.Client, jwksURI, issuer string, debugf func(string, ...interface{})) (keys map[string]crypto.PublicKey, cached bool, err error) {
	if debugf == nil {
		debugf = func(string, ...interface{}) {}
	}

	if body, err := oidccache.Load(oidccache.JWKSFile, issuer); err != nil {
		debugf("JWKS cache unusable, fetching live: %v", err)
	} else if body != nil {
		keys, err := ParseJWKS(body)
		if err == nil {
			debugf("JWKS served from cache")
			return keys, true, nil
		}
		debugf("JWKS cache failed validation, fetching live: %v", err)
	}

	keys, err = RefreshJWKS(ctx, client, jwksURI, issuer, debugf)
	return keys, false, err
}

// RefreshJWKS fetches the key set live and overwrites the on-disk cache with
// the validated body best-effort. A failed fetch or parse is never cached.
func RefreshJWKS(ctx context.Context, client *http.Client, jwksURI, issuer string, debugf func(string, ...interface{})) (map[string]crypto.PublicKey, error) {
	if debugf == nil {
		debugf = func(string, ...interface{}) {}
	}

	body, err := FetchJWKSRaw(ctx, client, jwksURI)
	if err != nil {
		return nil, err
	}
	keys, err := ParseJWKS(body)
	if err != nil {
		return nil, err
	}
	if err := oidccache.Save(oidccache.JWKSFile, issuer, body); err != nil {
		debugf("JWKS cache write failed (non-fatal): %v", err)
	}
	return keys, nil
}

// FetchJWKSRaw performs the HTTP part of FetchJWKS and returns the bounded
// raw body without parsing it.
func FetchJWKSRaw(ctx context.Context, client *http.Client, jwksURI string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		client = &http.Client{
			Timeout: defaultFetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	// The body read below must never block a login indefinitely: if the caller
	// supplied neither a context deadline nor a client timeout, bound it here.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && client.Timeout <= 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultFetchTimeout)
		defer cancel()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("build JWKS request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS returned status %d", resp.StatusCode)
	}

	// Bound the body: a JWKS document is a few KB; cap at 1 MiB so a host-pinned
	// but hostile issuer cannot exhaust memory in the root helper.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}
	return body, nil
}

// ParseJWKS decodes a JWKS body into a map of kid -> public key, applying the
// same key filtering and strength checks for live and cached documents.
func ParseJWKS(body []byte) (map[string]crypto.PublicKey, error) {
	var keySet jwksResponse
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&keySet); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for _, k := range keySet.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		// Reject keys with empty kid. A JWT whose header omits "kid" decodes
		// to kid == "" and would silently match such an entry, letting an
		// attacker who can influence the JWKS response forge tokens without
		// specifying a key ID. RFC 7517 makes kid optional, but every
		// mainstream OIDC provider emits it; treat its absence as malformed.
		if k.Kid == "" {
			continue
		}
		pubKey, err := parseJWK(k)
		if err != nil {
			continue // skip unparseable keys
		}
		keys[k.Kid] = pubKey
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no signing keys found in JWKS")
	}

	return keys, nil
}

func parseJWK(k jwk) (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return parseRSAKey(k)
	case "EC":
		return parseECKey(k)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func parseRSAKey(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode RSA N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode RSA E: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	// e is a big-endian unsigned integer (RFC 7518); no sane public exponent
	// needs more than 4 bytes, and anything longer than 8 would overflow the
	// int accumulator below.
	if len(eBytes) == 0 || len(eBytes) > 4 {
		return nil, fmt.Errorf("RSA exponent length %d out of range", len(eBytes))
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	// Reject cryptographically weak parameters before the key is ever used to
	// verify a signature. A short modulus is factorable; a tiny exponent
	// (notably e=1, where m^e == m) makes signatures trivially forgeable. These
	// only matter if the JWKS response is attacker-influenced, but rejecting
	// them closes that door cheaply.
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("RSA modulus too small: %d bits", n.BitLen())
	}
	if e < 3 {
		return nil, fmt.Errorf("RSA exponent too small: %d", e)
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func parseECKey(k jwk) (*ecdsa.PublicKey, error) {
	xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("decode EC X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("decode EC Y: %w", err)
	}

	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", k.Crv)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	// Reject points that do not satisfy the curve equation. An off-curve point
	// supplied via a poisoned JWKS can enable invalid-curve attacks; verifying
	// membership before the key is used is the standard mitigation.
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC point is not on curve %s", k.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}
