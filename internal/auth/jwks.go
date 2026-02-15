package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	Crv string `json:"crv"` // EC curve
	X   string `json:"x"`   // EC x coordinate
	Y   string `json:"y"`   // EC y coordinate
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKSCache caches JWKS keys with TTL
type JWKSCache struct {
	mu        sync.RWMutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
	ttl       time.Duration
	jwksURL   string
	client    *http.Client
}

// NewJWKSCache creates a new JWKS cache
func NewJWKSCache(jwksURL string, ttl time.Duration) *JWKSCache {
	return &JWKSCache{
		keys:    make(map[string]crypto.PublicKey),
		ttl:     ttl,
		jwksURL: jwksURL,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetKey returns the public key for the given kid, fetching from JWKS endpoint if needed
func (c *JWKSCache) GetKey(kid string) (crypto.PublicKey, error) {
	c.mu.RLock()
	if time.Since(c.fetchedAt) < c.ttl {
		if key, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return key, nil
		}
	}
	c.mu.RUnlock()

	// Fetch fresh keys
	if err := c.refresh(); err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	c.mu.RLock()
	defer c.mu.RUnlock()
	key, ok := c.keys[kid]
	if !ok {
		return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
	}
	return key, nil
}

// refresh fetches JWKS from the endpoint
func (c *JWKSCache) refresh() error {
	resp, err := c.client.Get(c.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("JWKS endpoint returned %d: %s", resp.StatusCode, body)
	}

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return fmt.Errorf("failed to decode JWKS: %w", err)
	}

	keys := make(map[string]crypto.PublicKey)
	for _, jwk := range jwks.Keys {
		if jwk.Use != "" && jwk.Use != "sig" {
			continue
		}
		key, err := parseJWK(jwk)
		if err != nil {
			continue // Skip keys we can't parse
		}
		keys[jwk.Kid] = key
	}

	c.mu.Lock()
	c.keys = keys
	c.fetchedAt = time.Now()
	c.mu.Unlock()

	return nil
}

// parseJWK converts a JWK to a crypto.PublicKey
func parseJWK(jwk JWK) (crypto.PublicKey, error) {
	switch jwk.Kty {
	case "RSA":
		return parseRSAKey(jwk)
	case "EC":
		return parseECKey(jwk)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", jwk.Kty)
	}
}

// parseRSAKey parses an RSA JWK into an rsa.PublicKey
func parseRSAKey(jwk JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode RSA exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// parseECKey parses an EC JWK into an ecdsa.PublicKey
func parseECKey(jwk JWK) (*ecdsa.PublicKey, error) {
	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC X: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to decode EC Y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// VerifyJWT verifies a JWT signature using the JWKS cache
func VerifyJWT(tokenString string, cache *JWKSCache) error {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid JWT format: expected 3 parts, got %d", len(parts))
	}

	// Parse header to get kid and alg
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("failed to parse JWT header: %w", err)
	}

	if header.Kid == "" {
		return fmt.Errorf("JWT header missing 'kid' field")
	}

	// Get the public key
	pubKey, err := cache.GetKey(header.Kid)
	if err != nil {
		return fmt.Errorf("failed to get signing key: %w", err)
	}

	// Verify signature
	signedContent := parts[0] + "." + parts[1]
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("failed to decode JWT signature: %w", err)
	}

	return verifySignature(header.Alg, pubKey, []byte(signedContent), signature)
}

// verifySignature verifies the JWT signature with the appropriate algorithm
func verifySignature(alg string, key crypto.PublicKey, signedContent, signature []byte) error {
	var hashFunc func() hash.Hash
	var cryptoHash crypto.Hash

	switch alg {
	case "RS256", "ES256":
		hashFunc = sha256.New
		cryptoHash = crypto.SHA256
	case "RS384", "ES384":
		hashFunc = sha512.New384
		cryptoHash = crypto.SHA384
	case "RS512", "ES512":
		hashFunc = sha512.New
		cryptoHash = crypto.SHA512
	default:
		return fmt.Errorf("unsupported algorithm: %s", alg)
	}

	h := hashFunc()
	h.Write(signedContent)
	digest := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, cryptoHash, digest, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, digest, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}
