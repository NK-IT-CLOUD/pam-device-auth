package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// TokenResult holds the extracted claims from a validated JWT.
type TokenResult struct {
	Username string
	Email    string
	Name     string
	Roles    []string
}

// Validate verifies a JWT access token and extracts claims.
// clientID is used for azp validation and role extraction from resource_access.
func Validate(accessToken string, keys map[string]crypto.PublicKey, issuer, clientID string) (*TokenResult, error) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT: expected 3 parts, got %d", len(parts))
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("parse JWT header: %w", err)
	}

	// Get public key
	key, ok := keys[header.Kid]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", header.Kid)
	}

	// Verify signature
	signedContent := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode JWT signature: %w", err)
	}
	if err := verifySignature(header.Alg, key, signedContent, signature); err != nil {
		return nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse JWT claims: %w", err)
	}

	// Validate issuer
	if iss, _ := claims["iss"].(string); iss != issuer {
		return nil, fmt.Errorf("invalid issuer: got %q, want %q", iss, issuer)
	}

	// Validate expiry
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, fmt.Errorf("token missing exp claim")
	}
	if time.Now().Unix() > int64(exp) {
		return nil, fmt.Errorf("token expired")
	}

	// Validate not-before
	if nbf, ok := claims["nbf"].(float64); ok {
		if time.Now().Unix() < int64(nbf) {
			return nil, fmt.Errorf("token not yet valid (nbf)")
		}
	}

	// Extract claims
	result := &TokenResult{
		Username: getStringClaim(claims, "preferred_username"),
		Email:    getStringClaim(claims, "email"),
		Name:     getStringClaim(claims, "name"),
		Roles:    ExtractRoles(claims, clientID),
	}

	if result.Username == "" {
		return nil, fmt.Errorf("token missing preferred_username claim")
	}

	return result, nil
}

func getStringClaim(claims map[string]interface{}, key string) string {
	if v, ok := claims[key].(string); ok {
		return v
	}
	return ""
}

func hashForAlgorithm(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "ES512":
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}

func verifySignature(alg string, key crypto.PublicKey, signedContent, signature []byte) error {
	hashFunc, err := hashForAlgorithm(alg)
	if err != nil {
		return err
	}

	h := hashFunc.New()
	h.Write(signedContent)
	hashed := h.Sum(nil)

	switch k := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(k, hashFunc, hashed, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(k, hashed, signature) {
			return fmt.Errorf("ECDSA signature verification failed")
		}
		return nil
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}
