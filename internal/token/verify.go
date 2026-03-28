package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// TokenResult holds the extracted claims from a validated JWT.
type TokenResult struct {
	Username   string
	Email      string
	Name       string
	Roles      []string
	AllowedIPs []string // IP allowlist from OIDC claim (nil = no restriction)
}

// Validate verifies a JWT access token and extracts claims.
// clientID is enforced against azp or aud and used for role extraction from resource_access.
// ipClaim is an optional JWT claim key containing allowed IPs/CIDRs (empty = skip).
func Validate(accessToken string, keys map[string]crypto.PublicKey, issuer, clientID, roleClaim, ipClaim string) (*TokenResult, error) {
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

	if err := validateClientBinding(claims, clientID); err != nil {
		return nil, err
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
		Roles:    ExtractRoles(claims, clientID, roleClaim),
	}

	// Extract IP allowlist from OIDC claim (if configured)
	if ipClaim != "" {
		if ips := ExtractStringList(claims, ipClaim); ips != nil {
			result.AllowedIPs = ips
		}
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

func validateClientBinding(claims map[string]interface{}, clientID string) error {
	if azp := getStringClaim(claims, "azp"); azp != "" {
		if azp != clientID {
			return fmt.Errorf("invalid authorized party: got %q, want %q", azp, clientID)
		}
		return nil
	}

	aud, ok := claims["aud"]
	if !ok {
		return fmt.Errorf("token missing azp or aud claim")
	}
	if audienceContains(aud, clientID) {
		return nil
	}

	return fmt.Errorf("token audience does not include %q", clientID)
}

func audienceContains(aud interface{}, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []string:
		for _, candidate := range v {
			if candidate == clientID {
				return true
			}
		}
	case []interface{}:
		for _, candidate := range v {
			if s, ok := candidate.(string); ok && s == clientID {
				return true
			}
		}
	}

	return false
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
		if !strings.HasPrefix(alg, "RS") {
			return fmt.Errorf("algorithm %s requires ECDSA key, got RSA", alg)
		}
		return rsa.VerifyPKCS1v15(k, hashFunc, hashed, signature)
	case *ecdsa.PublicKey:
		if !strings.HasPrefix(alg, "ES") {
			return fmt.Errorf("algorithm %s requires RSA key, got ECDSA", alg)
		}
		return verifyECDSAJWSSignature(alg, k, hashed, signature)
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

func verifyECDSAJWSSignature(alg string, key *ecdsa.PublicKey, hashed, signature []byte) error {
	partSize, err := ecdsaCoordinateSize(alg)
	if err != nil {
		return err
	}
	if len(signature) != partSize*2 {
		return fmt.Errorf("invalid ECDSA signature length: got %d, want %d", len(signature), partSize*2)
	}

	r := new(big.Int).SetBytes(signature[:partSize])
	s := new(big.Int).SetBytes(signature[partSize:])
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return fmt.Errorf("invalid ECDSA signature values")
	}
	if !ecdsa.Verify(key, hashed, r, s) {
		return fmt.Errorf("ECDSA signature verification failed")
	}

	return nil
}

func ecdsaCoordinateSize(alg string) (int, error) {
	switch alg {
	case "ES256":
		return 32, nil
	case "ES384":
		return 48, nil
	case "ES512":
		return 66, nil
	default:
		return 0, fmt.Errorf("unsupported algorithm: %s", alg)
	}
}
