// Package jwks provides a TokenVerifier implementation using JWKS (JSON Web Key Set).
//
// It fetches RSA public keys from a standard JWKS endpoint (RFC 7517), caches them
// locally, and verifies JWT signatures (RS256) without calling the IAM server.
// Compatible with any OIDC-compliant identity provider.
package jwks

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/golang-jwt/jwt/v5"
)

// Verifier implements iam.TokenVerifier using JWKS public keys.
type Verifier struct {
	jwksURL         string
	httpClient      *http.Client
	refreshInterval time.Duration

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey // kid → public key
	lastFetch time.Time
}

// compile-time check
var _ iam.TokenVerifier = (*Verifier)(nil)

// Option configures the Verifier.
type Option func(*Verifier)

// WithHTTPClient sets a custom HTTP client for fetching JWKS.
func WithHTTPClient(c *http.Client) Option {
	return func(v *Verifier) { v.httpClient = c }
}

// WithRefreshInterval sets how often cached keys are refreshed.
// Default: 1 hour.
func WithRefreshInterval(d time.Duration) Option {
	return func(v *Verifier) { v.refreshInterval = d }
}

// NewVerifier creates a new JWKS-based token verifier.
func NewVerifier(jwksURL string, opts ...Option) *Verifier {
	v := &Verifier{
		jwksURL:         jwksURL,
		httpClient:      http.DefaultClient,
		refreshInterval: 1 * time.Hour,
		keys:            make(map[string]*rsa.PublicKey),
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify validates a JWT token string and returns the extracted claims.
func (v *Verifier) Verify(ctx context.Context, tokenString string) (*iam.Claims, error) {
	parser := jwt.NewParser(jwt.WithExpirationRequired())

	token, err := parser.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		kid, _ := token.Header["kid"].(string)
		return v.getKey(ctx, kid)
	})
	if err != nil {
		return nil, fmt.Errorf("iam/jwks: %w", err)
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("iam/jwks: invalid token claims")
	}

	return mapToIAMClaims(mapClaims), nil
}

// getKey returns the RSA public key for the given kid, fetching/refreshing as needed.
func (v *Verifier) getKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	v.mu.RLock()
	key, found := v.keys[kid]
	stale := time.Since(v.lastFetch) > v.refreshInterval
	v.mu.RUnlock()

	if found && !stale {
		return key, nil
	}

	// Fetch fresh keys (kid mismatch or cache expired)
	if err := v.refresh(ctx); err != nil {
		if found {
			return key, nil // use stale key if refresh fails
		}
		return nil, err
	}

	v.mu.RLock()
	defer v.mu.RUnlock()

	if key, ok := v.keys[kid]; ok {
		return key, nil
	}

	// No kid specified — use the first available key
	if kid == "" {
		for _, k := range v.keys {
			return k, nil
		}
	}

	return nil, fmt.Errorf("iam/jwks: key not found for kid %q", kid)
}

// refresh fetches the JWKS from the configured URL and updates the cache.
func (v *Verifier) refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.jwksURL, nil)
	if err != nil {
		return fmt.Errorf("iam/jwks: create request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("iam/jwks: fetch: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("iam/jwks: fetch returned status %d", resp.StatusCode)
	}

	var jwksResp jwksResponse
	if err := json.NewDecoder(resp.Body).Decode(&jwksResp); err != nil {
		return fmt.Errorf("iam/jwks: decode: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwksResp.Keys))
	for _, jwk := range jwksResp.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") {
			continue
		}
		pub, err := jwk.rsaPublicKey()
		if err != nil {
			continue // skip malformed keys
		}
		keys[jwk.Kid] = pub
	}

	if len(keys) == 0 {
		return fmt.Errorf("iam/jwks: no valid RSA signing keys found")
	}

	v.mu.Lock()
	v.keys = keys
	v.lastFetch = time.Now()
	v.mu.Unlock()

	return nil
}

// JWKS JSON types

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (k *jwkKey) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}, nil
}

// mapToIAMClaims converts jwt.MapClaims to iam.Claims.
func mapToIAMClaims(m jwt.MapClaims) *iam.Claims {
	c := &iam.Claims{
		Extra: make(map[string]any),
	}

	if v, ok := m["sub"].(string); ok {
		c.Subject = v
	}
	if v, ok := m["tenant_id"].(string); ok {
		c.TenantID = v
	}
	if v, ok := m["email"].(string); ok {
		c.Email = v
	}
	if v, ok := m["iss"].(string); ok {
		c.Issuer = v
	}
	if v, ok := m["exp"].(float64); ok {
		c.ExpiresAt = time.Unix(int64(v), 0)
	}
	if v, ok := m["iat"].(float64); ok {
		c.IssuedAt = time.Unix(int64(v), 0)
	}
	if roles, ok := m["roles"].([]interface{}); ok {
		for _, r := range roles {
			if s, ok := r.(string); ok {
				c.Roles = append(c.Roles, s)
			}
		}
	}

	// Non-standard claims go to Extra
	standard := map[string]bool{
		"sub": true, "tenant_id": true, "email": true,
		"iss": true, "exp": true, "iat": true, "roles": true,
		"aud": true, "nbf": true, "jti": true,
	}
	for k, v := range m {
		if !standard[k] {
			c.Extra[k] = v
		}
	}

	return c
}
