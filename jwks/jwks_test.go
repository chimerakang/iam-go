package jwks_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chimerakang/iam-go/jwks"
	"github.com/golang-jwt/jwt/v5"
)

// testSetup creates an RSA key pair and a fake JWKS HTTP server.
func testSetup(t *testing.T, kid string) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := jwksServer(t, kid, &privateKey.PublicKey)
	return privateKey, server
}

func jwksServer(t *testing.T, kid string, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": kid,
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
}

func signToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	s, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestVerify_ValidToken(t *testing.T) {
	kid := "key-1"
	privKey, server := testSetup(t, kid)
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	now := time.Now()
	tokenStr := signToken(t, privKey, kid, jwt.MapClaims{
		"sub":       "user-123",
		"tenant_id": "tenant-456",
		"iss":       "test-issuer",
		"roles":     []string{"admin", "editor"},
		"exp":       now.Add(1 * time.Hour).Unix(),
		"iat":       now.Unix(),
		"email":     "test@example.com",
	})

	claims, err := verifier.Verify(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("Verify() unexpected error: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-123")
	}
	if claims.TenantID != "tenant-456" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "tenant-456")
	}
	if claims.Issuer != "test-issuer" {
		t.Errorf("Issuer = %q, want %q", claims.Issuer, "test-issuer")
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "admin" || claims.Roles[1] != "editor" {
		t.Errorf("Roles = %v, want [admin editor]", claims.Roles)
	}
	if claims.Extra["email"] != "test@example.com" {
		t.Errorf("Extra[email] = %v, want test@example.com", claims.Extra["email"])
	}
	if claims.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero")
	}
	if claims.IssuedAt.IsZero() {
		t.Error("IssuedAt should not be zero")
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	kid := "key-1"
	privKey, server := testSetup(t, kid)
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	tokenStr := signToken(t, privKey, kid, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
	})

	_, err := verifier.Verify(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("Verify() expected error for expired token, got nil")
	}
}

func TestVerify_InvalidSignature(t *testing.T) {
	kid := "key-1"
	_, server := testSetup(t, kid)
	defer server.Close()

	// Sign with a DIFFERENT key not in JWKS
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	verifier := jwks.NewVerifier(server.URL)

	tokenStr := signToken(t, otherKey, kid, jwt.MapClaims{
		"sub": "user-123",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err = verifier.Verify(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("Verify() expected error for invalid signature, got nil")
	}
}

func TestVerify_KidMismatchTriggersRefresh(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Server starts with key "key-1", then switches to "key-2"
	var currentKid atomic.Value
	currentKid.Store("key-1")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kid := currentKid.Load().(string)
		resp := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"use": "sig",
					"kid": kid,
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	// First verify with key-1
	tokenStr := signToken(t, privKey, "key-1", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	if _, err := verifier.Verify(context.Background(), tokenStr); err != nil {
		t.Fatalf("first Verify() error: %v", err)
	}

	// Server rotates to key-2
	currentKid.Store("key-2")

	// Token signed with key-2 should trigger refresh and succeed
	tokenStr2 := signToken(t, privKey, "key-2", jwt.MapClaims{
		"sub": "user-2",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	claims, err := verifier.Verify(context.Background(), tokenStr2)
	if err != nil {
		t.Fatalf("second Verify() after rotation error: %v", err)
	}
	if claims.Subject != "user-2" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-2")
	}
}

func TestVerify_NoKid(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	server := jwksServer(t, "the-key", &privKey.PublicKey)
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	// Token without kid header
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "user-no-kid",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	// Don't set kid
	tokenStr, err := token.SignedString(privKey)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.Verify(context.Background(), tokenStr)
	if err != nil {
		t.Fatalf("Verify() without kid error: %v", err)
	}
	if claims.Subject != "user-no-kid" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-no-kid")
	}
}

func TestVerify_ServerDown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tokenStr := signToken(t, privKey, "key-1", jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	_, err := verifier.Verify(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("Verify() expected error when JWKS server returns 500, got nil")
	}
}

func TestVerify_UnsupportedSigningMethod(t *testing.T) {
	kid := "key-1"
	_, server := testSetup(t, kid)
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL)

	// Create an HMAC-signed token (not RSA)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})
	tokenStr, err := token.SignedString([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = verifier.Verify(context.Background(), tokenStr)
	if err == nil {
		t.Fatal("Verify() expected error for HS256 token, got nil")
	}
}

func TestVerify_CustomRefreshInterval(t *testing.T) {
	kid := "key-1"
	privKey, server := testSetup(t, kid)
	defer server.Close()

	verifier := jwks.NewVerifier(server.URL, jwks.WithRefreshInterval(50*time.Millisecond))

	tokenStr := signToken(t, privKey, kid, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	})

	// First call — fetches keys
	if _, err := verifier.Verify(context.Background(), tokenStr); err != nil {
		t.Fatalf("first Verify() error: %v", err)
	}

	// Wait for cache to expire
	time.Sleep(60 * time.Millisecond)

	// Second call — should re-fetch (stale cache)
	if _, err := verifier.Verify(context.Background(), tokenStr); err != nil {
		t.Fatalf("second Verify() after refresh interval error: %v", err)
	}
}
