// +build integration

package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/authz"
	"github.com/chimerakang/iam-go/jwks"
	"github.com/chimerakang/iam-go/secret"
	"github.com/chimerakang/iam-go/tenant"
	"github.com/chimerakang/iam-go/user"
)

// This file demonstrates integration test patterns for iam-go.
// To run these tests, use: go test -tags=integration ./...
//
// Prerequisites:
// - IAM server running at http://localhost:8080
// - JWKS endpoint at http://localhost:8080/.well-known/jwks.json
// - PostgreSQL and Redis running

// Example: JWT verification via JWKS
func TestJWTVerificationViaJWKS(t *testing.T) {
	if os.Getenv("IAM_ENDPOINT") == "" {
		t.Skip("Skipping integration test (IAM_ENDPOINT not set)")
	}

	jwksURL := os.Getenv("IAM_ENDPOINT") + "/.well-known/jwks.json"
	verifier := jwks.NewVerifier(jwksURL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// In a real test, you would:
	// 1. Get a JWT token from the IAM server (via login)
	// 2. Call verifier.Verify(ctx, token)
	// 3. Verify claims match expected user

	_ = verifier // Use verifier in actual test
}

// Example: Multi-tenant isolation
func TestMultiTenantIsolation(t *testing.T) {
	if os.Getenv("IAM_ENDPOINT") == "" {
		t.Skip("Skipping integration test (IAM_ENDPOINT not set)")
	}

	cfg := iam.Config{
		Endpoint: os.Getenv("IAM_ENDPOINT"),
	}

	// Create client with real services pointing to IAM server
	// client, err := iam.NewClient(cfg,
	//     iam.WithTenantService(real_tenant_service),
	//     iam.WithUserService(real_user_service),
	// )

	// Test: User in tenant A should not access tenant B
	// 1. Create two test users in different tenants
	// 2. Attempt cross-tenant access
	// 3. Verify access is denied

	_ = cfg // Use cfg in actual test
}

// Example: API Key authentication
func TestAPIKeyAuthentication(t *testing.T) {
	if os.Getenv("IAM_ENDPOINT") == "" {
		t.Skip("Skipping integration test (IAM_ENDPOINT not set)")
	}

	// In a real test, you would:
	// 1. Create an API key/secret via IAM server
	// 2. Use secret.Service to verify credentials
	// 3. Verify claims returned
}

// Example: Token refresh and revocation
func TestTokenRefreshAndRevocation(t *testing.T) {
	if os.Getenv("IAM_ENDPOINT") == "" {
		t.Skip("Skipping integration test (IAM_ENDPOINT not set)")
	}

	// In a real test, you would:
	// 1. Get initial JWT token
	// 2. Use refresh token to get new JWT
	// 3. Verify old token is revoked
	// 4. Verify new token works
}

// Example: JWKS key rotation
func TestJWKSKeyRotation(t *testing.T) {
	if os.Getenv("IAM_ENDPOINT") == "" {
		t.Skip("Skipping integration test (IAM_ENDPOINT not set)")
	}

	jwksURL := os.Getenv("IAM_ENDPOINT") + "/.well-known/jwks.json"
	verifier := jwks.NewVerifier(jwksURL)

	// In a real test, you would:
	// 1. Verify a token signed with key A
	// 2. Rotate keys on IAM server (A -> B)
	// 3. Verify token signed with key B
	// 4. Verify old tokens still work during transition
	// 5. Verify JWKS auto-refreshed on kid mismatch

	_ = verifier // Use verifier in actual test
}
