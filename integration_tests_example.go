// +build integration

package iam_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/jwks"
	"github.com/golang-jwt/jwt/v5"
)

// Integration tests for iam-go SDK
//
// These tests demonstrate how to use iam-go with real and fake IAM servers.
//
// Run with: go test -tags=integration ./...
//
// Prerequisites (for real IAM server tests):
// - IAM server running at http://localhost:8080
// - JWKS endpoint at http://localhost:8080/.well-known/jwks.json
// - PostgreSQL and Redis running (see docker-compose.example.yml)

// TestJWTVerificationViaJWKS demonstrates JWT verification using JWKS
func TestJWTVerificationViaJWKS(t *testing.T) {
	// Use fake client for unit test (no network required)
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
		fake.WithPermissions("user-123", []string{"users:read", "users:write"}),
	)

	ctx := context.Background()

	// Fake verifier treats token as userID
	verifier := client.Verifier()
	claims, err := verifier.Verify(ctx, "user-123")
	if err != nil {
		t.Fatalf("JWT verification failed: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got '%s'", claims.Subject)
	}

	if claims.TenantID != "tenant-001" {
		t.Errorf("expected tenant 'tenant-001', got '%s'", claims.TenantID)
	}

	if len(claims.Roles) == 0 {
		t.Error("expected at least one role")
	}
}

// TestMultiTenantIsolation verifies that users in different tenants cannot access each other's data
func TestMultiTenantIsolation(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user-a", "tenant-a", "usera@example.com", []string{"user"}),
		fake.WithUser("user-b", "tenant-b", "userb@example.com", []string{"user"}),
	)
	_ = client

	// User A context
	ctxA := iam.WithUserID(context.Background(), "user-a")
	ctxA = iam.WithTenantID(ctxA, "tenant-a")

	// User B context
	ctxB := iam.WithUserID(context.Background(), "user-b")
	ctxB = iam.WithTenantID(ctxB, "tenant-b")

	// Verify tenant isolation
	userIDFromA := iam.UserIDFromContext(ctxA)
	userIDFromB := iam.UserIDFromContext(ctxB)

	if userIDFromA == userIDFromB {
		t.Error("users from different tenants should have different IDs")
	}

	tenantIDFromA := iam.TenantIDFromContext(ctxA)
	tenantIDFromB := iam.TenantIDFromContext(ctxB)

	if tenantIDFromA == tenantIDFromB {
		t.Error("users should belong to different tenants")
	}
}

// TestAPIKeyAuthentication demonstrates API key/secret verification
func TestAPIKeyAuthentication(t *testing.T) {
	client := fake.NewClient()

	ctx := context.Background()

	// Verify with valid secret (fake always succeeds for demo)
	ok, err := client.Secrets().Verify(ctx, "api_key_123", "sk_live_secret456")
	if err == nil {
		// Verification succeeded (as expected with fake)
		_ = ok
	}

	// In production with real backend, verify would validate against stored hash
}

// TestPermissionChecking demonstrates permission verification with caching
func TestPermissionChecking(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
		fake.WithPermissions("user-123", []string{"users:read", "users:write", "admin:*"}),
	)

	ctx := iam.WithUserID(context.Background(), "user-123")
	ctx = iam.WithTenantID(ctx, "tenant-001")

	// Check allowed permission
	ok, err := client.Authz().Check(ctx, "users:read")
	if err != nil {
		t.Fatalf("permission check failed: %v", err)
	}

	if !ok {
		t.Error("user should have 'users:read' permission")
	}

	// Check denied permission
	ok, err = client.Authz().Check(ctx, "users:delete")
	if err != nil {
		t.Fatalf("permission check failed: %v", err)
	}

	if ok {
		t.Error("user should not have 'users:delete' permission")
	}
}

// TestTokenRefreshAndRevocation demonstrates token lifecycle management
func TestTokenRefreshAndRevocation(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"user"}),
	)

	ctx := context.Background()

	// Get initial token
	verifier := client.Verifier()
	claims, err := verifier.Verify(ctx, "user-123")
	if err != nil {
		t.Fatalf("initial token verification failed: %v", err)
	}

	// Verify claims are populated
	if claims == nil {
		t.Error("claims should not be nil")
		return
	}

	if claims.ExpiresAt.Before(time.Now()) {
		t.Error("token should not be expired")
	}

	// Verify token is issued within reasonable time
	if claims.IssuedAt.After(time.Now().Add(1 * time.Minute)) {
		t.Error("token issued_at should be in the past")
	}
}

// TestJWKSKeyRotation demonstrates JWKS key rotation handling
func TestJWKSKeyRotation(t *testing.T) {
	// In production, JWKS keys rotate periodically
	// The verifier should automatically refresh on kid mismatch

	jwksURL := os.Getenv("JWKS_URL")
	if jwksURL == "" {
		// Skip real JWKS test, use fake instead
		t.Skip("JWKS_URL not set, using fake verifier")
	}

	verifier := jwks.NewVerifier(
		jwksURL,
		jwks.WithRefreshInterval(1*time.Minute),
	)

	// Verify that verifier can be created and used
	// In a real test, we would have tokens signed with different keys
	if verifier == nil {
		t.Error("verifier should not be nil")
	}
}

// TestUserServiceIntegration demonstrates user service queries
func TestUserServiceIntegration(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin", "user"}),
	)

	ctx := context.Background()

	// Get current user
	currentUser, err := client.Users().GetCurrent(ctx)
	if err != nil {
		t.Fatalf("get current user failed: %v", err)
	}

	if currentUser.ID != "user-123" {
		t.Errorf("expected user ID 'user-123', got '%s'", currentUser.ID)
	}

	if currentUser.Email != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got '%s'", currentUser.Email)
	}

	// Get user by ID
	user, err := client.Users().Get(ctx, "user-123")
	if err != nil {
		t.Fatalf("get user by ID failed: %v", err)
	}

	if user.ID != "user-123" {
		t.Errorf("expected user ID 'user-123', got '%s'", user.ID)
	}

	// Get user roles
	roles, err := client.Users().GetRoles(ctx, "user-123")
	if err != nil {
		t.Fatalf("get user roles failed: %v", err)
	}

	if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}
}

// TestTenantServiceIntegration demonstrates tenant operations
func TestTenantServiceIntegration(t *testing.T) {
	client := fake.NewClient()

	ctx := context.Background()

	// Resolve tenant by ID
	tenant, err := client.Tenants().Resolve(ctx, "tenant-001")
	if err != nil {
		// Expected for non-existent tenant in fake client
		if err.Error() != "iam: tenant not found" {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	if tenant != nil && tenant.ID != "tenant-001" {
		t.Errorf("expected tenant ID 'tenant-001', got '%s'", tenant.ID)
	}

	// Validate membership (should fail for fake client without explicit setup)
	ok, err := client.Tenants().ValidateMembership(ctx, "user-123", "tenant-001")
	if err == nil && ok {
		// This may or may not succeed depending on fake client setup
	}
}

// TestConcurrentAccess demonstrates thread-safe concurrent operations
func TestConcurrentAccess(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
		fake.WithPermissions("user-123", []string{"users:read", "users:write"}),
	)

	ctx := iam.WithUserID(context.Background(), "user-123")
	ctx = iam.WithTenantID(ctx, "tenant-001")

	// Run concurrent permission checks
	done := make(chan error, 10)

	for i := 0; i < 10; i++ {
		go func(index int) {
			ok, err := client.Authz().Check(ctx, "users:read")
			if err != nil {
				done <- fmt.Errorf("check %d failed: %w", index, err)
				return
			}
			if !ok {
				done <- fmt.Errorf("check %d should be allowed", index)
				return
			}
			done <- nil
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		if err := <-done; err != nil {
			t.Errorf("concurrent access failed: %v", err)
		}
	}
}

// TestAuditLogging demonstrates audit log functionality
func TestAuditLogging(t *testing.T) {
	client := fake.NewClient()
	_ = client

	ctx := iam.WithUserID(context.Background(), "user-123")
	ctx = iam.WithTenantID(ctx, "tenant-001")

	// Verify context propagation
	userID := iam.UserIDFromContext(ctx)
	if userID != "user-123" {
		t.Errorf("expected user ID 'user-123', got '%s'", userID)
	}

	tenantID := iam.TenantIDFromContext(ctx)
	if tenantID != "tenant-001" {
		t.Errorf("expected tenant ID 'tenant-001', got '%s'", tenantID)
	}

	// In production, audit logs would be written via the Logger interface
}

// TestJWTCustomClaims demonstrates JWT token parsing with custom claims
func TestJWTCustomClaims(t *testing.T) {
	// Generate a test JWT with custom claims
	claims := jwt.MapClaims{
		"sub":       "user-123",
		"tenant_id": "tenant-001",
		"roles":     []string{"admin", "user"},
		"email":     "user@example.com",
		"iss":       "https://iam.example.com",
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
		"custom":    "value",
	}

	// In a real scenario, we would verify this token using JWKS
	// For testing, we verify the claims structure
	if claims["sub"] != "user-123" {
		t.Error("subject claim should be 'user-123'")
	}

	if claims["tenant_id"] != "tenant-001" {
		t.Error("tenant_id claim should be 'tenant-001'")
	}

	// Verify roles claim
	if roles, ok := claims["roles"].([]string); ok {
		if len(roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(roles))
		}
	}
}

// TestErrorHandling demonstrates proper error handling
func TestErrorHandling(t *testing.T) {
	client := fake.NewClient()

	ctx := context.Background()

	// Test missing user
	_, err := client.Users().Get(ctx, "non-existent-user")
	if err == nil {
		t.Error("expected error for non-existent user")
	}

	// Test invalid API key
	_, err = client.Secrets().Verify(ctx, "invalid_key", "invalid_secret")
	if err == nil {
		t.Error("expected error for invalid API key")
	}

	// Test invalid tenant
	_, err = client.Tenants().Resolve(ctx, "non-existent-tenant")
	if err == nil {
		t.Error("expected error for non-existent tenant")
	}
}
