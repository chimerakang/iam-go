package tenant

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
)

// mockBackend implements Backend for testing
type mockBackend struct {
	tenants            map[string]*iam.Tenant
	memberships        map[string]map[string]bool // userID -> tenantID -> bool
	resolveCalls       int
	membershipCalls    int
	shouldFailResolve  bool
	shouldFailMember   bool
}

func (m *mockBackend) Resolve(ctx context.Context, identifier string) (*iam.Tenant, error) {
	m.resolveCalls++
	if m.shouldFailResolve {
		return nil, errors.New("resolve failed")
	}
	if tenant, ok := m.tenants[identifier]; ok {
		return tenant, nil
	}
	return nil, fmt.Errorf("tenant not found: %s", identifier)
}

func (m *mockBackend) ValidateMembership(ctx context.Context, userID, tenantID string) (bool, error) {
	m.membershipCalls++
	if m.shouldFailMember {
		return false, errors.New("membership check failed")
	}
	if userTenants, ok := m.memberships[userID]; ok {
		return userTenants[tenantID], nil
	}
	return false, nil
}

func TestResolve_Success(t *testing.T) {
	backend := &mockBackend{
		tenants: map[string]*iam.Tenant{
			"acme": {ID: "tenant123", Slug: "acme", Status: "active"},
		},
	}
	svc := New(backend)

	tenant, err := svc.Resolve(context.Background(), "acme")

	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if tenant.ID != "tenant123" {
		t.Errorf("expected tenant123, got %s", tenant.ID)
	}
	if backend.resolveCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backend.resolveCalls)
	}
}

func TestResolve_Cached(t *testing.T) {
	backend := &mockBackend{
		tenants: map[string]*iam.Tenant{
			"acme": {ID: "tenant123", Slug: "acme", Status: "active"},
		},
	}
	svc := New(backend)

	// First call
	_, _ = svc.Resolve(context.Background(), "acme")
	// Second call (should be cached)
	_, _ = svc.Resolve(context.Background(), "acme")

	if backend.resolveCalls != 1 {
		t.Errorf("expected 1 backend call (cached), got %d", backend.resolveCalls)
	}
}

func TestResolve_NotFound(t *testing.T) {
	backend := &mockBackend{tenants: make(map[string]*iam.Tenant)}
	svc := New(backend)

	_, err := svc.Resolve(context.Background(), "unknown")

	if err == nil {
		t.Fatal("expected error for unknown tenant")
	}
}

func TestResolve_NotFound_Cached(t *testing.T) {
	backend := &mockBackend{tenants: make(map[string]*iam.Tenant)}
	svc := New(backend)

	// First call (not found)
	_, _ = svc.Resolve(context.Background(), "unknown")
	// Second call (should be cached)
	_, _ = svc.Resolve(context.Background(), "unknown")

	if backend.resolveCalls != 1 {
		t.Errorf("expected 1 backend call (negative cached), got %d", backend.resolveCalls)
	}
}

func TestResolve_TTLExpiration(t *testing.T) {
	backend := &mockBackend{
		tenants: map[string]*iam.Tenant{
			"acme": {ID: "tenant123", Slug: "acme", Status: "active"},
		},
	}
	svc := New(backend, WithTTL(100*time.Millisecond))

	// First call
	_, _ = svc.Resolve(context.Background(), "acme")
	// Wait for TTL to expire
	time.Sleep(150 * time.Millisecond)
	// Second call (should hit backend again)
	_, _ = svc.Resolve(context.Background(), "acme")

	if backend.resolveCalls != 2 {
		t.Errorf("expected 2 backend calls (after TTL), got %d", backend.resolveCalls)
	}
}

func TestValidateMembership_Success(t *testing.T) {
	backend := &mockBackend{
		memberships: map[string]map[string]bool{
			"user123": {"tenant456": true},
		},
	}
	svc := New(backend)

	ok, err := svc.ValidateMembership(context.Background(), "user123", "tenant456")

	if err != nil {
		t.Fatalf("ValidateMembership returned error: %v", err)
	}
	if !ok {
		t.Error("expected true for valid membership")
	}
	if backend.membershipCalls != 1 {
		t.Errorf("expected 1 backend call, got %d", backend.membershipCalls)
	}
}

func TestValidateMembership_Denied(t *testing.T) {
	backend := &mockBackend{
		memberships: map[string]map[string]bool{
			"user123": {"tenant456": false},
		},
	}
	svc := New(backend)

	ok, err := svc.ValidateMembership(context.Background(), "user123", "tenant456")

	if err != nil {
		t.Fatalf("ValidateMembership returned error: %v", err)
	}
	if ok {
		t.Error("expected false for denied membership")
	}
}

func TestValidateMembership_Cached(t *testing.T) {
	backend := &mockBackend{
		memberships: map[string]map[string]bool{
			"user123": {"tenant456": true},
		},
	}
	svc := New(backend)

	// First call
	_, _ = svc.ValidateMembership(context.Background(), "user123", "tenant456")
	// Second call (should be cached)
	_, _ = svc.ValidateMembership(context.Background(), "user123", "tenant456")

	if backend.membershipCalls != 1 {
		t.Errorf("expected 1 backend call (cached), got %d", backend.membershipCalls)
	}
}

func TestValidateMembership_MultipleUsers(t *testing.T) {
	backend := &mockBackend{
		memberships: map[string]map[string]bool{
			"user1": {"tenant1": true},
			"user2": {"tenant1": false},
		},
	}
	svc := New(backend)

	// Different users should not share cache
	_, _ = svc.ValidateMembership(context.Background(), "user1", "tenant1")
	_, _ = svc.ValidateMembership(context.Background(), "user2", "tenant1")

	if backend.membershipCalls != 2 {
		t.Errorf("expected 2 backend calls (different users), got %d", backend.membershipCalls)
	}
}

func TestResolve_EmptyIdentifier(t *testing.T) {
	backend := &mockBackend{tenants: make(map[string]*iam.Tenant)}
	svc := New(backend)

	_, err := svc.Resolve(context.Background(), "")

	if err == nil {
		t.Fatal("expected error for empty identifier")
	}
}

func TestValidateMembership_EmptyParameters(t *testing.T) {
	backend := &mockBackend{}
	svc := New(backend)

	_, err := svc.ValidateMembership(context.Background(), "", "tenant")

	if err == nil {
		t.Fatal("expected error for empty userID")
	}

	_, err = svc.ValidateMembership(context.Background(), "user", "")

	if err == nil {
		t.Fatal("expected error for empty tenantID")
	}
}

func TestClearCache(t *testing.T) {
	backend := &mockBackend{
		tenants: map[string]*iam.Tenant{
			"acme": {ID: "tenant123", Slug: "acme", Status: "active"},
		},
	}
	svc := New(backend)

	// Populate cache
	_, _ = svc.Resolve(context.Background(), "acme")
	// Clear cache
	svc.ClearCache()
	// Next call should hit backend
	_, _ = svc.Resolve(context.Background(), "acme")

	if backend.resolveCalls != 2 {
		t.Errorf("expected 2 backend calls (after clear), got %d", backend.resolveCalls)
	}
}

func TestErrorWrapping(t *testing.T) {
	backend := &mockBackend{
		tenants:          make(map[string]*iam.Tenant),
		shouldFailResolve: true,
	}
	svc := New(backend)

	_, err := svc.Resolve(context.Background(), "acme")

	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, fmt.Errorf("iam/tenant: resolve failed")) {
		// Check if error message contains expected prefix
		if errMsg := err.Error(); errMsg[:11] != "iam/tenant:" {
			t.Errorf("expected error wrapped with 'iam/tenant:', got: %s", errMsg)
		}
	}
}
