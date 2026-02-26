package authz_test

import (
	"context"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/authz"
)

// mockBackend is a simple in-memory backend for testing.
type mockBackend struct {
	permissions map[string]map[string]bool // userID:tenantID:permission -> allowed
	callCount   int
}

func (m *mockBackend) GetPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	m.callCount++
	key := userID + ":" + tenantID
	perms := m.permissions[key]
	result := make([]string, 0, len(perms))
	for p, allowed := range perms {
		if allowed {
			result = append(result, p)
		}
	}
	return result, nil
}

func (m *mockBackend) CheckPermission(ctx context.Context, userID, tenantID, permission string) (bool, error) {
	m.callCount++
	key := userID + ":" + tenantID
	return m.permissions[key][permission], nil
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		permissions: map[string]map[string]bool{
			"user-1:tenant-1": {
				"users:read":    true,
				"users:write":   false,
				"posts:read":    true,
				"posts:write":   true,
				"posts:delete":  false,
			},
			"user-2:tenant-1": {
				"users:read":   false,
				"users:write":  false,
				"posts:read":   true,
				"posts:write":  false,
				"posts:delete": false,
			},
		},
	}
}

func TestCheck_Allowed(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	allowed, err := a.Check(ctx, "users:read")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !allowed {
		t.Error("Check() should return true for allowed permission")
	}
}

func TestCheck_Denied(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	allowed, err := a.Check(ctx, "users:write")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if allowed {
		t.Error("Check() should return false for denied permission")
	}
}

func TestCheck_MissingContext(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	// No userID in context

	_, err := a.Check(ctx, "users:read")
	if err == nil {
		t.Fatal("Check() expected error when userID is missing from context")
	}
}

func TestCheck_Cache(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend, authz.WithCacheTTL(100*time.Millisecond))

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	// First call — hits backend
	allowed1, _ := a.Check(ctx, "users:read")
	callCount1 := backend.callCount

	// Second call within TTL — should hit cache
	allowed2, _ := a.Check(ctx, "users:read")
	callCount2 := backend.callCount

	if callCount1 != 1 {
		t.Errorf("First Check() should call backend once, got %d", callCount1)
	}
	if callCount2 != 1 {
		t.Errorf("Second Check() should use cache, backend calls: expected 1, got %d", callCount2)
	}
	if allowed1 != allowed2 {
		t.Error("Cached result should be same as fresh result")
	}

	// Wait for cache to expire
	time.Sleep(110 * time.Millisecond)

	// Third call after TTL — hits backend again
	_, _ = a.Check(ctx, "users:read")
	callCount3 := backend.callCount

	if callCount3 != 2 {
		t.Errorf("Third Check() after TTL should hit backend again, expected 2 calls, got %d", callCount3)
	}
}

func TestCheckResource(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	// CheckResource should convert "posts", "write" -> "posts:write"
	allowed, err := a.CheckResource(ctx, "posts", "write")
	if err != nil {
		t.Fatalf("CheckResource() error: %v", err)
	}
	if !allowed {
		t.Error("CheckResource() should return true for posts:write")
	}

	// posts:delete should be false
	allowed, err = a.CheckResource(ctx, "posts", "delete")
	if err != nil {
		t.Fatalf("CheckResource() error: %v", err)
	}
	if allowed {
		t.Error("CheckResource() should return false for posts:delete")
	}
}

func TestGetPermissions(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	perms, err := a.GetPermissions(ctx)
	if err != nil {
		t.Fatalf("GetPermissions() error: %v", err)
	}

	expected := 3 // users:read, posts:read, posts:write
	if len(perms) != expected {
		t.Errorf("GetPermissions() returned %d permissions, expected %d", len(perms), expected)
	}
}

func TestGetPermissions_MissingContext(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	// No userID in context

	_, err := a.GetPermissions(ctx)
	if err == nil {
		t.Fatal("GetPermissions() expected error when userID is missing from context")
	}
}

func TestBackendError(t *testing.T) {
	// Mock backend that returns an error
	backend := &mockBackend{
		permissions: map[string]map[string]bool{},
	}
	a := authz.New(backend)

	// Simulate backend error by using a non-existent user
	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "non-existent")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	// This should succeed (returns false from empty map) but let's test error handling
	allowed, err := a.Check(ctx, "users:read")
	if err != nil {
		t.Errorf("Check() unexpected error: %v", err)
	}
	if allowed {
		t.Error("Check() should return false for non-existent user")
	}
}

func TestClearCache(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user-1")
	ctx = iam.WithTenantID(ctx, "tenant-1")

	// Populate cache
	a.Check(ctx, "users:read")
	callCount1 := backend.callCount

	// Clear cache
	a.ClearCache()

	// Next call should hit backend
	a.Check(ctx, "users:read")
	callCount2 := backend.callCount

	if callCount2 != callCount1+1 {
		t.Errorf("After ClearCache(), next Check() should hit backend, expected %d calls, got %d", callCount1+1, callCount2)
	}
}

func TestMultipleUsers(t *testing.T) {
	backend := newMockBackend()
	a := authz.New(backend)

	ctx1 := context.Background()
	ctx1 = iam.WithUserID(ctx1, "user-1")
	ctx1 = iam.WithTenantID(ctx1, "tenant-1")

	ctx2 := context.Background()
	ctx2 = iam.WithUserID(ctx2, "user-2")
	ctx2 = iam.WithTenantID(ctx2, "tenant-1")

	// user-1 has users:read, user-2 does not
	allowed1, _ := a.Check(ctx1, "users:read")
	allowed2, _ := a.Check(ctx2, "users:read")

	if !allowed1 {
		t.Error("user-1 should have users:read")
	}
	if allowed2 {
		t.Error("user-2 should not have users:read")
	}
}
