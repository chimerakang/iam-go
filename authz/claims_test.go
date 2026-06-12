package authz_test

import (
	"context"
	"testing"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/authz"
)

// stubAuthorizer records whether it was called.
type stubAuthorizer struct {
	called  bool
	allowed bool
	perms   []string
}

func (s *stubAuthorizer) Check(ctx context.Context, permission string) (bool, error) {
	s.called = true
	return s.allowed, nil
}

func (s *stubAuthorizer) CheckResource(ctx context.Context, resource, action string) (bool, error) {
	s.called = true
	return s.allowed, nil
}

func (s *stubAuthorizer) GetPermissions(ctx context.Context) ([]string, error) {
	s.called = true
	return s.perms, nil
}

func ctxWithPermissions(perms []string, extra map[string]any) context.Context {
	return iam.WithClaims(context.Background(), &iam.Claims{
		Subject:     "user-1",
		TenantID:    "tenant-1",
		Permissions: perms,
		Extra:       extra,
	})
}

func TestClaimsChecker_LocalCheck(t *testing.T) {
	fallback := &stubAuthorizer{}
	checker := authz.NewClaimsChecker(authz.WithFallback(fallback))

	ctx := ctxWithPermissions([]string{"users:read", "orders:*"}, nil)

	tests := []struct {
		permission string
		want       bool
	}{
		{"users:read", true},
		{"users:write", false},
		{"orders:read", true},
		{"orders:read:all", true},
		{"payments:read", false},
	}
	for _, tt := range tests {
		got, err := checker.Check(ctx, tt.permission)
		if err != nil {
			t.Fatalf("Check(%q) error: %v", tt.permission, err)
		}
		if got != tt.want {
			t.Errorf("Check(%q) = %v, want %v", tt.permission, got, tt.want)
		}
	}
	if fallback.called {
		t.Error("fallback should not be called when permissions are embedded")
	}
}

func TestClaimsChecker_EmptyPermissionsIsLocalDeny(t *testing.T) {
	fallback := &stubAuthorizer{allowed: true}
	checker := authz.NewClaimsChecker(authz.WithFallback(fallback))

	// Empty (non-nil) permissions = issuer says user has none.
	ctx := ctxWithPermissions([]string{}, nil)

	ok, err := checker.Check(ctx, "users:read")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if ok {
		t.Error("Check() = true, want false for empty embedded permissions")
	}
	if fallback.called {
		t.Error("fallback should not be called for empty (non-nil) permissions")
	}
}

func TestClaimsChecker_FallbackWhenNoEmbeddedPermissions(t *testing.T) {
	fallback := &stubAuthorizer{allowed: true}
	checker := authz.NewClaimsChecker(authz.WithFallback(fallback))

	// nil permissions = issuer did not embed the claim.
	ctx := ctxWithPermissions(nil, nil)

	ok, err := checker.Check(ctx, "users:read")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !ok {
		t.Error("Check() = false, want fallback's true")
	}
	if !fallback.called {
		t.Error("fallback should be called when permissions are not embedded")
	}
}

func TestClaimsChecker_FallbackWhenDegraded(t *testing.T) {
	fallback := &stubAuthorizer{allowed: true}
	checker := authz.NewClaimsChecker(authz.WithFallback(fallback))

	ctx := ctxWithPermissions([]string{"users:read"},
		map[string]any{authz.DefaultDegradedFlag: true})

	ok, err := checker.Check(ctx, "anything:else")
	if err != nil {
		t.Fatalf("Check() error: %v", err)
	}
	if !ok || !fallback.called {
		t.Error("degraded claims should route to fallback")
	}
}

func TestClaimsChecker_NoFallbackErrors(t *testing.T) {
	checker := authz.NewClaimsChecker()

	if _, err := checker.Check(context.Background(), "users:read"); err == nil {
		t.Error("Check() without claims or fallback expected error")
	}
	if _, err := checker.GetPermissions(context.Background()); err == nil {
		t.Error("GetPermissions() without claims or fallback expected error")
	}
}

func TestClaimsChecker_CheckResource(t *testing.T) {
	checker := authz.NewClaimsChecker()
	ctx := ctxWithPermissions([]string{"users:*"}, nil)

	ok, err := checker.CheckResource(ctx, "users", "write")
	if err != nil {
		t.Fatalf("CheckResource() error: %v", err)
	}
	if !ok {
		t.Error("CheckResource(users, write) = false, want true via users:*")
	}
}

func TestClaimsChecker_GetPermissions(t *testing.T) {
	checker := authz.NewClaimsChecker()
	ctx := ctxWithPermissions([]string{"a:b", "c:d"}, nil)

	perms, err := checker.GetPermissions(ctx)
	if err != nil {
		t.Fatalf("GetPermissions() error: %v", err)
	}
	if len(perms) != 2 || perms[0] != "a:b" || perms[1] != "c:d" {
		t.Errorf("GetPermissions() = %v", perms)
	}
}

func TestMatchPermission(t *testing.T) {
	tests := []struct {
		granted, required string
		want              bool
	}{
		{"users:read", "users:read", true},
		{"users:read", "users:write", false},
		{"users:*", "users:read", true},
		{"users:*", "users:read:all", true},
		{"users:*", "orders:read", false},
		{"*", "anything:at:all", true},
		{"users:*:read", "users:profile:read", true},
		{"users:*:read", "users:profile:write", false},
		{"users:read:all", "users:read", false}, // pattern longer than required
		{"users", "users:read", false},          // no wildcard, prefix only
	}
	for _, tt := range tests {
		if got := authz.MatchPermission(tt.granted, tt.required); got != tt.want {
			t.Errorf("MatchPermission(%q, %q) = %v, want %v", tt.granted, tt.required, got, tt.want)
		}
	}
}

func TestAuthorizer_Invalidate(t *testing.T) {
	backend := &countingBackend{allowed: true}
	a := authz.New(backend)

	ctx := iam.WithUserID(context.Background(), "u1")
	ctx = iam.WithTenantID(ctx, "t1")

	// Prime the cache.
	if _, err := a.Check(ctx, "users:read"); err != nil {
		t.Fatal(err)
	}
	if backend.checks != 1 {
		t.Fatalf("backend.checks = %d, want 1", backend.checks)
	}

	// Cached — no new backend call.
	if _, err := a.Check(ctx, "users:read"); err != nil {
		t.Fatal(err)
	}
	if backend.checks != 1 {
		t.Fatalf("backend.checks = %d, want 1 (cached)", backend.checks)
	}

	// Invalidate for the wrong tenant — still cached.
	a.Invalidate("u1", "other-tenant")
	if _, err := a.Check(ctx, "users:read"); err != nil {
		t.Fatal(err)
	}
	if backend.checks != 1 {
		t.Fatalf("backend.checks = %d, want 1 (other-tenant invalidation must not evict)", backend.checks)
	}

	// Invalidate the right user+tenant — next check hits the backend.
	a.Invalidate("u1", "t1")
	if _, err := a.Check(ctx, "users:read"); err != nil {
		t.Fatal(err)
	}
	if backend.checks != 2 {
		t.Fatalf("backend.checks = %d, want 2 (invalidated)", backend.checks)
	}

	// InvalidateUser evicts across tenants.
	a.InvalidateUser("u1")
	if _, err := a.Check(ctx, "users:read"); err != nil {
		t.Fatal(err)
	}
	if backend.checks != 3 {
		t.Fatalf("backend.checks = %d, want 3 (user-wide invalidation)", backend.checks)
	}
}

type countingBackend struct {
	allowed bool
	checks  int
}

func (b *countingBackend) CheckPermission(ctx context.Context, userID, tenantID, permission string) (bool, error) {
	b.checks++
	return b.allowed, nil
}

func (b *countingBackend) GetPermissions(ctx context.Context, userID, tenantID string) ([]string, error) {
	return nil, nil
}
