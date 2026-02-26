package fake_test

import (
	"context"
	"testing"

	"github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
)

func setup() *iam.Client {
	return fake.NewClient(
		fake.WithUser("u1", "t1", "alice@example.com", []string{"admin", "editor"}),
		fake.WithUser("u2", "t1", "bob@example.com", []string{"viewer"}),
		fake.WithUser("u3", "t2", "carol@example.com", []string{"admin"}),
		fake.WithTenant("t1", "acme", "active"),
		fake.WithTenant("t2", "globex", "active"),
		fake.WithPermissions("u1", []string{"users:read", "users:write", "records:read"}),
		fake.WithPermissions("u2", []string{"records:read"}),
		fake.WithAPIKey("ak-1", "sk-1", "u1"),
	)
}

func ctxAs(userID string) context.Context {
	return fake.ContextWithUserID(context.Background(), userID)
}

// --- TokenVerifier ---

func TestVerifier_ValidToken(t *testing.T) {
	c := setup()
	// Fake verifier treats token string as userID
	claims, err := c.Verifier().Verify(context.Background(), "u1")
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "u1")
	}
	if claims.TenantID != "t1" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "t1")
	}
	if len(claims.Roles) != 2 {
		t.Errorf("Roles = %v, want 2 roles", claims.Roles)
	}
}

func TestVerifier_UnknownToken(t *testing.T) {
	c := setup()
	_, err := c.Verifier().Verify(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Verify() expected error for unknown token")
	}
}

// --- Authorizer ---

func TestAuthorizer_Check(t *testing.T) {
	c := setup()

	tests := []struct {
		user string
		perm string
		want bool
	}{
		{"u1", "users:read", true},
		{"u1", "users:write", true},
		{"u1", "users:delete", false},
		{"u2", "records:read", true},
		{"u2", "users:read", false},
		{"u3", "anything", false}, // u3 has no permissions configured
	}

	for _, tt := range tests {
		got, err := c.Authz().Check(ctxAs(tt.user), tt.perm)
		if err != nil {
			t.Errorf("Check(%q, %q) error: %v", tt.user, tt.perm, err)
			continue
		}
		if got != tt.want {
			t.Errorf("Check(%q, %q) = %v, want %v", tt.user, tt.perm, got, tt.want)
		}
	}
}

func TestAuthorizer_CheckResource(t *testing.T) {
	c := setup()

	got, err := c.Authz().CheckResource(ctxAs("u1"), "users", "read")
	if err != nil {
		t.Fatalf("CheckResource() error: %v", err)
	}
	if !got {
		t.Error("CheckResource(u1, users, read) = false, want true")
	}
}

func TestAuthorizer_GetPermissions(t *testing.T) {
	c := setup()

	perms, err := c.Authz().GetPermissions(ctxAs("u1"))
	if err != nil {
		t.Fatalf("GetPermissions() error: %v", err)
	}
	if len(perms) != 3 {
		t.Errorf("GetPermissions(u1) returned %d perms, want 3", len(perms))
	}
}

// --- UserService ---

func TestUserService_Get(t *testing.T) {
	c := setup()

	user, err := c.Users().Get(context.Background(), "u1")
	if err != nil {
		t.Fatalf("Get() error: %v", err)
	}
	if user.Email != "alice@example.com" {
		t.Errorf("Email = %q, want %q", user.Email, "alice@example.com")
	}
}

func TestUserService_GetNotFound(t *testing.T) {
	c := setup()

	_, err := c.Users().Get(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Get() expected error for nonexistent user")
	}
}

func TestUserService_GetCurrent(t *testing.T) {
	c := setup()

	user, err := c.Users().GetCurrent(ctxAs("u2"))
	if err != nil {
		t.Fatalf("GetCurrent() error: %v", err)
	}
	if user.ID != "u2" {
		t.Errorf("ID = %q, want %q", user.ID, "u2")
	}
}

func TestUserService_List(t *testing.T) {
	c := setup()

	users, total, err := c.Users().List(context.Background(), iam.ListOptions{Page: 1, PageSize: 2})
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	if total != 3 {
		t.Errorf("total = %d, want 3", total)
	}
	if len(users) != 2 {
		t.Errorf("len(users) = %d, want 2 (page size)", len(users))
	}
}

func TestUserService_GetRoles(t *testing.T) {
	c := setup()

	roles, err := c.Users().GetRoles(context.Background(), "u1")
	if err != nil {
		t.Fatalf("GetRoles() error: %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("len(roles) = %d, want 2", len(roles))
	}
}

// --- TenantService ---

func TestTenantService_ResolveByID(t *testing.T) {
	c := setup()

	tenant, err := c.Tenants().Resolve(context.Background(), "t1")
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if tenant.Slug != "acme" {
		t.Errorf("Slug = %q, want %q", tenant.Slug, "acme")
	}
}

func TestTenantService_ResolveBySlug(t *testing.T) {
	c := setup()

	tenant, err := c.Tenants().Resolve(context.Background(), "globex")
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if tenant.ID != "t2" {
		t.Errorf("ID = %q, want %q", tenant.ID, "t2")
	}
}

func TestTenantService_ResolveNotFound(t *testing.T) {
	c := setup()

	_, err := c.Tenants().Resolve(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("Resolve() expected error for nonexistent tenant")
	}
}

func TestTenantService_ValidateMembership(t *testing.T) {
	c := setup()

	tests := []struct {
		user, tenant string
		want         bool
	}{
		{"u1", "t1", true},
		{"u1", "t2", false},
		{"u3", "t2", true},
		{"nonexistent", "t1", false},
	}

	for _, tt := range tests {
		got, err := c.Tenants().ValidateMembership(context.Background(), tt.user, tt.tenant)
		if err != nil {
			t.Errorf("ValidateMembership(%q, %q) error: %v", tt.user, tt.tenant, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ValidateMembership(%q, %q) = %v, want %v", tt.user, tt.tenant, got, tt.want)
		}
	}
}

// --- SecretService ---

func TestSecretService_Verify(t *testing.T) {
	c := setup()

	claims, err := c.Secrets().Verify(context.Background(), "ak-1", "sk-1")
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}
	if claims.Subject != "u1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "u1")
	}
}

func TestSecretService_VerifyInvalid(t *testing.T) {
	c := setup()

	_, err := c.Secrets().Verify(context.Background(), "ak-1", "wrong-secret")
	if err == nil {
		t.Fatal("Verify() expected error for wrong secret")
	}
}

func TestSecretService_CreateAndList(t *testing.T) {
	c := setup()

	secret, err := c.Secrets().Create(context.Background(), "test service")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if secret.APIKey == "" || secret.APISecret == "" {
		t.Error("Create() should return both APIKey and APISecret")
	}
	if secret.Description != "test service" {
		t.Errorf("Description = %q, want %q", secret.Description, "test service")
	}

	list, err := c.Secrets().List(context.Background())
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}
	// Should have original ak-1 + newly created
	if len(list) != 2 {
		t.Errorf("List() returned %d secrets, want 2", len(list))
	}
	// List should not expose APISecret
	for _, s := range list {
		if s.APISecret != "" {
			t.Error("List() should not expose APISecret")
		}
	}
}

func TestSecretService_Delete(t *testing.T) {
	c := setup()

	secret, _ := c.Secrets().Create(context.Background(), "to-delete")
	err := c.Secrets().Delete(context.Background(), secret.ID)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// Verify it's gone
	_, err = c.Secrets().Verify(context.Background(), secret.APIKey, secret.APISecret)
	if err == nil {
		t.Fatal("Verify() should fail after Delete()")
	}
}

func TestSecretService_Rotate(t *testing.T) {
	c := setup()

	secret, _ := c.Secrets().Create(context.Background(), "rotate-me")
	oldSecret := secret.APISecret

	rotated, err := c.Secrets().Rotate(context.Background(), secret.ID)
	if err != nil {
		t.Fatalf("Rotate() error: %v", err)
	}
	if rotated.APISecret == oldSecret {
		t.Error("Rotate() should return a new APISecret")
	}
	if rotated.APISecret == "" {
		t.Error("Rotate() should return the new APISecret")
	}
}
