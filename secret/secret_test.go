package secret_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/secret"
)

// mockBackend is a simple in-memory backend for testing.
type mockBackend struct {
	secrets map[string]*iam.Secret // secretID -> Secret
	claims  map[string]*iam.Claims  // apiKey:apiSecret -> Claims
	nextID  int
}

func (m *mockBackend) CreateSecret(ctx context.Context, description string) (*iam.Secret, error) {
	m.nextID++
	s := &iam.Secret{
		ID:          fmt.Sprintf("sec-%d", m.nextID),
		APIKey:      fmt.Sprintf("api_key_%d", m.nextID),
		APISecret:   fmt.Sprintf("sk_live_%d", m.nextID),
		Description: description,
		CreatedAt:   time.Now(),
	}
	m.secrets[s.ID] = s

	// Store claims for verification
	key := s.APIKey + ":" + s.APISecret
	m.claims[key] = &iam.Claims{
		Subject:  "user-1",
		TenantID: "tenant-1",
	}

	return s, nil
}

func (m *mockBackend) ListSecrets(ctx context.Context) ([]iam.Secret, error) {
	var result []iam.Secret
	for _, s := range m.secrets {
		// Copy without APISecret
		copy := *s
		copy.APISecret = "" // Don't return secret
		result = append(result, copy)
	}
	return result, nil
}

func (m *mockBackend) DeleteSecret(ctx context.Context, secretID string) error {
	if _, ok := m.secrets[secretID]; !ok {
		return fmt.Errorf("secret not found")
	}
	delete(m.secrets, secretID)
	return nil
}

func (m *mockBackend) VerifySecret(ctx context.Context, apiKey, apiSecret string) (*iam.Claims, error) {
	key := apiKey + ":" + apiSecret
	if claims, ok := m.claims[key]; ok {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid api key/secret")
}

func (m *mockBackend) RotateSecret(ctx context.Context, secretID string) (*iam.Secret, error) {
	s, ok := m.secrets[secretID]
	if !ok {
		return nil, fmt.Errorf("secret not found")
	}

	// Store old claims for the new secret
	oldKey := s.APIKey + ":" + s.APISecret
	oldClaims := m.claims[oldKey]

	// Generate new secret
	m.nextID++
	newSecret := fmt.Sprintf("sk_live_%d", m.nextID)
	s.APISecret = newSecret
	s.CreatedAt = time.Now()

	// Update claims mapping for new secret
	newKey := s.APIKey + ":" + newSecret
	m.claims[newKey] = oldClaims

	// Delete old mapping
	delete(m.claims, oldKey)

	return s, nil
}

func newMockBackend() *mockBackend {
	return &mockBackend{
		secrets: make(map[string]*iam.Secret),
		claims:  make(map[string]*iam.Claims),
	}
}

func TestCreate(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()
	s, err := svc.Create(ctx, "test-key")
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}

	if s.ID == "" {
		t.Error("Create() should return an ID")
	}
	if s.APIKey == "" {
		t.Error("Create() should return an API Key")
	}
	if s.APISecret == "" {
		t.Error("Create() should return an API Secret")
	}
	if s.Description != "test-key" {
		t.Errorf("Description = %q, want %q", s.Description, "test-key")
	}
}

func TestList(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Create two secrets
	s1, _ := svc.Create(ctx, "key-1")
	s2, _ := svc.Create(ctx, "key-2")

	// List
	secrets, err := svc.List(ctx)
	if err != nil {
		t.Fatalf("List() error: %v", err)
	}

	if len(secrets) != 2 {
		t.Errorf("List() returned %d secrets, expected 2", len(secrets))
	}

	// Verify secrets don't contain APISecret
	for _, s := range secrets {
		if s.APISecret != "" {
			t.Error("List() should not return APISecret")
		}
	}

	// Verify IDs are present
	found := map[string]bool{}
	for _, s := range secrets {
		found[s.ID] = true
	}
	if !found[s1.ID] || !found[s2.ID] {
		t.Error("List() should contain both created secrets")
	}
}

func TestDelete(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Create a secret
	s, _ := svc.Create(ctx, "to-delete")

	// Delete it
	err := svc.Delete(ctx, s.ID)
	if err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	// List should be empty
	secrets, _ := svc.List(ctx)
	if len(secrets) != 0 {
		t.Errorf("After Delete(), list should be empty, got %d", len(secrets))
	}
}

func TestDelete_NotFound(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Delete non-existent secret
	err := svc.Delete(ctx, "non-existent")
	if err == nil {
		t.Fatal("Delete() expected error for non-existent secret")
	}
}

func TestVerify(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Create a secret
	s, _ := svc.Create(ctx, "to-verify")

	// Verify with correct credentials
	claims, err := svc.Verify(ctx, s.APIKey, s.APISecret)
	if err != nil {
		t.Fatalf("Verify() error: %v", err)
	}

	if claims == nil {
		t.Fatal("Verify() should return claims")
	}
	if claims.Subject != "user-1" {
		t.Errorf("Subject = %q, want %q", claims.Subject, "user-1")
	}
	if claims.TenantID != "tenant-1" {
		t.Errorf("TenantID = %q, want %q", claims.TenantID, "tenant-1")
	}
}

func TestVerify_Invalid(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Verify with invalid credentials
	_, err := svc.Verify(ctx, "invalid-key", "invalid-secret")
	if err == nil {
		t.Fatal("Verify() expected error for invalid credentials")
	}
}

func TestRotate(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Create a secret
	s, _ := svc.Create(ctx, "to-rotate")
	oldSecret := s.APISecret

	// Rotate
	rotated, err := svc.Rotate(ctx, s.ID)
	if err != nil {
		t.Fatalf("Rotate() error: %v", err)
	}

	if rotated.APISecret == oldSecret {
		t.Error("Rotate() should generate a new secret")
	}

	// Verify new secret works
	claims, err := svc.Verify(ctx, rotated.APIKey, rotated.APISecret)
	if err != nil {
		t.Errorf("Verify() with rotated secret error: %v", err)
	}
	if claims == nil {
		t.Error("Verify() should return claims for rotated secret")
	}

	// Old secret should not work
	_, err = svc.Verify(ctx, s.APIKey, oldSecret)
	if err == nil {
		t.Error("Old secret should not verify after rotation")
	}
}

func TestRotate_NotFound(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Rotate non-existent secret
	_, err := svc.Rotate(ctx, "non-existent")
	if err == nil {
		t.Fatal("Rotate() expected error for non-existent secret")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that errors from backend are properly wrapped with "iam/secret:" prefix
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// Try to delete non-existent secret
	err := svc.Delete(ctx, "non-existent")
	if err == nil {
		t.Fatal("Delete() expected error")
	}

	// Check error message contains "iam/secret:"
	if errMsg := err.Error(); errMsg != "iam/secret: delete: secret not found" {
		t.Errorf("Error message = %q, expected to contain iam/secret: prefix", errMsg)
	}
}

func TestCRUDLifecycle(t *testing.T) {
	backend := newMockBackend()
	svc := secret.New(backend)

	ctx := context.Background()

	// 1. Create
	s1, _ := svc.Create(ctx, "first-key")
	s2, _ := svc.Create(ctx, "second-key")

	// 2. List
	secrets, _ := svc.List(ctx)
	if len(secrets) != 2 {
		t.Fatalf("After create, expected 2 secrets, got %d", len(secrets))
	}

	// 3. Verify
	claims1, _ := svc.Verify(ctx, s1.APIKey, s1.APISecret)
	if claims1 == nil {
		t.Fatal("Should be able to verify first secret")
	}

	// 4. Rotate
	s1rotated, _ := svc.Rotate(ctx, s1.ID)

	// 5. Verify rotated
	claimsRotated, _ := svc.Verify(ctx, s1rotated.APIKey, s1rotated.APISecret)
	if claimsRotated == nil {
		t.Fatal("Should be able to verify rotated secret")
	}

	// 6. Delete
	svc.Delete(ctx, s2.ID)

	// 7. List again
	secrets, _ = svc.List(ctx)
	if len(secrets) != 1 {
		t.Fatalf("After delete, expected 1 secret, got %d", len(secrets))
	}
	if secrets[0].ID != s1.ID {
		t.Errorf("Remaining secret should be s1, got %v", secrets[0].ID)
	}
}
