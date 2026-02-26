package user

import (
	"context"
	"errors"
	"testing"

	iam "github.com/chimerakang/iam-go"
)

// mockBackend implements Backend for testing
type mockBackend struct {
	currentUser *iam.User
	users       map[string]*iam.User
	userRoles   map[string][]iam.Role
	shouldFail  bool
}

func (m *mockBackend) GetCurrent(ctx context.Context) (*iam.User, error) {
	if m.shouldFail {
		return nil, errors.New("get current failed")
	}
	if m.currentUser == nil {
		return nil, errors.New("no current user")
	}
	return m.currentUser, nil
}

func (m *mockBackend) Get(ctx context.Context, userID string) (*iam.User, error) {
	if m.shouldFail {
		return nil, errors.New("get user failed")
	}
	user, ok := m.users[userID]
	if !ok {
		return nil, errors.New("user not found")
	}
	return user, nil
}

func (m *mockBackend) List(ctx context.Context, opts iam.ListOptions) ([]*iam.User, int, error) {
	if m.shouldFail {
		return nil, 0, errors.New("list users failed")
	}
	users := make([]*iam.User, 0, len(m.users))
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, len(users), nil
}

func (m *mockBackend) GetRoles(ctx context.Context, userID string) ([]iam.Role, error) {
	if m.shouldFail {
		return nil, errors.New("get roles failed")
	}
	roles, ok := m.userRoles[userID]
	if !ok {
		return []iam.Role{}, nil
	}
	return roles, nil
}

func TestGetCurrent_Success(t *testing.T) {
	user := &iam.User{ID: "user123", Email: "alice@example.com"}
	backend := &mockBackend{currentUser: user}
	svc := New(backend)

	result, err := svc.GetCurrent(context.Background())

	if err != nil {
		t.Fatalf("GetCurrent returned error: %v", err)
	}
	if result.ID != "user123" {
		t.Errorf("expected user123, got %s", result.ID)
	}
}

func TestGetCurrent_Failed(t *testing.T) {
	backend := &mockBackend{shouldFail: true}
	svc := New(backend)

	_, err := svc.GetCurrent(context.Background())

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGet_Success(t *testing.T) {
	user := &iam.User{ID: "user123", Email: "alice@example.com"}
	backend := &mockBackend{
		users: map[string]*iam.User{
			"user123": user,
		},
	}
	svc := New(backend)

	result, err := svc.Get(context.Background(), "user123")

	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if result.ID != "user123" {
		t.Errorf("expected user123, got %s", result.ID)
	}
}

func TestGet_NotFound(t *testing.T) {
	backend := &mockBackend{users: make(map[string]*iam.User)}
	svc := New(backend)

	_, err := svc.Get(context.Background(), "unknown")

	if err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestGet_EmptyUserID(t *testing.T) {
	backend := &mockBackend{}
	svc := New(backend)

	_, err := svc.Get(context.Background(), "")

	if err == nil {
		t.Fatal("expected error for empty userID")
	}
}

func TestList_Success(t *testing.T) {
	users := map[string]*iam.User{
		"user1": {ID: "user1", Email: "alice@example.com"},
		"user2": {ID: "user2", Email: "bob@example.com"},
	}
	backend := &mockBackend{users: users}
	svc := New(backend)

	result, total, err := svc.List(context.Background(), iam.ListOptions{})

	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 users, got %d", len(result))
	}
}

func TestList_Empty(t *testing.T) {
	backend := &mockBackend{users: make(map[string]*iam.User)}
	svc := New(backend)

	result, total, err := svc.List(context.Background(), iam.ListOptions{})

	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if total != 0 {
		t.Errorf("expected total 0, got %d", total)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 users, got %d", len(result))
	}
}

func TestList_Failed(t *testing.T) {
	backend := &mockBackend{shouldFail: true}
	svc := New(backend)

	_, _, err := svc.List(context.Background(), iam.ListOptions{})

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetRoles_Success(t *testing.T) {
	roles := []iam.Role{
		{ID: "role1", Name: "admin"},
		{ID: "role2", Name: "user"},
	}
	backend := &mockBackend{
		userRoles: map[string][]iam.Role{
			"user123": roles,
		},
	}
	svc := New(backend)

	result, err := svc.GetRoles(context.Background(), "user123")

	if err != nil {
		t.Fatalf("GetRoles returned error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 roles, got %d", len(result))
	}
	if result[0].Name != "admin" {
		t.Errorf("expected admin, got %s", result[0].Name)
	}
}

func TestGetRoles_NoRoles(t *testing.T) {
	backend := &mockBackend{userRoles: make(map[string][]iam.Role)}
	svc := New(backend)

	result, err := svc.GetRoles(context.Background(), "user123")

	if err != nil {
		t.Fatalf("GetRoles returned error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 roles, got %d", len(result))
	}
}

func TestGetRoles_EmptyUserID(t *testing.T) {
	backend := &mockBackend{}
	svc := New(backend)

	_, err := svc.GetRoles(context.Background(), "")

	if err == nil {
		t.Fatal("expected error for empty userID")
	}
}

func TestGetRoles_Failed(t *testing.T) {
	backend := &mockBackend{shouldFail: true}
	svc := New(backend)

	_, err := svc.GetRoles(context.Background(), "user123")

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestErrorWrapping(t *testing.T) {
	backend := &mockBackend{shouldFail: true}
	svc := New(backend)

	_, err := svc.Get(context.Background(), "user123")

	if err == nil {
		t.Fatal("expected error")
	}
	// Check if error message starts with expected prefix
	if errMsg := err.Error(); errMsg[:9] != "iam/user:" {
		t.Errorf("expected error wrapped with 'iam/user:', got: %s", errMsg)
	}
}
