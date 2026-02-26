package session

import (
	"context"
	"errors"
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
)

// mockBackend implements Backend for testing
type mockBackend struct {
	sessions       []iam.Session
	revokedSessions map[string]bool
	shouldFailList bool
	shouldFailRevoke bool
}

func (m *mockBackend) List(ctx context.Context) ([]iam.Session, error) {
	if m.shouldFailList {
		return nil, errors.New("list sessions failed")
	}
	return m.sessions, nil
}

func (m *mockBackend) Revoke(ctx context.Context, sessionID string) error {
	if m.shouldFailRevoke {
		return errors.New("revoke session failed")
	}
	m.revokedSessions[sessionID] = true
	return nil
}

func (m *mockBackend) RevokeAllOthers(ctx context.Context) error {
	if m.shouldFailRevoke {
		return errors.New("revoke all others failed")
	}
	// Mark all sessions as revoked (simulating revoke all except current)
	for _, session := range m.sessions {
		m.revokedSessions[session.ID] = true
	}
	return nil
}

func TestList_Success(t *testing.T) {
	sessions := []iam.Session{
		{ID: "sess1", UserID: "user123", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess2", UserID: "user123", ExpiresAt: time.Now().Add(2 * time.Hour)},
	}
	backend := &mockBackend{
		sessions: sessions,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	result, err := svc.List(context.Background())

	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(result) != 2 {
		t.Errorf("expected 2 sessions, got %d", len(result))
	}
	if result[0].ID != "sess1" {
		t.Errorf("expected sess1, got %s", result[0].ID)
	}
}

func TestList_Empty(t *testing.T) {
	backend := &mockBackend{
		sessions: []iam.Session{},
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	result, err := svc.List(context.Background())

	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 sessions, got %d", len(result))
	}
}

func TestList_Failed(t *testing.T) {
	backend := &mockBackend{
		shouldFailList: true,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	_, err := svc.List(context.Background())

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRevoke_Success(t *testing.T) {
	backend := &mockBackend{revokedSessions: make(map[string]bool)}
	svc := New(backend)

	err := svc.Revoke(context.Background(), "sess123")

	if err != nil {
		t.Fatalf("Revoke returned error: %v", err)
	}
	if !backend.revokedSessions["sess123"] {
		t.Error("session should be marked as revoked")
	}
}

func TestRevoke_EmptySessionID(t *testing.T) {
	backend := &mockBackend{revokedSessions: make(map[string]bool)}
	svc := New(backend)

	err := svc.Revoke(context.Background(), "")

	if err == nil {
		t.Fatal("expected error for empty sessionID")
	}
}

func TestRevoke_Failed(t *testing.T) {
	backend := &mockBackend{
		shouldFailRevoke: true,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	err := svc.Revoke(context.Background(), "sess123")

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestRevokeAllOthers_Success(t *testing.T) {
	sessions := []iam.Session{
		{ID: "sess1", UserID: "user123", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess2", UserID: "user123", ExpiresAt: time.Now().Add(2 * time.Hour)},
		{ID: "sess3", UserID: "user123", ExpiresAt: time.Now().Add(3 * time.Hour)},
	}
	backend := &mockBackend{
		sessions: sessions,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	err := svc.RevokeAllOthers(context.Background())

	if err != nil {
		t.Fatalf("RevokeAllOthers returned error: %v", err)
	}
	// All sessions should be marked as revoked
	for _, session := range sessions {
		if !backend.revokedSessions[session.ID] {
			t.Errorf("session %s should be revoked", session.ID)
		}
	}
}

func TestRevokeAllOthers_Failed(t *testing.T) {
	backend := &mockBackend{
		shouldFailRevoke: true,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	err := svc.RevokeAllOthers(context.Background())

	if err == nil {
		t.Fatal("expected error")
	}
}

func TestErrorWrapping(t *testing.T) {
	backend := &mockBackend{
		shouldFailRevoke: true,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	err := svc.Revoke(context.Background(), "sess123")

	if err == nil {
		t.Fatal("expected error")
	}
	// Check if error message contains expected prefix
	errMsg := err.Error()
	if len(errMsg) < 11 || errMsg[:11] != "iam/session" {
		t.Errorf("expected error wrapped with 'iam/session:', got: %s", errMsg)
	}
}

func TestCRUDLifecycle(t *testing.T) {
	sessions := []iam.Session{
		{ID: "sess1", UserID: "user123", ExpiresAt: time.Now().Add(1 * time.Hour)},
		{ID: "sess2", UserID: "user123", ExpiresAt: time.Now().Add(2 * time.Hour)},
	}
	backend := &mockBackend{
		sessions: sessions,
		revokedSessions: make(map[string]bool),
	}
	svc := New(backend)

	// List all sessions
	result, err := svc.List(context.Background())
	if err != nil || len(result) != 2 {
		t.Fatal("failed to list sessions")
	}

	// Revoke one session
	err = svc.Revoke(context.Background(), "sess1")
	if err != nil {
		t.Fatal("failed to revoke session")
	}

	// RevokeAllOthers
	err = svc.RevokeAllOthers(context.Background())
	if err != nil {
		t.Fatal("failed to revoke all others")
	}

	// Verify all sessions are revoked
	if !backend.revokedSessions["sess1"] || !backend.revokedSessions["sess2"] {
		t.Error("all sessions should be revoked")
	}
}
