// Package session provides SessionService implementation.
package session

import (
	"context"
	"fmt"

	iam "github.com/chimerakang/iam-go"
)

// Backend defines the contract for pluggable session service backends (gRPC, REST, etc.).
type Backend interface {
	// List returns all active sessions for the current user.
	List(ctx context.Context) ([]iam.Session, error)

	// Revoke terminates a specific session.
	Revoke(ctx context.Context, sessionID string) error

	// RevokeAllOthers terminates all sessions except the current one.
	RevokeAllOthers(ctx context.Context) error
}

// Service implements iam.SessionService with a configurable backend.
type Service struct {
	backend Backend
}

// New creates a new SessionService with the given backend.
func New(backend Backend) *Service {
	return &Service{backend: backend}
}

// List returns all active sessions for the current user.
func (s *Service) List(ctx context.Context) ([]iam.Session, error) {
	sessions, err := s.backend.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam/session: %w", err)
	}
	return sessions, nil
}

// Revoke terminates a specific session.
func (s *Service) Revoke(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return fmt.Errorf("iam/session: sessionID cannot be empty")
	}

	err := s.backend.Revoke(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("iam/session: %w", err)
	}
	return nil
}

// RevokeAllOthers terminates all sessions except the current one.
func (s *Service) RevokeAllOthers(ctx context.Context) error {
	err := s.backend.RevokeAllOthers(ctx)
	if err != nil {
		return fmt.Errorf("iam/session: %w", err)
	}
	return nil
}
