// Package user provides UserService implementation.
package user

import (
	"context"
	"fmt"

	iam "github.com/chimerakang/iam-go"
)

// Backend defines the contract for pluggable user service backends (gRPC, REST, etc.).
type Backend interface {
	// GetCurrent returns the currently authenticated user.
	GetCurrent(ctx context.Context) (*iam.User, error)

	// Get returns a user by ID.
	Get(ctx context.Context, userID string) (*iam.User, error)

	// List returns users with pagination.
	List(ctx context.Context, opts iam.ListOptions) ([]*iam.User, int, error)

	// GetRoles returns the roles assigned to a user.
	GetRoles(ctx context.Context, userID string) ([]iam.Role, error)
}

// Service implements iam.UserService with a configurable backend.
type Service struct {
	backend Backend
}

// New creates a new UserService with the given backend.
func New(backend Backend) *Service {
	return &Service{backend: backend}
}

// GetCurrent returns the currently authenticated user.
func (s *Service) GetCurrent(ctx context.Context) (*iam.User, error) {
	user, err := s.backend.GetCurrent(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam/user: %w", err)
	}
	return user, nil
}

// Get returns a user by ID.
func (s *Service) Get(ctx context.Context, userID string) (*iam.User, error) {
	if userID == "" {
		return nil, fmt.Errorf("iam/user: userID cannot be empty")
	}

	user, err := s.backend.Get(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("iam/user: %w", err)
	}
	return user, nil
}

// List returns users with pagination.
func (s *Service) List(ctx context.Context, opts iam.ListOptions) ([]*iam.User, int, error) {
	users, total, err := s.backend.List(ctx, opts)
	if err != nil {
		return nil, 0, fmt.Errorf("iam/user: %w", err)
	}
	return users, total, nil
}

// GetRoles returns the roles assigned to a user.
func (s *Service) GetRoles(ctx context.Context, userID string) ([]iam.Role, error) {
	if userID == "" {
		return nil, fmt.Errorf("iam/user: userID cannot be empty")
	}

	roles, err := s.backend.GetRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("iam/user: %w", err)
	}
	return roles, nil
}
