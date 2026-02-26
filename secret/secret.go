// Package secret provides a client-side implementation of iam.SecretService.
//
// It communicates with the IAM server's SecretService API to manage API keys/secrets.
// Supports both gRPC and REST backends via a configurable Backend interface.
package secret

import (
	"context"
	"fmt"

	iam "github.com/chimerakang/iam-go"
)

// Backend defines how to communicate with the IAM server's SecretService.
// Implementations can use gRPC, REST, or any other protocol.
type Backend interface {
	// CreateSecret generates a new API key/secret pair.
	CreateSecret(ctx context.Context, description string) (*iam.Secret, error)

	// ListSecrets returns all API keys for the authenticated user.
	ListSecrets(ctx context.Context) ([]iam.Secret, error)

	// DeleteSecret revokes an API key.
	DeleteSecret(ctx context.Context, secretID string) error

	// VerifySecret validates an API key/secret pair and returns associated claims.
	VerifySecret(ctx context.Context, apiKey, apiSecret string) (*iam.Claims, error)

	// RotateSecret regenerates the secret for an existing API key.
	RotateSecret(ctx context.Context, secretID string) (*iam.Secret, error)
}

// Service implements iam.SecretService using a backend client.
type Service struct {
	backend Backend
}

// compile-time check
var _ iam.SecretService = (*Service)(nil)

// New creates a new SecretService with the given backend.
func New(backend Backend) *Service {
	return &Service{backend: backend}
}

// Create generates a new API key/secret pair.
func (s *Service) Create(ctx context.Context, description string) (*iam.Secret, error) {
	secret, err := s.backend.CreateSecret(ctx, description)
	if err != nil {
		return nil, fmt.Errorf("iam/secret: create: %w", err)
	}
	return secret, nil
}

// List returns all API keys (secrets are not included).
func (s *Service) List(ctx context.Context) ([]iam.Secret, error) {
	secrets, err := s.backend.ListSecrets(ctx)
	if err != nil {
		return nil, fmt.Errorf("iam/secret: list: %w", err)
	}
	return secrets, nil
}

// Delete revokes an API key.
func (s *Service) Delete(ctx context.Context, secretID string) error {
	if err := s.backend.DeleteSecret(ctx, secretID); err != nil {
		return fmt.Errorf("iam/secret: delete: %w", err)
	}
	return nil
}

// Verify validates an API key/secret pair and returns the associated claims.
func (s *Service) Verify(ctx context.Context, apiKey, apiSecret string) (*iam.Claims, error) {
	claims, err := s.backend.VerifySecret(ctx, apiKey, apiSecret)
	if err != nil {
		return nil, fmt.Errorf("iam/secret: verify: %w", err)
	}
	return claims, nil
}

// Rotate regenerates the secret for an existing API key.
func (s *Service) Rotate(ctx context.Context, secretID string) (*iam.Secret, error) {
	secret, err := s.backend.RotateSecret(ctx, secretID)
	if err != nil {
		return nil, fmt.Errorf("iam/secret: rotate: %w", err)
	}
	return secret, nil
}
