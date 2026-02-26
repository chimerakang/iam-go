package iam

import "context"

// TokenVerifier verifies authentication tokens and extracts claims.
// Implementations: jwks/ (JWT via JWKS), fake/ (testing).
type TokenVerifier interface {
	// Verify validates the token and returns the extracted claims.
	Verify(ctx context.Context, token string) (*Claims, error)
}

// Authorizer checks whether the current user has specific permissions.
// Implementations may cache decisions locally with a configurable TTL.
type Authorizer interface {
	// Check returns true if the current user has the given permission.
	Check(ctx context.Context, permission string) (bool, error)

	// CheckResource returns true if the current user can perform the action on the resource.
	CheckResource(ctx context.Context, resource, action string) (bool, error)

	// GetPermissions returns all permissions for the current user.
	GetPermissions(ctx context.Context) ([]string, error)
}

// UserService provides user information.
type UserService interface {
	// GetCurrent returns the currently authenticated user.
	GetCurrent(ctx context.Context) (*User, error)

	// Get returns a user by ID.
	Get(ctx context.Context, userID string) (*User, error)

	// List returns users with pagination.
	List(ctx context.Context, opts ListOptions) ([]*User, int, error)

	// GetRoles returns the roles assigned to a user.
	GetRoles(ctx context.Context, userID string) ([]Role, error)
}

// TenantService manages tenant resolution and membership.
type TenantService interface {
	// Resolve looks up a tenant by slug or subdomain.
	Resolve(ctx context.Context, identifier string) (*Tenant, error)

	// ValidateMembership returns true if the user belongs to the tenant.
	ValidateMembership(ctx context.Context, userID, tenantID string) (bool, error)
}

// SessionService manages user sessions.
type SessionService interface {
	// List returns all active sessions for the current user.
	List(ctx context.Context) ([]Session, error)

	// Revoke terminates a specific session.
	Revoke(ctx context.Context, sessionID string) error

	// RevokeAllOthers terminates all sessions except the current one.
	RevokeAllOthers(ctx context.Context) error
}

// SecretService manages API key/secret pairs for service-to-service authentication.
type SecretService interface {
	// Create generates a new API key/secret pair.
	Create(ctx context.Context, description string) (*Secret, error)

	// List returns all API keys (secrets are not included).
	List(ctx context.Context) ([]Secret, error)

	// Delete revokes an API key.
	Delete(ctx context.Context, secretID string) error

	// Verify validates an API key/secret pair and returns the associated claims.
	Verify(ctx context.Context, apiKey, apiSecret string) (*Claims, error)

	// Rotate regenerates the secret for an existing API key.
	Rotate(ctx context.Context, secretID string) (*Secret, error)
}
