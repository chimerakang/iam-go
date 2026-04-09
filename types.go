package iam

import "time"

// Claims represents the standard claims extracted from a verified token.
type Claims struct {
	Subject   string
	TenantID  string
	Roles     []string
	Email     string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Issuer    string
	Extra     map[string]any
}

// User represents an authenticated user.
type User struct {
	ID       string
	Email    string
	Name     string
	TenantID string
	Roles    []Role
	Metadata map[string]any
}

// Role represents a named role assigned to a user.
type Role struct {
	ID   string
	Name string
}

// Tenant represents a tenant in a multi-tenant system.
type Tenant struct {
	ID     string
	Name   string
	Slug   string
	Status string
}

// Session represents an active user session.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	UserAgent string
	IP        string
}

// OAuth2Token represents an OAuth2 access token response.
type OAuth2Token struct {
	AccessToken string
	TokenType   string // "Bearer"
	ExpiresIn   int32
	ExpiresAt   time.Time
	Scope       string
}

// ListOptions holds pagination parameters.
type ListOptions struct {
	Page     int
	PageSize int
}

// LoginRequest holds the parameters for user authentication.
type LoginRequest struct {
	Email    string // User email address
	Password string // User password
	TenantID string // Optional tenant ID for multi-tenant systems
	ClientID string // Optional OAuth2 Application client_id (auto-injected by adapters)
}

// LoginResponse contains the result of a successful authentication.
type LoginResponse struct {
	User   *User        // Authenticated user information
	Tokens *TokenPair   // Access and refresh tokens
}

// SocialLoginRequest holds parameters for social OAuth login.
// The caller is responsible for obtaining the id_token from the provider.
// Typical use case: BFF pattern where the backend exchanges the authorization
// code for an id_token (requires client secret), then calls Valhalla to get a JWT.
type SocialLoginRequest struct {
	Provider string // "google", "apple", "line"
	IDToken  string // ID Token from the provider
	Nonce    string // Replay-prevention token (required for Apple, recommended for LINE)
	AppID    string // OAuthClientApp app_identifier (for multi-app OAuth)
	TenantID string // Optional tenant ID
}

// TokenPair holds access and refresh tokens from authentication.
type TokenPair struct {
	AccessToken  string // JWT access token
	RefreshToken string // Refresh token for token renewal
	ExpiresIn    int32  // Token expiry duration in seconds
	TokenType    string // Token type (typically "Bearer")
}
