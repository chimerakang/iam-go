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
