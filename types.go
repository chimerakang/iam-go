package iam

import "time"

// Claims represents the standard claims extracted from a verified token.
type Claims struct {
	Subject   string
	TenantID  string
	Roles     []string
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

// Secret represents an API key/secret pair for service-to-service authentication.
type Secret struct {
	ID          string
	APIKey      string
	APISecret   string // Only populated on Create or Rotate.
	Description string
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// ListOptions holds pagination parameters.
type ListOptions struct {
	Page     int
	PageSize int
}
