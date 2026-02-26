// Package iam provides a framework-agnostic Go SDK for Identity and Access Management.
//
// The SDK defines interfaces for token verification, authorization, user management,
// multi-tenancy, session management, and API key management. Concrete implementations
// are injected via Option functions, making the SDK independent of any specific IAM server.
//
// Example usage with a JWKS-based token verifier:
//
//	client, err := iam.NewClient(
//	    iam.Config{JWKSUrl: "https://auth.example.com/.well-known/jwks.json"},
//	    iam.WithTokenVerifier(myVerifier),
//	    iam.WithAuthorizer(myAuthz),
//	)
package iam

import (
	"fmt"
	"io"
	"log/slog"
	"time"
)

// Client is the main entry point for IAM operations.
// Service implementations are injected via Option functions.
type Client struct {
	config   Config
	logger   *slog.Logger
	verifier TokenVerifier
	authz    Authorizer
	users    UserService
	tenants  TenantService
	sessions SessionService
	secrets  SecretService
}

// Config holds connection and behavior configuration.
type Config struct {
	// Endpoint is the address of the IAM backend service (e.g. gRPC or HTTP).
	Endpoint string

	// JWKSUrl is the URL to fetch JWKS public keys for local JWT verification.
	// Example: "https://auth.example.com/.well-known/jwks.json"
	JWKSUrl string

	// APIKey is the public identifier for service-to-service authentication.
	APIKey string

	// APISecret is the private key for service-to-service authentication.
	APISecret string

	// CacheTTL controls how long permission decisions are cached locally.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// TLSEnabled enables TLS for backend connections.
	TLSEnabled bool

	// TLSCertPath is the path to the TLS certificate file.
	TLSCertPath string
}

// Option configures the Client.
type Option func(*Client)

// WithLogger sets a structured logger for the client.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// WithTokenVerifier sets the token verification implementation.
func WithTokenVerifier(v TokenVerifier) Option {
	return func(c *Client) { c.verifier = v }
}

// WithAuthorizer sets the authorization implementation.
func WithAuthorizer(a Authorizer) Option {
	return func(c *Client) { c.authz = a }
}

// WithUserService sets the user management implementation.
func WithUserService(u UserService) Option {
	return func(c *Client) { c.users = u }
}

// WithTenantService sets the tenant management implementation.
func WithTenantService(t TenantService) Option {
	return func(c *Client) { c.tenants = t }
}

// WithSessionService sets the session management implementation.
func WithSessionService(s SessionService) Option {
	return func(c *Client) { c.sessions = s }
}

// WithSecretService sets the API key management implementation.
func WithSecretService(s SecretService) Option {
	return func(c *Client) { c.secrets = s }
}

// DefaultCacheTTL is the default duration for caching permission decisions.
const DefaultCacheTTL = 5 * time.Minute

// NewClient creates a new IAM client with the given configuration and options.
func NewClient(cfg Config, opts ...Option) (*Client, error) {
	if cfg.Endpoint == "" && cfg.JWKSUrl == "" {
		return nil, fmt.Errorf("iam: at least one of Endpoint or JWKSUrl is required")
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}

	c := &Client{config: cfg}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Config returns the client configuration.
func (c *Client) Config() Config { return c.config }

// Verifier returns the token verifier, or nil if not configured.
func (c *Client) Verifier() TokenVerifier { return c.verifier }

// Authz returns the authorizer, or nil if not configured.
func (c *Client) Authz() Authorizer { return c.authz }

// Users returns the user service, or nil if not configured.
func (c *Client) Users() UserService { return c.users }

// Tenants returns the tenant service, or nil if not configured.
func (c *Client) Tenants() TenantService { return c.tenants }

// Sessions returns the session service, or nil if not configured.
func (c *Client) Sessions() SessionService { return c.sessions }

// Secrets returns the secret service, or nil if not configured.
func (c *Client) Secrets() SecretService { return c.secrets }

// Close releases all resources held by the client.
// Any injected service that implements io.Closer will be closed.
func (c *Client) Close() error {
	closers := []interface{}{
		c.verifier, c.authz, c.users,
		c.tenants, c.sessions, c.secrets,
	}
	var firstErr error
	for _, svc := range closers {
		if cl, ok := svc.(io.Closer); ok && cl != nil {
			if err := cl.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}
