// Package tenant provides TenantService implementation with local caching.
package tenant

import (
	"context"
	"fmt"
	"sync"
	"time"

	iam "github.com/chimerakang/iam-go"
)

// Backend defines the contract for pluggable tenant resolution backends (gRPC, REST, etc.).
type Backend interface {
	// Resolve looks up a tenant by slug or subdomain.
	Resolve(ctx context.Context, identifier string) (*iam.Tenant, error)

	// ValidateMembership checks if a user belongs to a tenant.
	ValidateMembership(ctx context.Context, userID, tenantID string) (bool, error)
}

// Service implements iam.TenantService with local caching and configurable backend.
type Service struct {
	backend Backend
	ttl     time.Duration
	cache   sync.Map // key: "resolve:<identifier>" | "member:<userID>:<tenantID>", value: cacheEntry
}

type cacheEntry struct {
	value     interface{}
	expiresAt time.Time
}

// Option configures Service behavior.
type Option func(*Service)

// WithTTL sets cache TTL (default: 5 minutes).
func WithTTL(ttl time.Duration) Option {
	return func(s *Service) {
		s.ttl = ttl
	}
}

// New creates a new TenantService with the given backend and options.
func New(backend Backend, opts ...Option) *Service {
	s := &Service{
		backend: backend,
		ttl:     5 * time.Minute,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Resolve looks up a tenant by slug/identifier with local caching.
func (s *Service) Resolve(ctx context.Context, identifier string) (*iam.Tenant, error) {
	if identifier == "" {
		return nil, fmt.Errorf("iam/tenant: identifier cannot be empty")
	}

	cacheKey := fmt.Sprintf("resolve:%s", identifier)

	// Try cache first
	if cached, ok := s.cache.Load(cacheKey); ok {
		entry := cached.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			if entry.value == nil {
				return nil, fmt.Errorf("iam/tenant: tenant not found (cached)")
			}
			return entry.value.(*iam.Tenant), nil
		}
		// Expired entry, remove it
		s.cache.Delete(cacheKey)
	}

	// Call backend
	tenant, err := s.backend.Resolve(ctx, identifier)
	if err != nil {
		// Cache negative result to avoid repeated lookups
		s.cache.Store(cacheKey, cacheEntry{
			value:     nil,
			expiresAt: time.Now().Add(s.ttl),
		})
		return nil, fmt.Errorf("iam/tenant: %w", err)
	}

	// Cache positive result
	s.cache.Store(cacheKey, cacheEntry{
		value:     tenant,
		expiresAt: time.Now().Add(s.ttl),
	})

	return tenant, nil
}

// ValidateMembership checks if a user belongs to a tenant with local caching.
func (s *Service) ValidateMembership(ctx context.Context, userID, tenantID string) (bool, error) {
	if userID == "" || tenantID == "" {
		return false, fmt.Errorf("iam/tenant: userID and tenantID cannot be empty")
	}

	cacheKey := fmt.Sprintf("member:%s:%s", userID, tenantID)

	// Try cache first
	if cached, ok := s.cache.Load(cacheKey); ok {
		entry := cached.(cacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.value.(bool), nil
		}
		// Expired entry, remove it
		s.cache.Delete(cacheKey)
	}

	// Call backend
	ok, err := s.backend.ValidateMembership(ctx, userID, tenantID)
	if err != nil {
		return false, fmt.Errorf("iam/tenant: %w", err)
	}

	// Cache result
	s.cache.Store(cacheKey, cacheEntry{
		value:     ok,
		expiresAt: time.Now().Add(s.ttl),
	})

	return ok, nil
}

// ClearCache removes all cached entries.
func (s *Service) ClearCache() {
	s.cache.Range(func(key, value interface{}) bool {
		s.cache.Delete(key)
		return true
	})
}
