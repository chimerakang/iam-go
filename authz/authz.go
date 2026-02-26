// Package authz provides a local-caching implementation of iam.Authorizer.
//
// It caches permission decisions in memory to reduce calls to the IAM backend.
// Thread-safe using sync.Map for concurrent access.
package authz

import (
	"context"
	"fmt"
	"sync"
	"time"

	iam "github.com/chimerakang/iam-go"
)

// Backend defines how to fetch permissions from the IAM server.
// Implementations can use gRPC, REST, or any other protocol.
type Backend interface {
	// GetPermissions fetches all permissions for the given user and tenant.
	GetPermissions(ctx context.Context, userID, tenantID string) ([]string, error)

	// CheckPermission checks if the user has the given permission.
	CheckPermission(ctx context.Context, userID, tenantID, permission string) (bool, error)
}

// Authorizer implements iam.Authorizer with local caching.
type Authorizer struct {
	backend Backend
	ttl     time.Duration

	// cache stores permissions: key = "userID:tenantID:permission", value = *cacheEntry
	cache sync.Map
}

type cacheEntry struct {
	allowed   bool
	timestamp time.Time
}

// compile-time check
var _ iam.Authorizer = (*Authorizer)(nil)

// Option configures the Authorizer.
type Option func(*Authorizer)

// WithCacheTTL sets the cache time-to-live duration.
// Default: 5 minutes (from Config.CacheTTL).
func WithCacheTTL(ttl time.Duration) Option {
	return func(a *Authorizer) { a.ttl = ttl }
}

// New creates a new Authorizer with the given backend.
func New(backend Backend, opts ...Option) *Authorizer {
	a := &Authorizer{
		backend: backend,
		ttl:     5 * time.Minute, // default from P1.2
	}
	for _, o := range opts {
		o(a)
	}
	return a
}

// Check checks if the user has the given permission.
// Result is cached for the configured TTL.
func (a *Authorizer) Check(ctx context.Context, permission string) (bool, error) {
	userID := iam.UserIDFromContext(ctx)
	tenantID := iam.TenantIDFromContext(ctx)

	if userID == "" || tenantID == "" {
		return false, fmt.Errorf("iam/authz: user_id and tenant_id required in context")
	}

	return a.checkCached(ctx, userID, tenantID, permission)
}

// CheckResource checks if the user can perform the action on the resource.
// Combines resource and action into a single permission string: "resource:action".
func (a *Authorizer) CheckResource(ctx context.Context, resource, action string) (bool, error) {
	permission := resource + ":" + action
	return a.Check(ctx, permission)
}

// GetPermissions returns all permissions for the user.
// Result is NOT cached to ensure accuracy.
func (a *Authorizer) GetPermissions(ctx context.Context) ([]string, error) {
	userID := iam.UserIDFromContext(ctx)
	tenantID := iam.TenantIDFromContext(ctx)

	if userID == "" || tenantID == "" {
		return nil, fmt.Errorf("iam/authz: user_id and tenant_id required in context")
	}

	return a.backend.GetPermissions(ctx, userID, tenantID)
}

// checkCached checks the cache and backend.
func (a *Authorizer) checkCached(ctx context.Context, userID, tenantID, permission string) (bool, error) {
	key := cacheKey(userID, tenantID, permission)

	// Check cache
	if cached, ok := a.cache.Load(key); ok {
		entry := cached.(*cacheEntry)
		if time.Since(entry.timestamp) < a.ttl {
			return entry.allowed, nil
		}
		// Cache expired, remove it
		a.cache.Delete(key)
	}

	// Query backend
	allowed, err := a.backend.CheckPermission(ctx, userID, tenantID, permission)
	if err != nil {
		return false, fmt.Errorf("iam/authz: %w", err)
	}

	// Cache result
	a.cache.Store(key, &cacheEntry{
		allowed:   allowed,
		timestamp: time.Now(),
	})

	return allowed, nil
}

// cacheKey generates a cache key from userID, tenantID, and permission.
func cacheKey(userID, tenantID, permission string) string {
	return userID + ":" + tenantID + ":" + permission
}

// ClearCache clears all cached entries. Useful for testing.
func (a *Authorizer) ClearCache() {
	a.cache.Range(func(key, value interface{}) bool {
		a.cache.Delete(key)
		return true
	})
}
