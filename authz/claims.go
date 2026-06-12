package authz

import (
	"context"
	"fmt"
	"strings"

	iam "github.com/chimerakang/iam-go"
)

// ClaimsChecker implements iam.Authorizer using permissions embedded in the
// verified JWT (the "permissions" claim) — zero network calls per check.
//
// When the token carries no permissions (Claims.Permissions == nil) or is
// flagged as degraded by the issuer, checks fall back to the configured
// remote Authorizer (typically the cached gRPC authorizer). Without a
// fallback, such checks are denied with an error.
//
// Consistency trade-off: embedded permissions are as fresh as the token —
// revoking a permission takes effect only after the token expires or is
// refreshed. Keep access-token TTLs short (minutes) when using local checks.
// See docs/PERMISSION_CHECKING.md.
type ClaimsChecker struct {
	fallback     iam.Authorizer
	degradedFlag string
}

// compile-time check
var _ iam.Authorizer = (*ClaimsChecker)(nil)

// DefaultDegradedFlag is the claim name issuers set (to true) when the
// embedded permissions could not be fully resolved and remote checks
// should be used instead.
const DefaultDegradedFlag = "permissions_degraded"

// ClaimsOption configures the ClaimsChecker.
type ClaimsOption func(*ClaimsChecker)

// WithFallback sets the Authorizer used when the token has no embedded
// permissions or is flagged degraded.
func WithFallback(a iam.Authorizer) ClaimsOption {
	return func(c *ClaimsChecker) { c.fallback = a }
}

// WithDegradedFlag overrides the claim name checked for issuer-side
// degradation. Default: DefaultDegradedFlag.
func WithDegradedFlag(name string) ClaimsOption {
	return func(c *ClaimsChecker) { c.degradedFlag = name }
}

// NewClaimsChecker creates a local, claims-based permission checker.
func NewClaimsChecker(opts ...ClaimsOption) *ClaimsChecker {
	c := &ClaimsChecker{degradedFlag: DefaultDegradedFlag}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Check reports whether the user holds the permission, matching locally
// against the token's embedded permissions (wildcards supported).
func (c *ClaimsChecker) Check(ctx context.Context, permission string) (bool, error) {
	claims, ok := c.usableClaims(ctx)
	if !ok {
		if c.fallback != nil {
			return c.fallback.Check(ctx, permission)
		}
		return false, fmt.Errorf("iam/authz: no embedded permissions in claims and no fallback authorizer configured")
	}

	for _, granted := range claims.Permissions {
		if MatchPermission(granted, permission) {
			return true, nil
		}
	}
	return false, nil
}

// CheckResource checks "resource:action" against the embedded permissions.
func (c *ClaimsChecker) CheckResource(ctx context.Context, resource, action string) (bool, error) {
	return c.Check(ctx, resource+":"+action)
}

// GetPermissions returns the token's embedded permissions, or the fallback's
// answer when none are embedded.
func (c *ClaimsChecker) GetPermissions(ctx context.Context) ([]string, error) {
	claims, ok := c.usableClaims(ctx)
	if !ok {
		if c.fallback != nil {
			return c.fallback.GetPermissions(ctx)
		}
		return nil, fmt.Errorf("iam/authz: no embedded permissions in claims and no fallback authorizer configured")
	}
	return claims.Permissions, nil
}

// usableClaims returns the context claims if they carry embedded permissions
// and are not flagged degraded by the issuer.
func (c *ClaimsChecker) usableClaims(ctx context.Context) (*iam.Claims, bool) {
	claims := iam.ClaimsFromContext(ctx)
	if claims == nil || claims.Permissions == nil {
		return nil, false
	}
	if degraded, _ := claims.Extra[c.degradedFlag].(bool); degraded {
		return nil, false
	}
	return claims, true
}

// MatchPermission reports whether a granted permission pattern covers the
// required permission. Patterns are segment-wise with ":" as separator;
// a "*" segment matches one segment, and a trailing "*" matches all
// remaining segments:
//
//	MatchPermission("users:read", "users:read")   == true
//	MatchPermission("users:*", "users:read")      == true
//	MatchPermission("users:*", "users:read:all")  == true
//	MatchPermission("*", "anything:at:all")       == true
//	MatchPermission("users:read", "users:write")  == false
func MatchPermission(granted, required string) bool {
	if granted == required {
		return true
	}

	g := strings.Split(granted, ":")
	r := strings.Split(required, ":")

	for i, seg := range g {
		if seg == "*" && i == len(g)-1 {
			return true // trailing wildcard covers the rest
		}
		if i >= len(r) {
			return false // pattern longer than required permission
		}
		if seg != "*" && seg != r[i] {
			return false
		}
	}
	return len(g) == len(r)
}
