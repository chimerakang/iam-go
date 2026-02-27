// Package kratosmw provides Kratos framework middleware for IAM integration.
//
// All middleware functions accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService). Works transparently with
// both Kratos HTTP and gRPC transports.
package kratosmw

import (
	"context"
	"strings"

	iam "github.com/chimerakang/iam-go"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

// AuthOption configures Auth middleware behavior.
type AuthOption func(*authConfig)

type authConfig struct {
	excludedOperations map[string]bool
}

// WithExcludedOperations sets operations that skip authentication (e.g. health checks).
// Operations are matched by transport.Operation() (gRPC method or HTTP route pattern).
func WithExcludedOperations(ops ...string) AuthOption {
	return func(cfg *authConfig) {
		for _, op := range ops {
			cfg.excludedOperations[op] = true
		}
	}
}

// Auth returns Kratos middleware that verifies JWT tokens via client.Verifier().
// On success, it stores claims in the context (retrievable via iam.UserIDFromContext, etc.).
// Returns kratos errors.Unauthorized if the token is missing or invalid.
func Auth(client *iam.Client, opts ...AuthOption) middleware.Middleware {
	cfg := &authConfig{excludedOperations: make(map[string]bool)}
	for _, o := range opts {
		o(cfg)
	}

	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			tr, ok := transport.FromServerContext(ctx)
			if !ok {
				return handler(ctx, req)
			}

			if cfg.excludedOperations[tr.Operation()] {
				return handler(ctx, req)
			}

			tokenStr := extractBearerToken(tr.RequestHeader().Get("Authorization"))
			if tokenStr == "" {
				return nil, errors.Unauthorized("UNAUTHORIZED", "missing authorization token")
			}

			verifier := client.Verifier()
			if verifier == nil {
				return nil, errors.InternalServer("INTERNAL", "token verifier not configured")
			}

			claims, err := verifier.Verify(ctx, tokenStr)
			if err != nil {
				return nil, errors.Unauthorized("UNAUTHORIZED", "invalid token")
			}

			ctx = iam.WithClaims(ctx, claims)
			ctx = iam.WithUserID(ctx, claims.Subject)
			ctx = iam.WithTenantID(ctx, claims.TenantID)
			ctx = iam.WithRoles(ctx, claims.Roles)

			return handler(ctx, req)
		}
	}
}

// Tenant returns Kratos middleware that validates tenant membership.
// Requires Auth middleware to run first (uses claims from context).
// Returns kratos errors.Forbidden if the user does not belong to the tenant.
func Tenant(client *iam.Client) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			svc := client.Tenants()
			if svc == nil {
				return handler(ctx, req)
			}

			userID := iam.UserIDFromContext(ctx)
			tenantID := iam.TenantIDFromContext(ctx)
			if userID == "" || tenantID == "" {
				return nil, errors.Unauthorized("UNAUTHORIZED", "missing user or tenant context")
			}

			ok, err := svc.ValidateMembership(ctx, userID, tenantID)
			if err != nil {
				return nil, errors.InternalServer("INTERNAL", "tenant validation failed")
			}
			if !ok {
				return nil, errors.Forbidden("FORBIDDEN", "not a member of this tenant")
			}

			return handler(ctx, req)
		}
	}
}

// Require returns Kratos middleware that checks a single permission.
// Requires Auth middleware to run first (uses user context).
// Returns kratos errors.Forbidden if the permission is denied.
func Require(client *iam.Client, permission string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			authz := client.Authz()
			if authz == nil {
				return nil, errors.InternalServer("INTERNAL", "authorizer not configured")
			}

			ok, err := authz.Check(ctx, permission)
			if err != nil {
				return nil, errors.InternalServer("INTERNAL", "authorization check failed")
			}
			if !ok {
				return nil, errors.Forbidden("FORBIDDEN", "permission denied")
			}

			return handler(ctx, req)
		}
	}
}

// RequireAny returns Kratos middleware that checks if the user has any of the given permissions.
func RequireAny(client *iam.Client, permissions ...string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			authz := client.Authz()
			if authz == nil {
				return nil, errors.InternalServer("INTERNAL", "authorizer not configured")
			}

			for _, perm := range permissions {
				ok, err := authz.Check(ctx, perm)
				if err != nil {
					return nil, errors.InternalServer("INTERNAL", "authorization check failed")
				}
				if ok {
					return handler(ctx, req)
				}
			}

			return nil, errors.Forbidden("FORBIDDEN", "permission denied")
		}
	}
}

// OAuth2ClientCredentials returns Kratos client-side middleware that injects
// an OAuth2 Bearer token into outgoing requests using client credentials.
// The token is automatically cached and refreshed before expiry.
func OAuth2ClientCredentials(client *iam.Client) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			exchanger := client.OAuth2()
			if exchanger == nil {
				return nil, errors.InternalServer("INTERNAL", "oauth2 exchanger not configured")
			}

			token, err := exchanger.GetCachedToken(ctx)
			if err != nil {
				return nil, errors.Unauthorized("UNAUTHORIZED", "failed to obtain oauth2 token")
			}

			tr, ok := transport.FromClientContext(ctx)
			if ok {
				tr.RequestHeader().Set("Authorization", "Bearer "+token)
			}

			return handler(ctx, req)
		}
	}
}

// --- internal helpers ---

func extractBearerToken(auth string) string {
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
