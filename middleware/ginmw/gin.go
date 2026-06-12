// Package ginmw provides Gin framework middleware for IAM integration — the
// same Auth / Tenant / Require / RequireAny stack as kratosmw, for services
// built on Gin.
//
// All middleware functions accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService). Failures abort the request
// with a JSON body:
//
//	{"code": "UNAUTHORIZED", "message": "invalid token"}
//
// Claims are stored on the request context, so the iam context helpers work
// with c.Request.Context():
//
//	userID := iam.UserIDFromContext(c.Request.Context())
//
// Usage:
//
//	r := gin.New()
//	api := r.Group("/api", ginmw.Auth(client), ginmw.Tenant(client))
//	api.GET("/users", ginmw.Require(client, "users:read"), listUsers)
package ginmw

import (
	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/middleware/internal/mwcore"
	"github.com/gin-gonic/gin"
)

// AuthOption configures Auth middleware behavior.
type AuthOption func(*authConfig)

type authConfig struct {
	excludedPaths map[string]bool
}

// WithExcludedPaths sets URL paths that skip authentication (e.g. health checks).
// Paths are matched exactly against the request URL path.
func WithExcludedPaths(paths ...string) AuthOption {
	return func(cfg *authConfig) {
		for _, p := range paths {
			cfg.excludedPaths[p] = true
		}
	}
}

// Auth returns Gin middleware that verifies JWT Bearer tokens via client.Verifier().
// On success, it stores claims in the request context (retrievable via
// iam.UserIDFromContext(c.Request.Context()), etc.).
// Aborts with 401 if the token is missing or invalid.
func Auth(client *iam.Client, opts ...AuthOption) gin.HandlerFunc {
	cfg := &authConfig{excludedPaths: make(map[string]bool)}
	for _, o := range opts {
		o(cfg)
	}

	return func(c *gin.Context) {
		if cfg.excludedPaths[c.Request.URL.Path] {
			c.Next()
			return
		}

		ctx, mwErr := mwcore.Authenticate(c.Request.Context(), client, c.GetHeader("Authorization"))
		if mwErr != nil {
			abortWithError(c, mwErr)
			return
		}

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}

// Tenant returns Gin middleware that validates tenant membership.
// Requires Auth middleware to run first (uses claims from context).
// Aborts with 403 if the user does not belong to the tenant.
func Tenant(client *iam.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if mwErr := mwcore.ValidateTenant(c.Request.Context(), client); mwErr != nil {
			abortWithError(c, mwErr)
			return
		}
		c.Next()
	}
}

// Require returns Gin middleware that checks a single permission.
// Requires Auth middleware to run first (uses user context).
// Aborts with 403 if the permission is denied.
func Require(client *iam.Client, permission string) gin.HandlerFunc {
	return RequireAny(client, permission)
}

// RequireAny returns Gin middleware that passes if the user has any of the given permissions.
func RequireAny(client *iam.Client, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if mwErr := mwcore.CheckAnyPermission(c.Request.Context(), client, permissions...); mwErr != nil {
			abortWithError(c, mwErr)
			return
		}
		c.Next()
	}
}

func abortWithError(c *gin.Context, e *mwcore.Error) {
	c.AbortWithStatusJSON(e.Status, gin.H{
		"code":    e.Code,
		"message": e.Message,
	})
}
