// Package ginmw provides Gin HTTP middleware for IAM integration.
//
// All middleware functions accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService) — no direct dependency on
// any specific IAM backend.
package ginmw

import (
	"net/http"
	"strings"

	iam "github.com/chimerakang/iam-go"
	"github.com/gin-gonic/gin"
)

// Context keys for storing IAM data in gin.Context.
const (
	KeyUserID   = "iam_user_id"
	KeyTenantID = "iam_tenant_id"
	KeyRoles    = "iam_roles"
	KeyEmail    = "iam_email"
	KeyClaims   = "iam_claims"
)

// AuthOption configures Auth middleware behavior.
type AuthOption func(*authConfig)

type authConfig struct {
	excludedPaths map[string]bool
}

// WithExcludedPaths sets paths that skip authentication (e.g. health checks).
func WithExcludedPaths(paths ...string) AuthOption {
	return func(cfg *authConfig) {
		for _, p := range paths {
			cfg.excludedPaths[p] = true
		}
	}
}

// Auth returns Gin middleware that verifies JWT tokens via client.Verifier().
// On success, it stores claims in the context (retrievable via GetUserID, GetClaims, etc.).
// Responds with 401 if the token is missing or invalid.
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

		tokenStr := extractBearerToken(c.Request)
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing authorization token"})
			return
		}

		verifier := client.Verifier()
		if verifier == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "token verifier not configured"})
			return
		}

		claims, err := verifier.Verify(c.Request.Context(), tokenStr)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		c.Set(KeyClaims, claims)
		c.Set(KeyUserID, claims.Subject)
		c.Set(KeyTenantID, claims.TenantID)
		c.Set(KeyRoles, claims.Roles)
		if email, ok := claims.Extra["email"].(string); ok {
			c.Set(KeyEmail, email)
		}

		c.Next()
	}
}

// Tenant returns Gin middleware that validates tenant membership.
// Requires Auth middleware to run first (uses claims from context).
// Responds with 403 if the user does not belong to the tenant.
func Tenant(client *iam.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		svc := client.Tenants()
		if svc == nil {
			c.Next()
			return
		}

		userID := GetUserID(c)
		tenantID := GetTenantID(c)
		if userID == "" || tenantID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing user or tenant context"})
			return
		}

		ok, err := svc.ValidateMembership(c.Request.Context(), userID, tenantID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "tenant validation failed"})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "not a member of this tenant"})
			return
		}

		c.Next()
	}
}

// Require returns Gin middleware that checks a single permission.
// Requires Auth middleware to run first (uses user context).
// Responds with 403 if the permission is denied.
func Require(client *iam.Client, permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := client.Authz()
		if authz == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorizer not configured"})
			return
		}

		ctx := contextWithUserID(c)
		ok, err := authz.Check(ctx, permission)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission denied"})
			return
		}

		c.Next()
	}
}

// RequireAny returns Gin middleware that checks if the user has any of the given permissions.
func RequireAny(client *iam.Client, permissions ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authz := client.Authz()
		if authz == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorizer not configured"})
			return
		}

		ctx := contextWithUserID(c)
		for _, perm := range permissions {
			ok, err := authz.Check(ctx, perm)
			if err != nil {
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "authorization check failed"})
				return
			}
			if ok {
				c.Next()
				return
			}
		}

		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "permission denied"})
	}
}

// APIKey returns Gin middleware that authenticates via API key/secret headers.
// Looks for X-API-Key and X-API-Secret headers.
func APIKey(client *iam.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		apiKey := c.GetHeader("X-API-Key")
		apiSecret := c.GetHeader("X-API-Secret")
		if apiKey == "" || apiSecret == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing API key or secret"})
			return
		}

		svc := client.Secrets()
		if svc == nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "secret service not configured"})
			return
		}

		claims, err := svc.Verify(c.Request.Context(), apiKey, apiSecret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid API credentials"})
			return
		}

		c.Set(KeyClaims, claims)
		c.Set(KeyUserID, claims.Subject)
		c.Set(KeyTenantID, claims.TenantID)
		c.Set(KeyRoles, claims.Roles)

		c.Next()
	}
}

// --- Context helpers ---

// GetUserID returns the authenticated user ID from the Gin context.
func GetUserID(c *gin.Context) string {
	v, _ := c.Get(KeyUserID)
	s, _ := v.(string)
	return s
}

// GetTenantID returns the tenant ID from the Gin context.
func GetTenantID(c *gin.Context) string {
	v, _ := c.Get(KeyTenantID)
	s, _ := v.(string)
	return s
}

// GetRoles returns the user's roles from the Gin context.
func GetRoles(c *gin.Context) []string {
	v, _ := c.Get(KeyRoles)
	r, _ := v.([]string)
	return r
}

// GetEmail returns the user's email from the Gin context.
func GetEmail(c *gin.Context) string {
	v, _ := c.Get(KeyEmail)
	s, _ := v.(string)
	return s
}

// GetClaims returns the full claims from the Gin context.
func GetClaims(c *gin.Context) *iam.Claims {
	v, _ := c.Get(KeyClaims)
	cl, _ := v.(*iam.Claims)
	return cl
}

// --- internal helpers ---

func extractBearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// contextWithUserID enriches the request context with the user ID from Gin context,
// so that Authorizer implementations (e.g. fake) can access it.
func contextWithUserID(c *gin.Context) context.Context {
	return context.WithValue(c.Request.Context(), ctxKey("iam_user_id"), GetUserID(c))
}

type ctxKey string
