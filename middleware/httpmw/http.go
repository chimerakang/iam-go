// Package httpmw provides standard library net/http middleware for IAM
// integration — the same Auth / Tenant / Require / RequireAny stack as
// kratosmw, for services that don't use Kratos.
//
// All middleware functions accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService). Failures are written as JSON:
//
//	{"code": "UNAUTHORIZED", "message": "invalid token"}
//
// Usage:
//
//	mux := http.NewServeMux()
//	mux.Handle("/api/", httpmw.Auth(client)(httpmw.Tenant(client)(apiHandler)))
package httpmw

import (
	"encoding/json"
	"net/http"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/middleware/internal/mwcore"
)

// Middleware is a standard net/http middleware: it wraps an http.Handler.
type Middleware func(http.Handler) http.Handler

// AuthOption configures Auth middleware behavior.
type AuthOption func(*authConfig)

type authConfig struct {
	excludedPaths map[string]bool
}

// WithExcludedPaths sets URL paths that skip authentication (e.g. health checks).
// Paths are matched exactly against r.URL.Path.
func WithExcludedPaths(paths ...string) AuthOption {
	return func(cfg *authConfig) {
		for _, p := range paths {
			cfg.excludedPaths[p] = true
		}
	}
}

// Auth returns middleware that verifies JWT Bearer tokens via client.Verifier().
// On success, it stores claims in the request context (retrievable via
// iam.UserIDFromContext, iam.ClaimsFromContext, etc.).
// Responds 401 if the token is missing or invalid.
func Auth(client *iam.Client, opts ...AuthOption) Middleware {
	cfg := &authConfig{excludedPaths: make(map[string]bool)}
	for _, o := range opts {
		o(cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.excludedPaths[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}

			ctx, mwErr := mwcore.Authenticate(r.Context(), client, r.Header.Get("Authorization"))
			if mwErr != nil {
				writeError(w, mwErr)
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Tenant returns middleware that validates tenant membership.
// Requires Auth middleware to run first (uses claims from context).
// Responds 403 if the user does not belong to the tenant.
func Tenant(client *iam.Client) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mwErr := mwcore.ValidateTenant(r.Context(), client); mwErr != nil {
				writeError(w, mwErr)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Require returns middleware that checks a single permission.
// Requires Auth middleware to run first (uses user context).
// Responds 403 if the permission is denied.
func Require(client *iam.Client, permission string) Middleware {
	return RequireAny(client, permission)
}

// RequireAny returns middleware that passes if the user has any of the given permissions.
func RequireAny(client *iam.Client, permissions ...string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if mwErr := mwcore.CheckAnyPermission(r.Context(), client, permissions...); mwErr != nil {
				writeError(w, mwErr)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Chain composes middleware left-to-right: Chain(a, b)(h) == a(b(h)).
func Chain(mws ...Middleware) Middleware {
	return func(next http.Handler) http.Handler {
		for i := len(mws) - 1; i >= 0; i-- {
			next = mws[i](next)
		}
		return next
	}
}

func writeError(w http.ResponseWriter, e *mwcore.Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(e.Status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":    e.Code,
		"message": e.Message,
	})
}
