// Package mwcore holds the framework-agnostic middleware logic shared by
// httpmw and ginmw. It mirrors the behavior of kratosmw: same checks, same
// error semantics, expressed as HTTP status codes instead of kratos errors.
package mwcore

import (
	"context"
	"net/http"
	"strings"

	iam "github.com/chimerakang/iam-go"
)

// Error is a middleware failure with an HTTP status and a machine-readable code.
type Error struct {
	Status  int    // HTTP status code
	Code    string // "UNAUTHORIZED", "FORBIDDEN", "INTERNAL"
	Message string
}

func (e *Error) Error() string { return e.Message }

func unauthorized(msg string) *Error {
	return &Error{Status: http.StatusUnauthorized, Code: "UNAUTHORIZED", Message: msg}
}

func forbidden(msg string) *Error {
	return &Error{Status: http.StatusForbidden, Code: "FORBIDDEN", Message: msg}
}

func internal(msg string) *Error {
	return &Error{Status: http.StatusInternalServerError, Code: "INTERNAL", Message: msg}
}

// Authenticate verifies the Bearer token from an Authorization header value
// and returns a context populated with claims, user ID, tenant ID, and roles.
func Authenticate(ctx context.Context, client *iam.Client, authorizationHeader string) (context.Context, *Error) {
	tokenStr := ExtractBearerToken(authorizationHeader)
	if tokenStr == "" {
		return ctx, unauthorized("missing authorization token")
	}

	verifier := client.Verifier()
	if verifier == nil {
		return ctx, internal("token verifier not configured")
	}

	claims, err := verifier.Verify(ctx, tokenStr)
	if err != nil {
		return ctx, unauthorized("invalid token")
	}

	ctx = iam.WithClaims(ctx, claims)
	ctx = iam.WithUserID(ctx, claims.Subject)
	ctx = iam.WithTenantID(ctx, claims.TenantID)
	ctx = iam.WithRoles(ctx, claims.Roles)
	return ctx, nil
}

// ValidateTenant checks tenant membership for the authenticated user.
// Requires Authenticate to have populated the context first.
// A nil TenantService is a no-op (matches kratosmw.Tenant).
func ValidateTenant(ctx context.Context, client *iam.Client) *Error {
	svc := client.Tenants()
	if svc == nil {
		return nil
	}

	userID := iam.UserIDFromContext(ctx)
	tenantID := iam.TenantIDFromContext(ctx)
	if userID == "" || tenantID == "" {
		return unauthorized("missing user or tenant context")
	}

	ok, err := svc.ValidateMembership(ctx, userID, tenantID)
	if err != nil {
		return internal("tenant validation failed")
	}
	if !ok {
		return forbidden("not a member of this tenant")
	}
	return nil
}

// CheckAnyPermission passes if the user holds at least one of the permissions.
// Requires Authenticate to have populated the context first.
func CheckAnyPermission(ctx context.Context, client *iam.Client, permissions ...string) *Error {
	authz := client.Authz()
	if authz == nil {
		return internal("authorizer not configured")
	}

	for _, perm := range permissions {
		ok, err := authz.Check(ctx, perm)
		if err != nil {
			return internal("authorization check failed")
		}
		if ok {
			return nil
		}
	}
	return forbidden("permission denied")
}

// ExtractBearerToken parses an Authorization header value of the form
// "Bearer <token>" (scheme case-insensitive). Returns "" if malformed.
func ExtractBearerToken(auth string) string {
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
