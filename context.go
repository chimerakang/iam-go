package iam

import "context"

type ctxKey string

const (
	ctxKeyUserID   ctxKey = "iam_user_id"
	ctxKeyTenantID ctxKey = "iam_tenant_id"
	ctxKeyRoles    ctxKey = "iam_roles"
	ctxKeyClaims   ctxKey = "iam_claims"
)

// WithUserID stores the authenticated user ID in the context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, ctxKeyUserID, userID)
}

// UserIDFromContext extracts the authenticated user ID from the context.
func UserIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyUserID).(string)
	return v
}

// WithTenantID stores the tenant ID in the context.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, ctxKeyTenantID, tenantID)
}

// TenantIDFromContext extracts the tenant ID from the context.
func TenantIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyTenantID).(string)
	return v
}

// WithRoles stores the user roles in the context.
func WithRoles(ctx context.Context, roles []string) context.Context {
	return context.WithValue(ctx, ctxKeyRoles, roles)
}

// RolesFromContext extracts the user roles from the context.
func RolesFromContext(ctx context.Context) []string {
	v, _ := ctx.Value(ctxKeyRoles).([]string)
	return v
}

// WithClaims stores the full token claims in the context.
func WithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, ctxKeyClaims, claims)
}

// ClaimsFromContext extracts the full token claims from the context.
func ClaimsFromContext(ctx context.Context) *Claims {
	v, _ := ctx.Value(ctxKeyClaims).(*Claims)
	return v
}
