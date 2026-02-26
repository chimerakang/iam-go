// Package grpcmw provides pure gRPC interceptors for IAM integration.
//
// Use this package for gRPC services that do NOT use Kratos.
// For Kratos-based services, use kratosmw instead — Kratos middleware
// handles both HTTP and gRPC transports transparently.
//
// All interceptors accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService) — no direct dependency on
// any specific IAM backend.
package grpcmw

import (
	"context"
	"strings"

	iam "github.com/chimerakang/iam-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// AuthOption configures auth interceptor behavior.
type AuthOption func(*authConfig)

type authConfig struct {
	excludedMethods map[string]bool
}

// WithExcludedMethods sets gRPC methods that skip authentication.
// Methods should be fully qualified (e.g. "/package.Service/Method").
func WithExcludedMethods(methods ...string) AuthOption {
	return func(cfg *authConfig) {
		for _, m := range methods {
			cfg.excludedMethods[m] = true
		}
	}
}

// UnaryAuth returns a gRPC unary server interceptor that verifies JWT tokens.
// On success, it stores claims in the context via iam.WithUserID, iam.WithClaims, etc.
func UnaryAuth(client *iam.Client, opts ...AuthOption) grpc.UnaryServerInterceptor {
	cfg := &authConfig{excludedMethods: make(map[string]bool)}
	for _, o := range opts {
		o(cfg)
	}

	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		if cfg.excludedMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		ctx, err := authenticate(ctx, client)
		if err != nil {
			return nil, err
		}

		return handler(ctx, req)
	}
}

// StreamAuth returns a gRPC stream server interceptor that verifies JWT tokens.
func StreamAuth(client *iam.Client, opts ...AuthOption) grpc.StreamServerInterceptor {
	cfg := &authConfig{excludedMethods: make(map[string]bool)}
	for _, o := range opts {
		o(cfg)
	}

	return func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if cfg.excludedMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		ctx, err := authenticate(ss.Context(), client)
		if err != nil {
			return err
		}

		wrapped := &wrappedStream{ServerStream: ss, ctx: ctx}
		return handler(srv, wrapped)
	}
}

// UnaryTenant returns a gRPC unary server interceptor that validates tenant membership.
// Requires UnaryAuth to run first.
func UnaryTenant(client *iam.Client) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		svc := client.Tenants()
		if svc == nil {
			return handler(ctx, req)
		}

		userID := iam.UserIDFromContext(ctx)
		tenantID := iam.TenantIDFromContext(ctx)
		if userID == "" || tenantID == "" {
			return nil, status.Error(codes.Unauthenticated, "missing user or tenant context")
		}

		ok, err := svc.ValidateMembership(ctx, userID, tenantID)
		if err != nil {
			return nil, status.Error(codes.Internal, "tenant validation failed")
		}
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "not a member of this tenant")
		}

		return handler(ctx, req)
	}
}

// UnaryRequire returns a gRPC unary server interceptor that checks a single permission.
// Requires UnaryAuth to run first.
func UnaryRequire(client *iam.Client, permission string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		authz := client.Authz()
		if authz == nil {
			return nil, status.Error(codes.Internal, "authorizer not configured")
		}

		ok, err := authz.Check(ctx, permission)
		if err != nil {
			return nil, status.Error(codes.Internal, "authorization check failed")
		}
		if !ok {
			return nil, status.Error(codes.PermissionDenied, "permission denied")
		}

		return handler(ctx, req)
	}
}

// --- internal helpers ---

func authenticate(ctx context.Context, client *iam.Client) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx, status.Error(codes.Unauthenticated, "missing metadata")
	}

	tokenStr := extractBearerFromMD(md)
	if tokenStr == "" {
		return ctx, status.Error(codes.Unauthenticated, "missing authorization token")
	}

	verifier := client.Verifier()
	if verifier == nil {
		return ctx, status.Error(codes.Internal, "token verifier not configured")
	}

	claims, err := verifier.Verify(ctx, tokenStr)
	if err != nil {
		return ctx, status.Error(codes.Unauthenticated, "invalid token")
	}

	ctx = iam.WithClaims(ctx, claims)
	ctx = iam.WithUserID(ctx, claims.Subject)
	ctx = iam.WithTenantID(ctx, claims.TenantID)
	ctx = iam.WithRoles(ctx, claims.Roles)

	return ctx, nil
}

func extractBearerFromMD(md metadata.MD) string {
	vals := md.Get("authorization")
	if len(vals) == 0 {
		return ""
	}
	parts := strings.SplitN(vals[0], " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// wrappedStream wraps grpc.ServerStream to override Context().
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
