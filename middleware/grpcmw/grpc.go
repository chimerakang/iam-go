// Package grpcmw provides gRPC interceptors for IAM integration.
//
// All interceptors accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService) — no direct dependency on
// any specific IAM backend.
package grpcmw

// TODO: Implement gRPC interceptors
// - UnaryAuthInterceptor(client): JWT verification for unary RPCs via client.Verifier()
// - StreamAuthInterceptor(client): JWT verification for streaming RPCs
// - UnaryTenantInterceptor(client): Tenant context injection
// - Metadata propagation (user_id, tenant_id, roles)
