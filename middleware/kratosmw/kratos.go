// Package kratosmw provides Kratos framework middleware for IAM integration.
//
// All middleware functions accept an *iam.Client and use its interfaces
// (TokenVerifier, Authorizer, TenantService) — no direct dependency on
// any specific IAM backend.
package kratosmw

// TODO: Implement Kratos middleware
// - KratosAuth(client): JWT verification via client.Verifier()
// - KratosTenant(client): Tenant context injection via client.Tenants()
// - KratosRequire(client, permission): Permission gate via client.Authz()
// - Works with both HTTP and gRPC transports
