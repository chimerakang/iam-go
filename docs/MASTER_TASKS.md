# IAM-Go SDK - Master Tasks

> Go SDK for Valhalla IAM - Authentication, Authorization, and Multi-tenancy client library
> Last updated: 2026-02-26
> Auto-generated from GitHub Issues — do not edit manually.
> Run `/task-sync` to regenerate.

## Status Legend

| Status | Label |
|--------|-------|
| 📋 | 規劃中 |
| 🔄 | 開發中 |
| 🧪 | 測試中 |
| ✅ | 已完成 |
| ⏸️ | 暫停 |
| ❌ | 已取消 |

---

## Phase Overview

| Phase | Description | Progress | Status |
|-------|-------------|----------|--------|
| P0: Valhalla Prerequisites | Server-side features needed in Valhalla before SDK can work | 0% (0/3) | 📋 |
| P1: Core SDK | JWKS client, gRPC connection, authorization client, secret client | 0% (0/4) | 📋 |
| P2: Middleware | Gin, Kratos, gRPC middleware and interceptors | 0% (0/3) | 📋 |
| P3: Extended Features | Tenant, user, session clients | 0% (0/3) | 📋 |
| P4: Testing & Quality | Fake client, integration tests, CI/CD | 0% (0/3) | 📋 |
| P5: Audit & Observability | Audit logging, Prometheus metrics | 0% (0/2) | 📋 |

---

## P0: Valhalla Prerequisites (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P0.1 | **P0.1 RS256 JWT Signing + JWKS Endpoint** | [#1](https://github.com/chimerakang/iam-go/issues/1) | 🔄 |
| | — Generate RSA key pair for JWT signing (stored in config/env) | | ☐ |
| | — Switch JWT signing from HS256 to RS256 | | ☐ |
| | — Implement `GET /.well-known/jwks.json` endpoint | | ☐ |
| | — Support multiple active keys (key rotation via `kid`) | | ☐ |
| | — Update existing JWT middleware to support RS256 verification | | ☐ |
| | — Backward-compatible: support both HS256 (deprecated) and RS256 during migration | | ☐ |
| | — `curl http://<server>/.well-known/jwks.json` returns valid JWKS | | ☐ |
| | — Tokens signed with RS256 can be verified using the public key | | ☐ |
| | — Existing HS256 tokens still work during transition period | | ☐ |
| P0.2 | **P0.2 API Key/Secret Management Service** | [#2](https://github.com/chimerakang/iam-go/issues/2) | 🔄 |
| | — Secret CRUD endpoints: Create, List, Delete, Verify, Rotate | | ☐ |
| | — Database migration: `api_secrets` table (id, user_id, tenant_id, secret_id, secret_key_hash, description, expires_at, status) | | ☐ |
| | — Secret generation (crypto/rand), hashing (bcrypt), verification | | ☐ |
| | — API Key authentication middleware (X-API-Key + X-API-Secret headers) | | ☐ |
| | — Rate limiting per API key | | ☐ |
| | — Secret key shown only once at creation time | | ☐ |
| P0.3 | **P0.3 IAM gRPC Service for External Consumers** | [#3](https://github.com/chimerakang/iam-go/issues/3) | 🔄 |
| | — Define IAM service API (gRPC or REST) | | ☐ |
| | — `IntrospectToken(token)` → TokenClaims (checks blacklist + signature) | | ☐ |
| | — `CheckPermission(user_id, tenant_id, permission)` → bool | | ☐ |
| | — `GetUserPermissions(user_id, tenant_id)` → []string | | ☐ |
| | — `ValidateTenantMembership(user_id, tenant_id)` → MembershipInfo | | ☐ |
| | — `GetTenantBySlug(slug)` → Tenant | | ☐ |
| | — Service implementation with caching | | ☐ |
| | — API Key authentication for this service (not JWT) | | ☐ |

---

## P1: Core SDK (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P1.1 | **P1.1 JWKS Client — Public Key Fetching and JWT Verification** | [#4](https://github.com/chimerakang/iam-go/issues/4) | 🔄 |
| | — `jwks.NewVerifier(url, options...)` → `iam.TokenVerifier` | | ☐ |
| | — Fetch and parse JWKS from configurable `/.well-known/jwks.json` URL | | ☐ |
| | — Cache RSA public keys in memory | | ☐ |
| | — Auto-refresh on configurable interval (default: 1 hour) | | ☐ |
| | — Auto-refresh on `kid` mismatch (key rotation) | | ☐ |
| | — `Verify(ctx, tokenString)` → (`*iam.Claims`, error) | | ☐ |
| | — Extract claims: sub, tenant_id, email, roles, exp, iat → `iam.Claims` | | ☐ |
| | — Handle expired tokens, invalid signatures, malformed tokens | | ☐ |
| | — Unit tests with fake JWKS HTTP server | | ☐ |
| P1.2 | **P1.2 Client Core — gRPC Connection and Config** | [#5](https://github.com/chimerakang/iam-go/issues/5) | 🔄 |
| | — `Config` struct with validation | | ✅ |
| | — Option pattern: `WithTokenVerifier`, `WithAuthorizer`, `WithUserService`, `WithTenantService`, `WithSessionService`, `WithSecretService`, `WithLogger` | | ✅ |
| | — `NewClient(cfg, opts...)` with validation | | ✅ |
| | — Accessor methods: `Verifier()`, `Authz()`, `Users()`, `Tenants()`, `Sessions()`, `Secrets()` | | ✅ |
| | — Connection health check method | | ☐ |
| | — Graceful shutdown via `Close()` — close backend connections, stop goroutines | | ☐ |
| | — Context propagation (timeout, cancellation, request ID) | | ☐ |
| | — Default CacheTTL (5 min) when not specified | | ☐ |
| | — TLS support in Config | | ☐ |
| | — Unit tests for client creation, validation, Close lifecycle | | ☐ |
| P1.3 | **P1.3 Authorizer — Permission Checking with Cache** | [#6](https://github.com/chimerakang/iam-go/issues/6) | 🔄 |
| | — Implement `iam.Authorizer` with configurable backend (gRPC, REST, etc.) | | ☐ |
| | — `Check(ctx, permission)` → bool — single permission check | | ☐ |
| | — `CheckResource(ctx, resource, action)` → bool — resource-level ABAC | | ☐ |
| | — `GetPermissions(ctx)` → []string — list all permissions | | ☐ |
| | — Local in-memory cache with configurable TTL (default: 5 min from `Config.CacheTTL`) | | ☐ |
| | — Cache key: `{user_id}:{tenant_id}:{permission}` | | ☐ |
| | — Thread-safe cache (sync.Map or sync.RWMutex) | | ☐ |
| | — Unit tests with fake backend | | ☐ |
| P1.4 | **P1.4 SecretService — API Key Management** | [#7](https://github.com/chimerakang/iam-go/issues/7) | 🔄 |
| | — Implement `iam.SecretService` with configurable backend (gRPC, REST, etc.) | | ☐ |
| | — `Create(ctx, description)` → (`*iam.Secret`, error) — generate new key pair | | ☐ |
| | — `List(ctx)` → (`[]iam.Secret`, error) — list all keys (secrets excluded) | | ☐ |
| | — `Delete(ctx, secretID)` → error — revoke a key | | ☐ |
| | — `Verify(ctx, apiKey, apiSecret)` → (`*iam.Claims`, error) — validate credentials | | ☐ |
| | — `Rotate(ctx, secretID)` → (`*iam.Secret`, error) — regenerate secret | | ☐ |
| | — Unit tests with fake backend | | ☐ |

---

## P2: Middleware (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P2.1 | **P2.1 Gin Middleware — Auth, Tenant, Permission** | [#8](https://github.com/chimerakang/iam-go/issues/8) | 🔄 |
| | — `GinAuth(client)` — JWT verification via `client.Verifier()`, injects user_id/email/roles into context | | ☐ |
| | — `GinTenant(client)` — Extracts tenant_id from claims via `client.Tenants()`, validates membership, injects into context | | ☐ |
| | — `GinRequire(client, permission)` — Permission gate via `client.Authz()` (403 if denied) | | ☐ |
| | — `GinRequireAny(client, ...permissions)` — Any-of permission gate | | ☐ |
| | — `GinAPIKey(client)` — API Key authentication via `client.Secrets()` for service endpoints | | ☐ |
| | — Context helpers: `GetUserID(c)`, `GetTenantID(c)`, `GetRoles(c)`, `GetEmail(c)` | | ☐ |
| | — Excluded paths configuration (e.g., health check, public routes) | | ☐ |
| | — Custom error response handler (configurable) | | ☐ |
| | — Integration tests with httptest | | ☐ |
| P2.2 | **P2.2 Kratos Middleware — Auth, Tenant, Permission** | [#9](https://github.com/chimerakang/iam-go/issues/9) | 🔄 |
| | — `KratosAuth(client)` — JWT verification via `client.Verifier()` (works with HTTP + gRPC transport) | | ☐ |
| | — `KratosTenant(client)` — Tenant context via `client.Tenants()` | | ☐ |
| | — `KratosRequire(client, permission)` — Permission gate via `client.Authz()` | | ☐ |
| | — Context propagation compatible with Kratos transport layer | | ☐ |
| | — Unit tests | | ☐ |
| P2.3 | **P2.3 gRPC Interceptors — Auth and Tenant** | [#10](https://github.com/chimerakang/iam-go/issues/10) | 🔄 |
| | — `UnaryAuthInterceptor(client)` — JWT verification via `client.Verifier()` for unary RPCs | | ☐ |
| | — `StreamAuthInterceptor(client)` — JWT verification for streaming RPCs | | ☐ |
| | — `UnaryTenantInterceptor(client)` — Tenant context injection via `client.Tenants()` | | ☐ |
| | — Metadata propagation: user_id, tenant_id, roles, request_id | | ☐ |
| | — Excluded methods configuration (e.g., health check RPCs) | | ☐ |
| | — Unit tests with bufconn | | ☐ |

---

## P3: Extended Features (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P3.1 | **P3.1 TenantService — Resolution and Context** | [#11](https://github.com/chimerakang/iam-go/issues/11) | 🔄 |
| | — Implement `iam.TenantService` with configurable backend | | ☐ |
| | — `Resolve(ctx, identifier)` → `*iam.Tenant` — resolve by slug or subdomain | | ☐ |
| | — `ValidateMembership(ctx, userID, tenantID)` → bool | | ☐ |
| | — Local tenant cache with TTL | | ☐ |
| | — `SwitchTenant` helper (issue new token for different tenant) | | ☐ |
| | — Unit tests with fake backend | | ☐ |
| P3.2 | **P3.2 UserService — User Query** | [#12](https://github.com/chimerakang/iam-go/issues/12) | 🔄 |
| | — Implement `iam.UserService` with configurable backend | | ☐ |
| | — `GetCurrent(ctx)` → `*iam.User` | | ☐ |
| | — `Get(ctx, userID)` → `*iam.User` | | ☐ |
| | — `List(ctx, opts)` → (`[]*iam.User`, total, error) | | ☐ |
| | — `GetRoles(ctx, userID)` → `[]iam.Role` | | ☐ |
| | — Unit tests with fake backend | | ☐ |
| P3.3 | **P3.3 SessionService — Session Management** | [#13](https://github.com/chimerakang/iam-go/issues/13) | 🔄 |
| | — Implement `iam.SessionService` with configurable backend | | ☐ |
| | — `List(ctx)` → `[]iam.Session` | | ☐ |
| | — `Revoke(ctx, sessionID)` → error | | ☐ |
| | — `RevokeAllOthers(ctx)` → error | | ☐ |
| | — Unit tests with fake backend | | ☐ |

---

## P4: Testing & Quality (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P4.1 | **P4.1 Fake Client — In-Memory Test Doubles** | [#14](https://github.com/chimerakang/iam-go/issues/14) | 🔄 |
| | — `fake.NewClient(options...)` — returns `*iam.Client` with all services wired to in-memory fakes | | ☐ |
| | — `fake.WithUser(id, tenantID, email, roles)` — configure a test user | | ☐ |
| | — `fake.WithTenant(id, slug, status)` — configure a test tenant | | ☐ |
| | — `fake.WithPermissions(userID, []string)` — configure permission rules | | ☐ |
| | — `fake.WithAPIKey(key, secret, userID)` — configure test API key | | ☐ |
| | — Implements: `iam.TokenVerifier`, `iam.Authorizer`, `iam.UserService`, `iam.TenantService`, `iam.SessionService`, `iam.SecretService` | | ☐ |
| | — Comprehensive unit tests for the fake itself | | ☐ |
| P4.2 | **P4.2 Integration Tests — End-to-End Verification** | [#15](https://github.com/chimerakang/iam-go/issues/15) | 🔄 |
| | — Docker Compose test environment (IAM server + PostgreSQL + Redis) | | ☐ |
| | — Test: login → get JWT → verify via JWKS → check permission | | ☐ |
| | — Test: create API key → authenticate → query permissions | | ☐ |
| | — Test: multi-tenant isolation (user in tenant A can't access tenant B) | | ☐ |
| | — Test: token refresh and revocation | | ☐ |
| | — Test: key rotation (JWKS refresh) | | ☐ |
| | — CI-friendly (runs in GitHub Actions with services) | | ☐ |
| P4.3 | **P4.3 CI/CD — GitHub Actions Pipeline** | [#16](https://github.com/chimerakang/iam-go/issues/16) | 🔄 |
| | — GitHub Actions: `go vet`, `golangci-lint` on every PR | | ☐ |
| | — GitHub Actions: `go test ./...` with race detector | | ☐ |
| | — GitHub Actions: release workflow with semantic versioning (tags) | | ☐ |
| | — Go report card badge in README | | ☐ |
| | — Test coverage reporting (codecov or similar) | | ☐ |
| | — Dependabot for dependency updates | | ☐ |

---

## P5: Audit & Observability (📋 0%)

| # | Task | Issue | Status |
|---|------|-------|--------|
| P5.1 | **P5.1 Audit Log Integration** | [#17](https://github.com/chimerakang/iam-go/issues/17) | 🔄 |
| | — Audit event struct (timestamp, user_id, tenant_id, action, resource, result, ip, user_agent) | | ☐ |
| | — Middleware hooks: emit on auth success/failure, permission check | | ☐ |
| | — Configurable destination: stdout (JSON), callback function, or remote service | | ☐ |
| | — Request ID propagation in audit records | | ☐ |
| | — Buffered async emission (don't block request) | | ☐ |
| P5.2 | **P5.2 Prometheus Metrics** | [#18](https://github.com/chimerakang/iam-go/issues/18) | 🔄 |
| | — Counter: `iam_auth_requests_total{status=success|failure,method=jwt|apikey}` | | ☐ |
| | — Counter: `iam_permission_checks_total{result=allowed|denied}` | | ☐ |
| | — Histogram: `iam_permission_check_duration_seconds` | | ☐ |
| | — Gauge: `iam_cache_entries` (current cache size) | | ☐ |
| | — Counter: `iam_cache_hits_total` / `iam_cache_misses_total` | | ☐ |
| | — Gauge: `iam_grpc_connection_state` (0=disconnected, 1=connected) | | ☐ |
| | — Optional: enable/disable via config | | ☐ |

---

## Issue Tracker

| Issue | Title | Phase | Status |
|-------|-------|-------|--------|
| [#1](https://github.com/chimerakang/iam-go/issues/1) | P0.1 RS256 JWT Signing + JWKS Endpoint | P0: Valhalla Prerequisites | 🔄 |
| [#2](https://github.com/chimerakang/iam-go/issues/2) | P0.2 API Key/Secret Management Service | P0: Valhalla Prerequisites | 🔄 |
| [#3](https://github.com/chimerakang/iam-go/issues/3) | P0.3 IAM gRPC Service for External Consumers | P0: Valhalla Prerequisites | 🔄 |
| [#4](https://github.com/chimerakang/iam-go/issues/4) | P1.1 JWKS Client — Public Key Fetching and JWT Verification | P1: Core SDK | 🔄 |
| [#5](https://github.com/chimerakang/iam-go/issues/5) | P1.2 Client Core — gRPC Connection and Config | P1: Core SDK | 🔄 |
| [#6](https://github.com/chimerakang/iam-go/issues/6) | P1.3 Authorizer — Permission Checking with Cache | P1: Core SDK | 🔄 |
| [#7](https://github.com/chimerakang/iam-go/issues/7) | P1.4 SecretService — API Key Management | P1: Core SDK | 🔄 |
| [#8](https://github.com/chimerakang/iam-go/issues/8) | P2.1 Gin Middleware — Auth, Tenant, Permission | P2: Middleware | 🔄 |
| [#9](https://github.com/chimerakang/iam-go/issues/9) | P2.2 Kratos Middleware — Auth, Tenant, Permission | P2: Middleware | 🔄 |
| [#10](https://github.com/chimerakang/iam-go/issues/10) | P2.3 gRPC Interceptors — Auth and Tenant | P2: Middleware | 🔄 |
| [#11](https://github.com/chimerakang/iam-go/issues/11) | P3.1 TenantService — Resolution and Context | P3: Extended Features | 🔄 |
| [#12](https://github.com/chimerakang/iam-go/issues/12) | P3.2 UserService — User Query | P3: Extended Features | 🔄 |
| [#13](https://github.com/chimerakang/iam-go/issues/13) | P3.3 SessionService — Session Management | P3: Extended Features | 🔄 |
| [#14](https://github.com/chimerakang/iam-go/issues/14) | P4.1 Fake Client — In-Memory Test Doubles | P4: Testing & Quality | 🔄 |
| [#15](https://github.com/chimerakang/iam-go/issues/15) | P4.2 Integration Tests — End-to-End Verification | P4: Testing & Quality | 🔄 |
| [#16](https://github.com/chimerakang/iam-go/issues/16) | P4.3 CI/CD — GitHub Actions Pipeline | P4: Testing & Quality | 🔄 |
| [#17](https://github.com/chimerakang/iam-go/issues/17) | P5.1 Audit Log Integration | P5: Audit & Observability | 🔄 |
| [#18](https://github.com/chimerakang/iam-go/issues/18) | P5.2 Prometheus Metrics | P5: Audit & Observability | 🔄 |

---

## Summary

**Total Issues:** 18
**Completed:** 0 ✅
**In Progress:** 18 🔄

**Last sync:** 2026-02-26
