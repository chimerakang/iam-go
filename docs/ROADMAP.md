# IAM-Go SDK Development Roadmap

## Project Goal

Build a Kratos + Proto-first Go SDK for Identity and Access Management, providing:
- Token verification (JWT via JWKS, standard RFC 7517)
- Permission checking (with local caching)
- OAuth2 Client Credentials (service-to-service)
- Multi-tenancy context injection
- Middleware for Kratos (primary) and pure gRPC

The SDK defines **interfaces** backed by **proto service definitions** — concrete backends (gRPC, REST, etc.) are injected via the Option pattern.

---

## Phase 0: Foundation (Server-side Prerequisites)

Before the SDK can be used, the IAM server needs these capabilities:

### P0.1 RS256 JWT Signing + JWKS Endpoint
**Priority:** Critical | **Effort:** 2-3 days | **Location:** IAM server repo

- [ ] Generate RSA key pair for JWT signing
- [ ] Sign JWTs with RS256 (not HS256)
- [ ] Implement `GET /.well-known/jwks.json` endpoint
- [ ] Key rotation support (multiple active keys)

### P0.2 OAuth2 Client Credentials Grant
**Priority:** Critical | **Effort:** 2-3 days | **Location:** IAM server repo

- [ ] OAuth2 token endpoint (`POST /oauth2/token`)
- [ ] Client credentials registration and management
- [ ] Access token issuance with configurable scopes and TTL
- [ ] Rate limiting per client ID

### P0.3 IAM Service for External Consumers
**Priority:** Critical | **Effort:** 2-3 days | **Location:** IAM server repo

- [ ] Endpoints: IntrospectToken, CheckPermission, GetUserPermissions, ValidateTenantMembership
- [ ] Expose service port for external consumers
- [ ] Authentication via OAuth2 Bearer token for service-to-service calls

---

## Phase 1: Core SDK

### P1.1 JWKS Client (TokenVerifier)
**Priority:** Critical | **Effort:** 2 days | **Package:** `jwks/`

- [x] Fetch JWKS from configurable URL
- [x] Parse RSA public keys from JWK format
- [x] Cache keys in memory with configurable refresh interval
- [x] Auto-refresh on key rotation (kid mismatch)
- [x] Verify JWT signature using cached public key
- [x] Extract standard claims (sub, iss, exp, tenant_id, roles) → `iam.Claims`
- [x] Implement `iam.TokenVerifier` interface
- [x] Unit tests with fake JWKS server

### P1.2 Client Core
**Priority:** Critical | **Effort:** 1-2 days | **Package:** root

- [x] `Config` struct with validation
- [x] Option pattern for injecting service implementations
- [x] Accessor methods: `Verifier()`, `Authz()`, `Users()`, `Tenants()`, `Sessions()`, `OAuth2()`
- [x] Context helpers: `WithUserID()`, `UserIDFromContext()`, etc.
- [ ] Connection health check
- [ ] Graceful shutdown (Close)
- [ ] Context propagation (timeout, cancellation)

### P1.3 Interfaces & Types
**Priority:** Critical | **Effort:** Done | **Package:** root

- [x] `TokenVerifier` interface
- [x] `Authorizer` interface (Check, CheckResource, GetPermissions)
- [x] `UserService` interface
- [x] `TenantService` interface
- [x] `SessionService` interface
- [x] `OAuth2TokenExchanger` interface
- [x] Domain types: Claims, User, Role, Tenant, Session, OAuth2Token, ListOptions

### P1.4 Proto Definitions
**Priority:** Critical | **Effort:** Done | **Package:** `proto/iam/v1/`

- [x] Define proto service contracts (AuthzService, UserService, TenantService, SessionService)
- [x] Define proto message types aligned with Go domain types
- [x] `buf.yaml` and `buf.gen.yaml` configuration
- [x] Makefile targets for proto generation
- [ ] Generate Go stubs from proto
- [ ] Conversion functions between proto and domain types

---

## Phase 2: Middleware

### P2.1 Kratos Middleware (Primary)
**Priority:** Critical | **Effort:** 2-3 days | **Package:** `middleware/kratosmw/`

- [x] `Auth(client)` — JWT verification via `client.Verifier()`, injects user context
- [x] `Tenant(client)` — Validates tenant membership via `client.Tenants()`
- [x] `Require(client, permission)` — Permission gate via `client.Authz()`
- [x] `RequireAny(client, ...permissions)` — Any-of permission gate
- [x] `OAuth2ClientCredentials(client)` — OAuth2 client credentials via `client.OAuth2()`
- [x] Works with both HTTP and gRPC transports
- [x] Excluded operations configuration
- [ ] Integration tests with Kratos server

### P2.2 gRPC Interceptors
**Priority:** High | **Effort:** 1-2 days | **Package:** `middleware/grpcmw/`

- [x] `UnaryAuth(client)` — JWT verification for unary RPCs
- [x] `StreamAuth(client)` — JWT verification for streaming
- [x] `UnaryTenant(client)` — Tenant context injection
- [x] `UnaryRequire(client, permission)` — Permission gate
- [x] Excluded methods configuration
- [ ] Integration tests

---

## Phase 3: Extended Features

Note: These interfaces are already defined in the root package. Phase 3 is about providing
reference implementations or backend-specific adapters.

### P3.1 Tenant Operations
**Priority:** Medium | **Effort:** 1-2 days

- [ ] Reference `TenantService` implementation with local caching
- [ ] `SwitchTenant(ctx, tenantID)` → (newTokenPair, error) helper

### P3.2 User Operations
**Priority:** Medium | **Effort:** 1 day

- [ ] Reference `UserService` implementation

### P3.3 Session Operations
**Priority:** Low | **Effort:** 1 day

- [ ] Reference `SessionService` implementation

---

## Phase 4: Testing & Quality

### P4.1 Fake Client
**Priority:** High | **Effort:** Done | **Package:** `fake/`

- [x] `fake.NewClient(options...)` — Returns `*iam.Client` with in-memory implementations
- [x] `fake.WithUser(id, tenantID, email, roles)` — Configure test user
- [x] `fake.WithTenant(id, slug, status)` — Configure test tenant
- [x] `fake.WithPermissions(userID, perms)` — Configure permission rules
- [x] `fake.WithOAuth2App(clientID, clientSecret, scopes)` — Configure test OAuth2 app
- [x] Implements all `iam.*` interfaces
- [x] Full unit tests

### P4.2 Integration Tests
**Priority:** Medium | **Effort:** 2 days

- [ ] Docker Compose test environment (IAM server + PostgreSQL + Redis)
- [ ] End-to-end test: login → get token → verify → check permission
- [ ] End-to-end test: OAuth2 client credentials → token exchange → service auth
- [ ] Multi-tenant isolation test
- [ ] Token refresh and revocation test

### P4.3 CI/CD
**Priority:** Medium | **Effort:** 1 day

- [ ] GitHub Actions: lint + test on PR
- [ ] GitHub Actions: release with semantic versioning
- [ ] Go report card badge
- [ ] Test coverage reporting

---

## Phase 5: Audit & Observability

### P5.1 Audit Log Integration
**Priority:** Medium | **Effort:** 2-3 days

- [ ] Middleware emits audit events (auth success/failure, permission checks)
- [ ] Configurable audit log destination (stdout, callback, etc.)
- [ ] Structured log format (JSON)
- [ ] Request ID propagation

### P5.2 Metrics
**Priority:** Low | **Effort:** 1 day

- [ ] Prometheus metrics: auth_requests_total, auth_failures_total
- [ ] Permission check latency histogram
- [ ] Cache hit/miss ratio

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|-------------|
| P0 (Server prerequisites) | 1-2 weeks | None |
| P1 (Core SDK) | 1 week | P0 |
| P2 (Middleware) | 1 week | P1 |
| P3 (Extended) | 3-5 days | P1 |
| P4 (Testing) | 3-5 days | P1, P2 |
| P5 (Audit) | 2-3 days | P1 |
| **Total** | **~5-6 weeks** | |

---

## Key Design Decisions

### 1. Kratos + Proto-first
- API contracts defined in `proto/iam/v1/iam.proto`
- Kratos middleware is the primary integration (HTTP + gRPC)
- Go interfaces align with proto service definitions
- Generated gRPC stubs for backend communication

### 2. Backend-Agnostic (Interface-Based)
- SDK defines contracts (interfaces), not implementations
- Any IAM server can be integrated by implementing the interfaces
- Injected via Option pattern: `iam.WithAuthorizer(myImpl)`
- Follows Go best practice: accept interfaces, return structs

### 3. RS256 over HS256
- Public key verification — services can't forge tokens
- JWKS auto-distribution — no shared secrets
- Industry standard for multi-service architectures

### 4. Local Cache + Remote Fallback
- Permission decisions cached locally (configurable TTL, default 5 min)
- Reduces latency to ~0ms for cached decisions
- Cache invalidation via TTL (future: event-driven)

### 5. OAuth2 Client Credentials for Service-to-Service
- Standard RFC 6749 grant type for M2M authentication
- No login flow required — client ID + secret exchange for access token
- Token caching with automatic refresh before expiry
- Singleflight to prevent thundering herd on concurrent requests

---

## Reference Projects

| Project | What to learn |
|---------|--------------|
| [kubernetes/client-go](https://github.com/kubernetes/client-go) | SDK API design patterns, interface-based architecture |
| [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) | JWKS implementation reference |
| [ory/ladon](https://github.com/ory/ladon) | Policy-based authorization engine |
| [marmotedu/iam](https://github.com/marmotedu/iam) | API key management, Go SDK design |
| [go-kratos/kratos](https://github.com/go-kratos/kratos) | Framework patterns, middleware design |
