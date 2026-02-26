# IAM-Go SDK Development Roadmap

## Project Goal

Build a backend-agnostic Go SDK for Identity and Access Management, providing:
- Token verification (JWT via JWKS, standard RFC 7517)
- Permission checking (with local caching)
- API Key authentication (service-to-service)
- Multi-tenancy context injection
- Middleware for popular frameworks (Gin, Kratos, gRPC)

The SDK defines **interfaces** — concrete backends (gRPC, REST, etc.) are injected via the Option pattern.

---

## Phase 0: Foundation (Server-side Prerequisites)

Before the SDK can be used, the IAM server needs these capabilities:

### P0.1 RS256 JWT Signing + JWKS Endpoint
**Priority:** Critical | **Effort:** 2-3 days | **Location:** IAM server repo

- [ ] Generate RSA key pair for JWT signing
- [ ] Sign JWTs with RS256 (not HS256)
- [ ] Implement `GET /.well-known/jwks.json` endpoint
- [ ] Key rotation support (multiple active keys)

### P0.2 API Key/Secret Management
**Priority:** Critical | **Effort:** 3-4 days | **Location:** IAM server repo

- [ ] Secret CRUD: Create, List, Delete, Verify, Rotate
- [ ] Database: `api_secrets` table
- [ ] API Key authentication as alternative to JWT
- [ ] Rate limiting per API key

### P0.3 IAM Service for External Consumers
**Priority:** Critical | **Effort:** 2-3 days | **Location:** IAM server repo

- [ ] Endpoints: IntrospectToken, CheckPermission, GetUserPermissions, ValidateTenantMembership
- [ ] Expose service port for external consumers
- [ ] Authentication via API Key for service-to-service calls

---

## Phase 1: Core SDK

### P1.1 JWKS Client (TokenVerifier)
**Priority:** Critical | **Effort:** 2 days | **Package:** `jwks/`

- [ ] Fetch JWKS from configurable URL
- [ ] Parse RSA public keys from JWK format
- [ ] Cache keys in memory with configurable refresh interval
- [ ] Auto-refresh on key rotation (kid mismatch)
- [ ] Verify JWT signature using cached public key
- [ ] Extract standard claims (sub, iss, exp, tenant_id, roles) → `iam.Claims`
- [ ] Implement `iam.TokenVerifier` interface
- [ ] Unit tests with fake JWKS server

### P1.2 Client Core
**Priority:** Critical | **Effort:** 1-2 days | **Package:** root

- [x] `Config` struct with validation
- [x] Option pattern for injecting service implementations
- [x] Accessor methods: `Verifier()`, `Authz()`, `Users()`, `Tenants()`, `Sessions()`, `Secrets()`
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
- [x] `SecretService` interface
- [x] Domain types: Claims, User, Role, Tenant, Session, Secret, ListOptions

---

## Phase 2: Middleware

### P2.1 Gin Middleware
**Priority:** Critical | **Effort:** 2-3 days | **Package:** `middleware/`

- [ ] `GinAuth(client)` — JWT verification via `client.Verifier()`, injects user context
- [ ] `GinTenant(client)` — Extracts tenant_id via `client.Tenants()`, validates membership
- [ ] `GinRequire(client, permission)` — Permission gate via `client.Authz()`
- [ ] `GinRequireAny(client, ...permissions)` — Any-of permission gate
- [ ] `GinAPIKey(client)` — API Key authentication via `client.Secrets()`
- [ ] Context helpers: `GetUserID(c)`, `GetTenantID(c)`, `GetRoles(c)`
- [ ] Excluded paths configuration (public routes)
- [ ] Integration tests

### P2.2 Kratos Middleware
**Priority:** High | **Effort:** 2 days | **Package:** `middleware/`

- [ ] `KratosAuth(client)` — JWT verification middleware
- [ ] `KratosTenant(client)` — Tenant context middleware
- [ ] `KratosRequire(client, permission)` — Permission gate
- [ ] Works with both HTTP and gRPC transports

### P2.3 gRPC Interceptors
**Priority:** High | **Effort:** 1-2 days | **Package:** `middleware/`

- [ ] `UnaryAuthInterceptor(client)` — JWT verification for unary RPCs
- [ ] `StreamAuthInterceptor(client)` — JWT verification for streaming
- [ ] `UnaryTenantInterceptor(client)` — Tenant context injection
- [ ] Metadata propagation (user_id, tenant_id, roles)

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
**Priority:** High | **Effort:** 2 days | **Package:** `fake/`

- [ ] `fake.NewClient(options...)` — Returns `*iam.Client` with in-memory implementations
- [ ] `fake.WithUser(id, tenantID, roles)` — Configure test user
- [ ] `fake.WithTenant(id, slug, status)` — Configure test tenant
- [ ] `fake.WithPermissions(map)` — Configure permission rules
- [ ] `fake.WithAPIKey(key, secret, userID)` — Configure test API key
- [ ] Implements all `iam.*` interfaces
- [ ] Full unit tests

### P4.2 Integration Tests
**Priority:** Medium | **Effort:** 2 days

- [ ] Docker Compose test environment (IAM server + PostgreSQL + Redis)
- [ ] End-to-end test: login → get token → verify → check permission
- [ ] End-to-end test: API key creation → service auth → permission check
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

### 1. Backend-Agnostic (Interface-Based)
- SDK defines contracts (interfaces), not implementations
- Any IAM server can be integrated by implementing the interfaces
- Injected via Option pattern: `iam.WithAuthorizer(myImpl)`
- Follows Go best practice: accept interfaces, return structs

### 2. RS256 over HS256
- Public key verification — services can't forge tokens
- JWKS auto-distribution — no shared secrets
- Industry standard for multi-service architectures

### 3. Local Cache + Remote Fallback
- Permission decisions cached locally (configurable TTL, default 5 min)
- Reduces latency to ~0ms for cached decisions
- Cache invalidation via TTL (future: event-driven)

### 4. API Key for Service-to-Service
- Long-lived credentials (unlike JWT)
- No login flow required
- Per-service key isolation
- Can be rotated without downtime

---

## Reference Projects

| Project | What to learn |
|---------|--------------|
| [kubernetes/client-go](https://github.com/kubernetes/client-go) | SDK API design patterns, interface-based architecture |
| [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) | JWKS implementation reference |
| [ory/ladon](https://github.com/ory/ladon) | Policy-based authorization engine |
| [marmotedu/iam](https://github.com/marmotedu/iam) | API key management, Go SDK design |
