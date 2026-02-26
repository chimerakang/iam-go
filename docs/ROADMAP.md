# IAM-Go SDK Development Roadmap

## Project Goal

Build a Go SDK that enables any Go service to integrate with Valhalla's centralized IAM, providing:
- Token verification (JWT via JWKS)
- Permission checking (gRPC with local caching)
- API Key authentication (service-to-service)
- Multi-tenancy context injection
- Middleware for popular frameworks (Gin, Kratos, gRPC)

---

## Phase 0: Foundation (Valhalla-side Prerequisites)

Before the SDK can work, Valhalla IAM needs these server-side features:

### P0.1 RS256 JWT Signing + JWKS Endpoint
**Priority:** Critical | **Effort:** 2-3 days | **Location:** Valhalla repo

- [ ] Generate RSA key pair for JWT signing
- [ ] Switch JWT signing from HS256 to RS256
- [ ] Implement `GET /.well-known/jwks.json` endpoint
- [ ] Key rotation support (multiple active keys)
- [ ] Update existing middleware to support RS256 verification

### P0.2 API Key/Secret Management
**Priority:** Critical | **Effort:** 3-4 days | **Location:** Valhalla repo

- [ ] Proto definition: `SecretService` (Create, List, Delete, Verify, Rotate)
- [ ] Database migration: `api_secrets` table
- [ ] Biz layer: SecretUseCase (generation, hashing, verification)
- [ ] Service layer: gRPC implementation
- [ ] API Key authentication middleware (alternative to JWT)
- [ ] Rate limiting per API key

### P0.3 IAM gRPC Service for External Consumers
**Priority:** Critical | **Effort:** 2-3 days | **Location:** Valhalla repo

- [ ] Proto definition: `IAMService` (IntrospectToken, CheckPermission, GetUserPermissions, ValidateTenantMembership)
- [ ] Service layer implementation
- [ ] Expose gRPC port for external services (already partially done: Issue #133)
- [ ] Authentication via API Key for service-to-service calls

---

## Phase 1: Core SDK

### P1.1 JWKS Client
**Priority:** Critical | **Effort:** 2 days | **Package:** `jwks/`

- [ ] Fetch JWKS from configurable URL
- [ ] Parse RSA public keys from JWK format
- [ ] Cache keys in memory with configurable refresh interval
- [ ] Auto-refresh on key rotation (kid mismatch)
- [ ] Verify JWT signature using cached public key
- [ ] Extract standard claims (sub, iss, exp, tenant_id, roles)
- [ ] Unit tests with fake JWKS server

### P1.2 Client Core
**Priority:** Critical | **Effort:** 1-2 days | **Package:** root

- [ ] `Config` struct with validation
- [ ] gRPC connection management (dial, keepalive, retry)
- [ ] API Key authentication interceptor
- [ ] Connection health check
- [ ] Graceful shutdown (Close)
- [ ] Context propagation (timeout, cancellation)

### P1.3 Authorization Client
**Priority:** Critical | **Effort:** 2 days | **Package:** `authz/`

- [ ] `Check(ctx, permission)` → bool
- [ ] `CheckResource(ctx, resource, action)` → bool
- [ ] `GetUserPermissions(ctx)` → []string
- [ ] Local cache with configurable TTL (default 5 min)
- [ ] Cache invalidation on permission change
- [ ] Batch permission check support
- [ ] Unit tests with fake server

### P1.4 Secret Client
**Priority:** High | **Effort:** 1-2 days | **Package:** `secret/`

- [ ] `Create(ctx, description)` → (apiKey, apiSecret)
- [ ] `List(ctx)` → []Secret
- [ ] `Delete(ctx, secretID)` → error
- [ ] `Verify(ctx, apiKey, apiSecret)` → (claims, error)
- [ ] `Rotate(ctx, secretID)` → (newSecret)

---

## Phase 2: Middleware

### P2.1 Gin Middleware
**Priority:** Critical | **Effort:** 2-3 days | **Package:** `middleware/`

- [ ] `GinAuth(client)` — JWT verification via JWKS, injects user context
- [ ] `GinTenant(client)` — Extracts tenant_id, validates membership
- [ ] `GinRequire(client, permission)` — Permission gate
- [ ] `GinRequireAny(client, ...permissions)` — Any-of permission gate
- [ ] `GinAPIKey(client)` — API Key authentication (for service endpoints)
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

### P3.1 Tenant Client
**Priority:** Medium | **Effort:** 1-2 days | **Package:** `tenant/`

- [ ] `Resolve(ctx, slug)` → Tenant
- [ ] `ResolveBySubdomain(ctx, subdomain)` → Tenant
- [ ] `ValidateMembership(ctx, userID, tenantID)` → bool
- [ ] `SwitchTenant(ctx, tenantID)` → (newTokenPair, error)
- [ ] Local tenant cache

### P3.2 User Client
**Priority:** Medium | **Effort:** 1 day | **Package:** `user/`

- [ ] `GetCurrent(ctx)` → User
- [ ] `Get(ctx, userID)` → User
- [ ] `List(ctx, options)` → ([]User, total)
- [ ] `GetRoles(ctx, userID)` → []Role

### P3.3 Session Client
**Priority:** Low | **Effort:** 1 day | **Package:** `session/`

- [ ] `List(ctx)` → []Session
- [ ] `Revoke(ctx, sessionID)` → error
- [ ] `RevokeAllOthers(ctx)` → error

---

## Phase 4: Testing & Quality

### P4.1 Fake Client
**Priority:** High | **Effort:** 2 days | **Package:** `fake/`

- [ ] `fake.NewClient(options...)` — In-memory IAM client
- [ ] `fake.WithUser(id, tenantID, roles)` — Configure test user
- [ ] `fake.WithTenant(id, slug, status)` — Configure test tenant
- [ ] `fake.WithPermissions(map)` — Configure permission rules
- [ ] `fake.WithAPIKey(key, secret, userID)` — Configure test API key
- [ ] Implements same interfaces as real client
- [ ] Full unit tests

### P4.2 Integration Tests
**Priority:** Medium | **Effort:** 2 days

- [ ] Docker Compose test environment (Valhalla IAM + PostgreSQL + Redis)
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
- [ ] Configurable audit log destination (stdout, gRPC → Valhalla)
- [ ] Structured log format (JSON)
- [ ] Request ID propagation

### P5.2 Metrics
**Priority:** Low | **Effort:** 1 day

- [ ] Prometheus metrics: auth_requests_total, auth_failures_total
- [ ] Permission check latency histogram
- [ ] Cache hit/miss ratio
- [ ] gRPC connection health

---

## Timeline Estimate

| Phase | Duration | Dependencies |
|-------|----------|-------------|
| P0 (Valhalla prerequisites) | 1-2 weeks | None |
| P1 (Core SDK) | 1 week | P0.1, P0.2, P0.3 |
| P2 (Middleware) | 1 week | P1 |
| P3 (Extended) | 3-5 days | P1 |
| P4 (Testing) | 3-5 days | P1, P2 |
| P5 (Audit) | 2-3 days | P1 |
| **Total** | **~5-6 weeks** | |

---

## Key Design Decisions

### 1. RS256 over HS256
- Public key verification — services can't forge tokens
- JWKS auto-distribution — no shared secrets
- Industry standard for multi-service architectures

### 2. gRPC for Service Communication
- Type-safe via protobuf
- Efficient binary protocol
- Bidirectional streaming support
- Native Go support

### 3. Local Cache + gRPC Fallback
- Permission decisions cached locally (5 min default)
- Reduces latency to ~0ms for cached decisions
- Falls back to gRPC when cache misses
- Cache invalidation via TTL (future: Redis Pub/Sub)

### 4. API Key for Service-to-Service
- Long-lived credentials (unlike JWT)
- No login flow required
- Per-service key isolation
- Can be rotated without downtime

### 5. Interface-Based Design
- All client components implement interfaces
- Enables fake implementations for testing
- Follows Go best practices (accept interfaces, return structs)

---

## Reference Projects

| Project | What to learn |
|---------|--------------|
| [marmotedu/iam](https://github.com/marmotedu/iam) | API key management, authz server separation, Go SDK design |
| [kubernetes/client-go](https://github.com/kubernetes/client-go) | SDK API design patterns, interface-based architecture |
| [ory/ladon](https://github.com/ory/ladon) | Policy-based authorization engine |
| [lestrrat-go/jwx](https://github.com/lestrrat-go/jwx) | JWKS implementation reference |
