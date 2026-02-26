# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Module:** `github.com/chimerakang/iam-go`
**Purpose:** Backend-agnostic Go SDK for Identity and Access Management — authentication, authorization, and multi-tenancy.
**Architecture:** Kratos + Proto-first
**Status:** Core interfaces, types, JWKS verifier, Kratos middleware, gRPC interceptors, and fake test doubles implemented. Proto definitions ready for code generation.

## Build & Development Commands

```bash
# Build / verify compilation
go build ./...

# Run all tests
go test ./...

# Run a single package's tests
go test ./jwks/...

# Run a specific test by name
go test ./middleware/kratosmw/... -run TestAuth

# Run tests with verbose output
go test -v ./...

# Vet / static analysis
go vet ./...

# Proto generation (requires buf)
make proto

# Proto linting
make proto-lint

# Install build tools (one-time)
make init
```

## Architecture

This is a **Kratos + Proto-first** Go SDK library. All service contracts are proto-defined and exposed as Go interfaces in the root package; implementations are injected via Options.

```
Root package (iam)
├── client.go       → Client, Config, Option pattern, accessor methods
├── interfaces.go   → TokenVerifier, Authorizer, UserService, TenantService,
│                     SessionService, SecretService (pure interfaces)
├── types.go        → Claims, User, Role, Tenant, Session, Secret, ListOptions
├── context.go      → Shared context helpers (WithUserID, UserIDFromContext, etc.)

proto/iam/v1/       → Proto-first service definitions (source of truth for API contracts)
                      AuthzService, UserService, TenantService, SessionService, SecretService

jwks/               → TokenVerifier implementation using standard JWKS (RFC 7517)
                      Compatible with any OIDC provider, not tied to a specific backend.

middleware/
  kratosmw/         → Primary middleware — Kratos HTTP + gRPC (Auth, Tenant, Require, APIKey)
  grpcmw/           → Pure gRPC interceptors (for non-Kratos services)

fake/               → In-memory implementations of all interfaces for testing.
```

**Data flow:** Request → Kratos middleware verifies JWT via `client.Verifier()` (local JWKS) → middleware checks permission via `client.Authz()` (cached) → handler uses `client.Users()`/`client.Tenants()` etc.

**Key pattern:** The SDK defines *what* (interfaces + proto), not *how* (implementation). A gRPC-backed implementation for a specific IAM server would satisfy these interfaces and be injected via `iam.WithAuthorizer(myGrpcAuthz)`.

## Development Conventions

- **Proto-first:** API contracts defined in `proto/iam/v1/iam.proto`, Go interfaces align with proto services
- **Kratos-native:** Primary middleware uses Kratos `middleware.Middleware` pattern (works with HTTP + gRPC)
- **Interface-based design:** All service contracts are interfaces in the root package; implementations are unexported
- **Option pattern:** Services injected via `iam.With*()` functions — no hardcoded backends
- **Context helpers:** Use root package `iam.WithUserID()` / `iam.UserIDFromContext()` — never define context keys in sub-packages
- **Error prefix:** Wrap errors with `fmt.Errorf("iam: %w", err)`
- **Logging:** Accept `log/slog.Logger` via `iam.WithLogger()` — no global loggers
- **Context:** All methods take `context.Context` as first parameter
- **Testing:** Use `fake/` package — no real IAM server needed in tests

## Architecture Constraints (MUST follow)

This project follows a strict **Kratos + Proto-first** architecture. These rules are non-negotiable:

| Rule | Description |
|------|-------------|
| **No Gin** | Do NOT add Gin middleware, Gin dependencies, or any `gin-gonic` imports. Gin was explicitly removed. |
| **No other HTTP frameworks** | Do NOT add Echo, Chi, Fiber, or any non-Kratos HTTP framework middleware. |
| **Kratos is primary** | All HTTP + gRPC middleware MUST use Kratos `middleware.Middleware` pattern (`middleware/kratosmw/`). |
| **Proto-first** | New API contracts MUST be defined in `proto/iam/v1/iam.proto` first, then aligned in Go interfaces. |
| **Shared context keys** | All context key definitions MUST live in root `context.go`. Sub-packages MUST NOT define their own `ctxKey` types. |
| **Pure gRPC is secondary** | `middleware/grpcmw/` exists only for non-Kratos gRPC services. Prefer `kratosmw` for Kratos projects. |

If you are unsure whether a change violates these constraints, ask before proceeding.

## Key Design Principles

1. **Kratos + Proto-first** — proto defines contracts, Kratos is the primary framework
2. **Backend-agnostic** — interfaces define contracts, any IAM server can be used
3. **Zero network calls for JWT verification** — JWKS public keys cached locally
4. **Cache permission decisions** — local TTL cache reduces round-trips
5. **API Key for service-to-service** — no login flow needed
6. **Transport-agnostic middleware** — Kratos middleware works with both HTTP and gRPC

## Git Workflow

- `main` branch for releases
- `develop` branch for active development
- Semantic versioning: `v0.1.0`, `v0.2.0`, etc.
- Tag releases for Go module versioning
