# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Module:** `github.com/chimerakang/iam-go`
**Purpose:** Backend-agnostic Go SDK for Identity and Access Management — authentication, authorization, and multi-tenancy.
**Status:** Early scaffold — `client.go` has Config/NewClient/Option pattern; all service packages are TODO stubs.

## Build & Development Commands

```bash
# Build / verify compilation
go build ./...

# Run all tests
go test ./...

# Run a single package's tests
go test ./jwks/...

# Run a specific test by name
go test ./middleware/... -run TestGinAuth

# Run tests with verbose output
go test -v ./...

# Vet / static analysis
go vet ./...
```

No Makefile or CI pipeline exists yet. Proto stubs (`proto/iam/v1/`) are empty.

## Architecture

This is a **multi-package Go library** (not a binary). All service contracts are interfaces in the root package; implementations are injected via Options.

```
Root package (iam)
├── client.go       → Client, Config, Option pattern, accessor methods
├── interfaces.go   → TokenVerifier, Authorizer, UserService, TenantService,
│                     SessionService, SecretService (pure interfaces)
├── types.go        → Claims, User, Role, Tenant, Session, Secret, ListOptions

jwks/               → TokenVerifier implementation using standard JWKS (RFC 7517)
                      Compatible with any OIDC provider, not tied to a specific backend.

middleware/         → Framework integrations (Gin, Kratos, gRPC)
  gin.go            →   GinAuth, GinTenant, GinRequire
  kratos.go         →   KratosAuth, KratosTenant, KratosRequire
  grpc.go           →   UnaryAuthInterceptor, StreamAuthInterceptor

fake/               → In-memory implementations of all interfaces for testing.

proto/iam/v1/       → Placeholder for generated gRPC stubs (empty).
```

**Data flow:** HTTP request → middleware verifies JWT via `client.Verifier()` (local JWKS) → middleware checks permission via `client.Authz()` (cached) → handler uses `client.Users()`/`client.Tenants()` etc.

**Key pattern:** The SDK defines *what* (interfaces), not *how* (implementation). A gRPC-backed implementation for a specific IAM server would be a separate package or module that satisfies these interfaces and is injected via `iam.WithAuthorizer(myGrpcAuthz)`.

## Development Conventions

- **Interface-based design:** All service contracts are interfaces in the root package; implementations are unexported
- **Option pattern:** Services injected via `iam.With*()` functions — no hardcoded backends
- **Error prefix:** Wrap errors with `fmt.Errorf("iam: %w", err)`
- **Logging:** Accept `log/slog.Logger` via `iam.WithLogger()` — no global loggers
- **Context:** All methods take `context.Context` as first parameter
- **Testing:** Use `fake/` package — no real IAM server needed in tests

## Key Design Principles

1. **Backend-agnostic** — interfaces define contracts, any IAM server can be used
2. **Zero network calls for JWT verification** — JWKS public keys cached locally
3. **Cache permission decisions** — local TTL cache reduces round-trips
4. **API Key for service-to-service** — no login flow needed
5. **Framework agnostic** — core logic independent of Gin/Kratos/etc.

## Git Workflow

- `main` branch for releases
- `develop` branch for active development
- Semantic versioning: `v0.1.0`, `v0.2.0`, etc.
- Tag releases for Go module versioning
