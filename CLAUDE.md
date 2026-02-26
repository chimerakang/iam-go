# IAM-Go SDK Development Guide

## Project Overview

**Module:** `github.com/chimerakang/iam-go`
**Purpose:** Go SDK for Valhalla IAM — enables any Go service to integrate with centralized authentication, authorization, and multi-tenancy.
**Related:** [Valhalla](https://github.com/haticestudio/valhalla) (IAM server)

## Architecture

```
iam-go/
├── client.go              # Client initialization, Config
├── middleware/
│   ├── gin.go             # Gin middleware (GinAuth, GinTenant, GinRequire)
│   ├── kratos.go          # Kratos middleware
│   └── grpc.go            # gRPC interceptors
├── jwks/
│   └── jwks.go            # JWKS public key fetching + caching
├── authz/
│   └── authz.go           # Authorization decision client
├── secret/
│   └── secret.go          # API Key/Secret management
├── tenant/
│   └── tenant.go          # Tenant context + resolution
├── user/
│   └── user.go            # User management client
├── session/
│   └── session.go         # Session management client
├── fake/
│   └── fake.go            # In-memory fake for testing
├── proto/iam/v1/          # Generated gRPC stubs
└── docs/
    └── ROADMAP.md         # Development roadmap
```

## Development Conventions

- **Interface-based design:** All components expose interfaces, implementations are private
- **Testing:** Use `fake/` package for unit tests, no external dependencies
- **Error handling:** Wrap errors with context, use `fmt.Errorf("iam: %w", err)`
- **Logging:** Accept `log/slog.Logger` via options, no global loggers
- **Context:** All methods take `context.Context` as first parameter

## Git Workflow

- `main` branch for releases
- `develop` branch for active development
- Semantic versioning: `v0.1.0`, `v0.2.0`, etc.
- Tag releases for Go module versioning

## Key Design Principles

1. **Zero network calls for JWT verification** — use JWKS public keys locally
2. **Cache permission decisions** — reduce gRPC calls to IAM server
3. **API Key for service-to-service** — no login flow needed
4. **Fake implementations for testing** — no real IAM server needed in tests
5. **Framework agnostic** — core logic independent of Gin/Kratos/etc.
