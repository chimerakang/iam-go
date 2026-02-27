# iam-go

Go SDK for Identity and Access Management — Authentication, Authorization, and Multi-tenancy client library.

## Overview

`iam-go` is a Go SDK for integrating with **any IAM server** that implements the standard Identity and Access Management capabilities. It enables any Go service to:

- **Verify JWT tokens** locally via JWKS (RS256 public key) — no network calls
- **Check permissions** with local caching
- **OAuth2 Client Credentials** for service-to-service authentication
- **Inject tenant context** automatically via middleware

The SDK is **backend-agnostic** — all services are defined as interfaces. Concrete implementations (gRPC, REST, in-memory) are injected via the Option pattern.

> **What is a "Standard IAM Server"?**
>
> Any IAM server that implements the **P0 Requirements** (see [Roadmap](docs/ROADMAP.md)):
> - **P0.1**: RS256 JWT signing + JWKS endpoint
> - **P0.2**: OAuth2 Client Credentials Grant (service-to-service)
> - **P0.3**: IAM service API for external token verification and permission checking
>
> Once your IAM server implements these, any service using `iam-go` can authenticate and authorize without vendor lock-in.

**Architecture:** Kratos + Proto-first

> **Architecture Rule:** This SDK is built on **go-kratos/kratos** with Proto-first API design.
> Gin, Echo, Chi, and other HTTP frameworks are intentionally excluded.
> Kratos middleware handles both HTTP and gRPC transports — no need for framework-specific adapters.

## Architecture

```
Your Service (Kratos-based)
    │
    ├── kratosmw.Auth(client)          ← JWT verification (local, via JWKS)
    ├── kratosmw.Tenant(client)        ← Tenant context injection
    ├── kratosmw.Require(client, p)    ← Permission check
    │                                    (works with both HTTP and gRPC)
    └── client.Authz().Check()         ← Direct permission query
        client.Users().GetCurrent()
        client.OAuth2().GetCachedToken() ← OAuth2 M2M token
```

## Installation

```bash
go get github.com/chimerakang/iam-go
```

## Quick Start

```go
package main

import (
    iam "github.com/chimerakang/iam-go"
    "github.com/chimerakang/iam-go/middleware/kratosmw"
    "github.com/go-kratos/kratos/v2/transport/http"
)

func main() {
    // Initialize IAM client with injected implementations
    client, err := iam.NewClient(
        iam.Config{
            Endpoint:           "iam-server:9000",
            JWKSUrl:            "https://auth.example.com/.well-known/jwks.json",
            OAuth2ClientID:     os.Getenv("IAM_OAUTH2_CLIENT_ID"),
            OAuth2ClientSecret: os.Getenv("IAM_OAUTH2_CLIENT_SECRET"),
            OAuth2TokenURL:     os.Getenv("IAM_OAUTH2_TOKEN_URL"),
        },
        iam.WithTokenVerifier(myVerifier),
        iam.WithAuthorizer(myAuthz),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Kratos HTTP server with IAM middleware
    httpSrv := http.NewServer(
        http.Middleware(
            kratosmw.Auth(client),
            kratosmw.Tenant(client),
        ),
    )
}
```

## Packages

| Package | Description |
|---------|-------------|
| `iam-go` (root) | Client, Config, Option pattern, interfaces, domain types, context helpers |
| `middleware/kratosmw/` | Kratos middleware — Auth, Tenant, Require (HTTP + gRPC) |
| `middleware/grpcmw/` | Pure gRPC interceptors (for non-Kratos services) |
| `jwks/` | JWKS-based TokenVerifier (standard RFC 7517) |
| `fake/` | In-memory implementations for testing |
| `proto/iam/v1/` | Proto service definitions and generated gRPC stubs |

## Core Interfaces

The root package defines these interfaces — implement them to integrate with any IAM backend:

| Interface | Purpose |
|-----------|---------|
| `TokenVerifier` | Verify tokens, extract claims |
| `Authorizer` | Check permissions (with caching) |
| `UserService` | User CRUD and role queries |
| `TenantService` | Tenant resolution and membership |
| `SessionService` | Session management |
| `OAuth2TokenExchanger` | OAuth2 client credentials token exchange |

## Authentication Methods

### JWT Token (for end users)
```go
// Kratos middleware verifies JWT via any JWKS-compliant endpoint
kratosmw.Auth(client)
```

### OAuth2 Client Credentials (for services)
```go
// Service-to-service authentication via OAuth2 token
kratosmw.OAuth2ClientCredentials(client)
```

## Proto-first Development

Service contracts are defined in `proto/iam/v1/iam.proto`. Generate Go stubs with:

```bash
make proto       # Generate gRPC stubs
make proto-lint  # Lint proto files
```

## Testing

Use the `fake` package for unit tests without a real IAM server:

```go
import "github.com/chimerakang/iam-go/fake"

func TestMyHandler(t *testing.T) {
    client := fake.NewClient(
        fake.WithUser("user1", "tenant1", "user1@test.com", []string{"admin"}),
        fake.WithPermissions("user1", []string{"users:read"}),
    )

    ctx := fake.ContextWithUserID(context.Background(), "user1")
    ok, _ := client.Authz().Check(ctx, "users:read")
    // ok == true
}
```

## Build

```bash
make build       # go build ./...
make test        # go test ./...
make lint        # go vet ./...
make proto       # buf generate
```

## License

MIT License - see [LICENSE](LICENSE) for details.
