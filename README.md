# iam-go

Go SDK for Identity and Access Management — Authentication, Authorization, and Multi-tenancy client library.

## Overview

`iam-go` provides a unified Go client for integrating with centralized IAM services. It enables any Go service to:

- **Verify JWT tokens** locally via JWKS (RS256 public key)
- **Check permissions** with local caching
- **Manage API Keys** for service-to-service authentication
- **Inject tenant context** automatically via middleware

The SDK is **backend-agnostic** — all services are defined as interfaces. Concrete implementations (gRPC, REST, in-memory) are injected via the Option pattern.

## Architecture

```
Your Service (e.g., workforce-saas)
    │
    ├── middleware.GinAuth(client)       ← JWT verification (local, via JWKS)
    ├── middleware.GinTenant(client)     ← Tenant context injection
    ├── middleware.GinRequire(client, p) ← Permission check
    │
    └── client.Authz().Check()          ← Direct permission query
        client.Users().GetCurrent()
        client.Secrets().Verify()
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
    "github.com/chimerakang/iam-go/middleware"
)

func main() {
    // Initialize IAM client with injected implementations
    client, err := iam.NewClient(
        iam.Config{
            Endpoint: "iam-server:9000",
            JWKSUrl:  "https://auth.example.com/.well-known/jwks.json",
            APIKey:   os.Getenv("IAM_API_KEY"),
            APISecret: os.Getenv("IAM_API_SECRET"),
        },
        iam.WithTokenVerifier(myVerifier),
        iam.WithAuthorizer(myAuthz),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Gin middleware example
    router := gin.Default()
    router.Use(middleware.GinAuth(client))      // Verify JWT
    router.Use(middleware.GinTenant(client))     // Inject tenant context

    // Protected route with permission check
    api := router.Group("/api/v1")
    api.GET("/records",
        middleware.GinRequire(client, "attendance:record:read"),
        handleListRecords,
    )
}
```

## Packages

| Package | Description |
|---------|-------------|
| `iam-go` (root) | Client, Config, Option pattern, interfaces, domain types |
| `middleware/` | Gin, Kratos, gRPC middleware/interceptors |
| `jwks/` | JWKS-based TokenVerifier (standard RFC 7517) |
| `fake/` | In-memory implementations for testing |
| `proto/` | Generated gRPC stubs (optional) |

## Core Interfaces

The root package defines these interfaces — implement them to integrate with any IAM backend:

| Interface | Purpose |
|-----------|---------|
| `TokenVerifier` | Verify tokens, extract claims |
| `Authorizer` | Check permissions (with caching) |
| `UserService` | User CRUD and role queries |
| `TenantService` | Tenant resolution and membership |
| `SessionService` | Session management |
| `SecretService` | API key/secret lifecycle |

## Authentication Methods

### JWT Token (for end users)
```go
// Middleware verifies JWT via any JWKS-compliant endpoint
router.Use(middleware.GinAuth(client))
```

### API Key/Secret (for services)
```go
// Service-to-service authentication
client, _ := iam.NewClient(iam.Config{
    Endpoint:  "iam-server:9000",
    APIKey:    os.Getenv("IAM_API_KEY"),
    APISecret: os.Getenv("IAM_API_SECRET"),
})
```

## Testing

Use the `fake` package for unit tests without a real IAM server:

```go
import "github.com/chimerakang/iam-go/fake"

func TestMyHandler(t *testing.T) {
    client := fake.NewClient(fake.WithUser("user1", "tenant1", []string{"admin"}))

    // Use client in tests — no network calls
    ok, _ := client.Authz().Check(ctx, "users:read")
    assert.True(t, ok)
}
```

## License

MIT License - see [LICENSE](LICENSE) for details.
