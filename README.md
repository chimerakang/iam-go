# iam-go

Go SDK for [Valhalla IAM](https://github.com/haticestudio/valhalla) — Authentication, Authorization, and Multi-tenancy client library.

## Overview

`iam-go` provides a unified Go client for integrating with Valhalla's centralized IAM service. It enables any Go service to:

- **Verify JWT tokens** locally via JWKS (RS256 public key)
- **Check permissions** via gRPC with local caching
- **Manage API Keys** for service-to-service authentication
- **Inject tenant context** automatically via middleware
- **Audit trail** integration

## Architecture

```
Your Service (e.g., workforce-saas)
    │
    ├── middleware.GinAuth()       ← JWT verification (local, via JWKS public key)
    ├── middleware.GinTenant()     ← Tenant context injection
    ├── middleware.GinRequire()    ← Permission check (gRPC → Valhalla IAM)
    │
    └── client.Authz().Check()    ← Direct permission query
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
    // Initialize IAM client
    client, err := iam.NewClient(iam.Config{
        Endpoint:  "valhalla-iam:9000",        // gRPC endpoint
        JWKSUrl:   "http://valhalla:8080/.well-known/jwks.json",
        APIKey:    os.Getenv("IAM_API_KEY"),
        APISecret: os.Getenv("IAM_API_SECRET"),
    })
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
| `iam-go` (root) | Client initialization, configuration |
| `middleware/` | Gin, Kratos, gRPC middleware/interceptors |
| `jwks/` | JWKS public key fetching and caching |
| `authz/` | Authorization decision client |
| `secret/` | API Key/Secret management client |
| `tenant/` | Tenant context and resolution |
| `user/` | User management client |
| `session/` | Session management client |
| `fake/` | In-memory fake implementations for testing |
| `proto/` | Generated gRPC stubs (lightweight) |

## Authentication Methods

### JWT Token (for end users)
```go
// Middleware automatically verifies JWT via JWKS
router.Use(middleware.GinAuth(client))
```

### API Key/Secret (for services)
```go
// Service-to-service authentication
client, _ := iam.NewClient(iam.Config{
    Endpoint:  "valhalla-iam:9000",
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
