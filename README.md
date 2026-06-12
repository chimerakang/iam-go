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

**Architecture:** Proto-first contracts, framework-agnostic middleware

## Framework Support

The same Auth / Tenant / Require / RequireAny middleware stack is provided for each framework — pick the one matching your service:

| Framework | Package | Example |
|-----------|---------|---------|
| Kratos (HTTP + gRPC) | `middleware/kratosmw/` | [examples/kratos-service](examples/kratos-service) |
| Standard `net/http` (also Chi, Echo via adapters) | `middleware/httpmw/` | [examples/std-http-service](examples/std-http-service) |
| Gin | `middleware/ginmw/` | [examples/gin-service](examples/gin-service) |
| Pure gRPC | `middleware/grpcmw/` | [examples/grpc-service](examples/grpc-service) |

All four share the same core logic and error semantics; only the framework adapter differs.

## Architecture

```
Your Service (Kratos / net/http / Gin / gRPC)
    │
    ├── <mw>.Auth(client)              ← JWT verification (local, via JWKS)
    ├── <mw>.Tenant(client)            ← Tenant context injection
    ├── <mw>.Require(client, p)        ← Permission check
    │                                    (kratosmw / httpmw / ginmw / grpcmw)
    └── client.Authz().Check()         ← Direct permission query
        client.Users().GetCurrent()
        client.OAuth2().GetCachedToken() ← OAuth2 M2M token
```

## Installation

```bash
go get github.com/chimerakang/iam-go
```

## Quick Start

### One-liner (Valhalla backend)

```go
import "github.com/chimerakang/iam-go/valhalla"

client, err := valhalla.New("iam.example.com:50051",
    valhalla.WithOAuth2(os.Getenv("IAM_CLIENT_ID"), os.Getenv("IAM_CLIENT_SECRET")), // optional M2M
)
// JWKS verifier, cached authorizer, user/tenant/session/auth services — all wired.
```

### Manual assembly (any backend)

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
| `middleware/httpmw/` | Standard library net/http middleware — same stack, plus `Chain` |
| `middleware/ginmw/` | Gin middleware — same stack as `gin.HandlerFunc` |
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
| `AuthService` | User login (email/password + social OAuth) |

## Authentication Methods

### JWT Token (for end users)
```go
// Middleware verifies JWT via any JWKS-compliant endpoint — pick your framework:
kratosmw.Auth(client)                              // Kratos
mux.Handle("/api/", httpmw.Auth(client)(handler))  // net/http
r.Use(ginmw.Auth(client))                          // Gin
```

### OAuth2 Client Credentials (for services)
```go
// Service-to-service authentication via OAuth2 token
kratosmw.OAuth2ClientCredentials(client)
```

### Email / Password Login
```go
resp, err := client.Auth().Login(ctx, iam.LoginRequest{
    Email:    "user@example.com",
    Password: "secret",
    TenantID: "tenant-uuid",
    AppID:    "my_app",
})
```

### Social Login — Google / Apple / LINE (BFF pattern)
```go
// Backend-for-Frontend: backend exchanges authorization code for id_token,
// then calls IAM to get a Valhalla JWT.
resp, err := client.Auth().SocialLogin(ctx, iam.SocialLoginRequest{
    Provider: "line",          // "google", "apple", "line"
    IDToken:  lineIDToken,     // obtained server-side from provider
    Nonce:    sessionNonce,    // replay prevention (required for Apple / LINE)
    AppID:    "hospital_erp_mobile",
    TenantID: "tenant-uuid",
})
// resp.Tokens.AccessToken — Valhalla JWT ready to use
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
        fake.WithSocialLogin("line", &iam.User{
            ID:       "user1",
            Email:    "user@example.com",
            TenantID: "tenant1",
        }, &iam.TokenPair{
            AccessToken: "fake-jwt",
            TokenType:   "Bearer",
            ExpiresIn:   3600,
        }),
    )

    ctx := fake.ContextWithUserID(context.Background(), "user1")
    ok, _ := client.Authz().Check(ctx, "users:read")
    // ok == true

    // Test social login
    resp, _ := client.Auth().SocialLogin(ctx, iam.SocialLoginRequest{
        Provider: "line",
        IDToken:  "any-token",
        AppID:    "test_app",
    })
    // resp.Tokens.AccessToken == "fake-jwt"
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
