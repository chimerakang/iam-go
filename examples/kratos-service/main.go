// Example: Kratos HTTP+gRPC service with iam-go middleware.
//
// Demonstrates:
//   - JWT authentication via kratosmw.Auth
//   - Tenant membership validation via kratosmw.Tenant
//   - Permission gating via kratosmw.Require
//   - API key authentication via kratosmw.APIKey
//   - Context helpers for accessing authenticated user info
package main

import (
	"context"
	"log"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/kratosmw"
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/middleware"
	kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

// Demonstrate usage patterns (referenced in documentation).
var (
	_ = adminOnlyMiddleware
	_ = editorMiddleware
	_ = exampleHandler
)

func main() {
	// Create IAM client with fake backend for demo.
	// In production, inject real implementations via iam.With*() options.
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
		fake.WithTenant("tenant-001", "acme", "active"),
		fake.WithPermissions("user-123", []string{"users:read", "users:write", "admin:*"}),
		fake.WithAPIKey("ak_test", "sk_test", "user-123"),
	)
	defer func() { _ = client.Close() }()

	// IAM middleware stack
	iamMiddleware := []middleware.Middleware{
		// JWT authentication — skips health check endpoint
		kratosmw.Auth(client, kratosmw.WithExcludedOperations("/health")),
		// Tenant membership validation
		kratosmw.Tenant(client),
	}

	// Kratos HTTP server
	httpSrv := khttp.NewServer(
		khttp.Address(":8080"),
		khttp.Middleware(iamMiddleware...),
	)

	// Kratos gRPC server (same middleware works for both transports)
	grpcSrv := kgrpc.NewServer(
		kgrpc.Address(":50051"),
		kgrpc.Middleware(iamMiddleware...),
	)

	// In production, register proto-generated services:
	//   pb.RegisterUserServiceHTTPServer(httpSrv, &userService{client: client})
	//   pb.RegisterUserServiceServer(grpcSrv, &userService{client: client})

	app := kratos.New(
		kratos.Name("iam-example"),
		kratos.Version("1.0.0"),
		kratos.Server(httpSrv, grpcSrv),
	)

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// Example: Using permission middleware on specific routes.
// In Kratos proto-first design, this would be applied per-service or per-method.
func adminOnlyMiddleware(client *iam.Client) middleware.Middleware {
	return kratosmw.Require(client, "admin:*")
}

// Example: Using RequireAny for flexible permission checks.
func editorMiddleware(client *iam.Client) middleware.Middleware {
	return kratosmw.RequireAny(client, "content:write", "content:admin")
}

// Example: Handler showing how to read IAM context values.
func exampleHandler(ctx context.Context, req interface{}) (interface{}, error) {
	// Values injected by Auth middleware
	userID := iam.UserIDFromContext(ctx)
	tenantID := iam.TenantIDFromContext(ctx)
	roles := iam.RolesFromContext(ctx)
	claims := iam.ClaimsFromContext(ctx)

	_ = userID   // "user-123"
	_ = tenantID // "tenant-001"
	_ = roles    // ["admin"]
	_ = claims   // full *iam.Claims struct

	return nil, nil
}
