// Example: Pure gRPC service (non-Kratos) with iam-go interceptors.
//
// Use this pattern when your service uses google.golang.org/grpc directly,
// without the Kratos framework. For Kratos services, use kratosmw instead.
//
// Demonstrates:
//   - UnaryAuth / StreamAuth interceptors for JWT verification
//   - UnaryTenant interceptor for tenant context
//   - UnaryRequire interceptor for permission gating
//   - Context helpers for accessing authenticated user info
package main

import (
	"context"
	"log"
	"net"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/grpcmw"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Demonstrate usage patterns (referenced in documentation).
var (
	_ = exampleGetUser
	_ = adminInterceptor
)

func main() {
	// Create IAM client with fake backend for demo.
	// In production, inject real implementations via iam.With*() options.
	client := fake.NewClient(
		fake.WithUser("service-123", "tenant-001", "service@example.com", []string{"admin"}),
		fake.WithPermissions("service-123", []string{"users:read", "users:write"}),
	)
	defer func() { _ = client.Close() }()

	// Create standard gRPC server with IAM interceptors
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			// JWT authentication — skips health check
			grpcmw.UnaryAuth(client, grpcmw.WithExcludedMethods("/grpc.health.v1.Health/Check")),
			// Tenant membership validation
			grpcmw.UnaryTenant(client),
		),
		grpc.ChainStreamInterceptor(
			// JWT authentication for streaming RPCs
			grpcmw.StreamAuth(client),
		),
	)

	// In production, register proto-generated services:
	//   pb.RegisterUserServiceServer(srv, &userService{client: client})

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("gRPC server listening on :50051")
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err)
	}
}

// Example: gRPC handler showing how to read IAM context and check permissions.
func exampleGetUser(ctx context.Context, client *iam.Client) error {
	// Values injected by UnaryAuth interceptor
	userID := iam.UserIDFromContext(ctx)
	tenantID := iam.TenantIDFromContext(ctx)

	if userID == "" {
		return status.Error(codes.Unauthenticated, "missing authentication")
	}
	if tenantID == "" {
		return status.Error(codes.InvalidArgument, "missing tenant context")
	}

	// Direct permission check in handler (alternative to UnaryRequire interceptor)
	ok, err := client.Authz().Check(ctx, "users:read")
	if err != nil {
		return status.Error(codes.Internal, "authorization check failed")
	}
	if !ok {
		return status.Error(codes.PermissionDenied, "insufficient permissions")
	}

	// Proceed with business logic...
	return nil
}

// Example: Permission-gated interceptor for a specific service.
func adminInterceptor(client *iam.Client) grpc.UnaryServerInterceptor {
	return grpcmw.UnaryRequire(client, "admin:*")
}
