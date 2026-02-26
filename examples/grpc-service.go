package main

import (
	"context"
	"log"
	"net"
	"os"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/grpcmw"
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/transport/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ExampleGRPCService demonstrates a gRPC service using iam-go SDK
//
// This example shows:
// - gRPC interceptors for authentication
// - Tenant context injection
// - Direct permission checks in handlers
// - Support for both Kratos and non-Kratos gRPC services

// Define a simple gRPC service for demo
// In production, you would use protobuf-generated code

func main() {
	// Initialize IAM client with fake backend for demo
	client, err := iam.NewClient(
		iam.Config{
			Endpoint: os.Getenv("IAM_ENDPOINT"),
		},
		iam.WithTokenVerifier(fake.NewVerifier(
			fake.WithUser("service-123", "tenant-001", "service@example.com", []string{"admin"}),
			fake.WithPermissions("service-123", []string{"users:read", "users:write"}),
		)),
		iam.WithAuthorizer(fake.NewAuthorizer()),
	)
	if err != nil {
		log.Fatalf("Failed to create IAM client: %v", err)
	}
	defer client.Close()

	// Create gRPC server with iam-go interceptors
	grpcSrv := grpc.NewServer(
		grpc.Address(":50051"),
		grpc.Middleware(
			// Add authentication interceptor
			grpcmw.UnaryServerAuthInterceptor(client),
			// Add tenant injection interceptor
			grpcmw.UnaryServerTenantInterceptor(client),
		),
	)

	// Register service handlers (example)
	// In production: pb.RegisterUserServiceServer(grpcSrv, &userServiceServer{client: client})

	// Create Kratos application
	app := kratos.New(
		kratos.Name("iam-grpc-service"),
		kratos.Version("1.0.0"),
		kratos.Server(grpcSrv),
	)

	// Start the server
	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run service: %v", err)
	}
}

// Example gRPC service implementation
// This demonstrates how to use iam-go in gRPC handlers

type UserServiceServer struct {
	client *iam.Client
}

// GetUser - Example gRPC handler with permission checking
func (s *UserServiceServer) GetUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Get user from context (set by Auth interceptor)
	userID, err := iam.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing authentication")
	}

	// Get tenant from context (set by Tenant interceptor)
	tenantID, err := iam.TenantIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "missing tenant")
	}

	// Check permission
	ok, err := s.client.Authz().Check(ctx, "users:read")
	if err != nil || !ok {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
	}

	// In production, fetch user from database
	// For demo, return hardcoded response
	return &User{
		Id:       "user-123",
		Email:    "user@example.com",
		Name:     "User Name",
		TenantId: tenantID,
		Roles:    []string{"admin"},
	}, nil
}

// ListUsers - Example gRPC handler listing users for a tenant
func (s *UserServiceServer) ListUsers(ctx context.Context, req interface{}) (interface{}, error) {
	// Verify authentication
	userID, err := iam.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing authentication")
	}

	// Get tenant
	tenantID, err := iam.TenantIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "missing tenant")
	}

	// Check read permission
	ok, err := s.client.Authz().Check(ctx, "users:read")
	if err != nil || !ok {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
	}

	_ = userID // Use in actual implementation

	// Return list of users for the tenant
	return &UserList{
		Users: []*User{
			{
				Id:       "user-1",
				Email:    "user1@example.com",
				Name:     "User 1",
				TenantId: tenantID,
				Roles:    []string{"user"},
			},
			{
				Id:       "user-2",
				Email:    "user2@example.com",
				Name:     "User 2",
				TenantId: tenantID,
				Roles:    []string{"user"},
			},
		},
		Total:    2,
		TenantId: tenantID,
	}, nil
}

// CreateUser - Example gRPC handler for creating a new user
func (s *UserServiceServer) CreateUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Verify authentication
	_, err := iam.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing authentication")
	}

	// Check write permission
	ok, err := s.client.Authz().Check(ctx, "users:write")
	if err != nil || !ok {
		return nil, status.Error(codes.PermissionDenied, "insufficient permissions")
	}

	// Get tenant
	tenantID, err := iam.TenantIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "missing tenant")
	}

	// In production: validate request, save to database
	return &User{
		Id:       "user-new",
		Email:    "newuser@example.com",
		Name:     "New User",
		TenantId: tenantID,
		Roles:    []string{"user"},
	}, nil
}

// DeleteUser - Example gRPC handler for deleting a user
func (s *UserServiceServer) DeleteUser(ctx context.Context, req interface{}) (interface{}, error) {
	// Verify authentication
	_, err := iam.UserIDFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "missing authentication")
	}

	// Check admin permission
	ok, err := s.client.Authz().Check(ctx, "admin:*")
	if err != nil || !ok {
		return nil, status.Error(codes.PermissionDenied, "admin permission required")
	}

	// In production: delete from database
	return &DeleteResponse{
		Success: true,
		Message: "user deleted successfully",
	}, nil
}

// Example data structures (in production, use protobuf-generated code)

type User struct {
	Id       string
	Email    string
	Name     string
	TenantId string
	Roles    []string
}

type UserList struct {
	Users    []*User
	Total    int
	TenantId string
}

type DeleteResponse struct {
	Success bool
	Message string
}

// Example: Using gRPC interceptors with Kratos gRPC transport

func ExampleGRPCWithKratos() {
	client, _ := iam.NewClient(iam.Config{})
	defer client.Close()

	// Kratos automatically applies interceptors
	_ = grpc.NewServer(
		grpc.Address(":50051"),
		grpc.Middleware(
			grpcmw.UnaryServerAuthInterceptor(client),
			grpcmw.UnaryServerTenantInterceptor(client),
		),
	)
}

// Example: Using gRPC interceptors with standard Google gRPC

func ExampleGRPCWithGoogleGRPC() {
	client, _ := iam.NewClient(iam.Config{})
	defer client.Close()

	lis, _ := net.Listen("tcp", ":50051")

	// Standard Google gRPC with iam-go interceptors
	_ = grpcmw.NewServerWithInterceptors(lis, client)
}

// Helper function: Create gRPC server with all iam-go interceptors
func grpcmw_NewServerWithInterceptors(lis net.Listener, client *iam.Client) *grpcmw.ServerWithAuth {
	// This is a helper to demonstrate how to set up a complete gRPC server
	// In production, you would use google.golang.org/grpc directly

	return &grpcmw.ServerWithAuth{
		Listener: lis,
		Client:   client,
	}
}

// Define a mock ServerWithAuth for the example
type ServerWithAuth struct {
	Listener net.Listener
	Client   *iam.Client
}
