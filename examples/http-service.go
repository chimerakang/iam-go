package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/kratosmw"
	"github.com/go-kratos/kratos/v2"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/middleware/logging"
	khttp "github.com/go-kratos/kratos/v2/transport/http"
)

// ExampleHTTPService demonstrates a Kratos HTTP service using iam-go SDK
//
// This example shows:
// - JWT authentication middleware
// - Tenant injection middleware
// - Permission checking middleware
// - Direct permission queries in handlers

func main() {
	// Initialize IAM client with fake backend for demo
	// In production, use real IAM server implementations
	client, err := iam.NewClient(
		iam.Config{
			Endpoint: os.Getenv("IAM_ENDPOINT"),
		},
		iam.WithTokenVerifier(fake.NewVerifier(
			fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
			fake.WithPermissions("user-123", []string{"users:read", "users:write"}),
		)),
		iam.WithAuthorizer(fake.NewAuthorizer()),
	)
	if err != nil {
		log.Fatalf("Failed to create IAM client: %v", err)
	}
	defer client.Close()

	// Create Kratos HTTP server with IAM middleware
	httpSrv := khttp.NewServer(
		khttp.Address(":8080"),
		khttp.Middleware(
			// Logging middleware
			logging.Server(log.New(os.Stderr, "", log.LstdFlags)),

			// IAM middleware - JWT verification
			kratosmw.Auth(client, kratosmw.WithExcludedOperations("/api/v1/login", "/api/v1/health")),

			// IAM middleware - Tenant injection
			kratosmw.Tenant(client),
		),
	)

	// Define HTTP handlers
	httpSrv.HandleFunc("/api/v1/health", handleHealth).Methods(http.MethodGet)
	httpSrv.HandleFunc("/api/v1/login", handleLogin).Methods(http.MethodPost)
	httpSrv.HandleFunc("/api/v1/users", handleListUsers).Methods(http.MethodGet)
	httpSrv.HandleFunc("/api/v1/users/{id}", handleGetUser).Methods(http.MethodGet)
	httpSrv.HandleFunc("/api/v1/users/{id}", handleUpdateUser).Methods(http.MethodPut)
	httpSrv.HandleFunc("/api/v1/users/{id}", handleDeleteUser).Methods(http.MethodDelete)

	// Create Kratos application
	app := kratos.New(
		kratos.Name("iam-http-service"),
		kratos.Version("1.0.0"),
		kratos.Server(httpSrv),
	)

	// Start the server
	if err := app.Run(); err != nil {
		log.Fatalf("Failed to run service: %v", err)
	}
}

// Handler definitions

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// In production, verify credentials and issue JWT token
	// This is a placeholder for demo
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
		"expires_in": 3600
	}`))
}

func handleListUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get current user from context (set by Auth middleware)
	userID, err := iam.UserIDFromContext(ctx)
	if err != nil {
		http.Error(w, "Missing user context", http.StatusUnauthorized)
		return
	}

	// Get tenant from context (set by Tenant middleware)
	tenantID, err := iam.TenantIDFromContext(ctx)
	if err != nil {
		http.Error(w, "Missing tenant context", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"users": [
			{"id": "user-1", "email": "user1@example.com", "name": "User 1"},
			{"id": "user-2", "email": "user2@example.com", "name": "User 2"}
		],
		"tenant_id": "` + tenantID + `",
		"requested_by": "` + userID + `"
	}`))
}

func handleGetUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")

	// In production, use permission middleware for this
	// For demo, we'll show how to check permissions directly
	_ = userID // Use userID in actual implementation

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"id": "` + userID + `",
		"email": "user@example.com",
		"name": "User Name",
		"roles": ["admin"]
	}`))
}

func handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")

	// Verify permission
	// client := getClientFromContext(ctx)
	// ok, err := client.Authz().Check(ctx, "users:write")
	// if !ok {
	//     http.Error(w, "Permission denied", http.StatusForbidden)
	//     return
	// }

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{
		"id": "` + userID + `",
		"email": "user@example.com",
		"name": "Updated Name",
		"updated_at": "` + time.Now().Format(time.RFC3339) + `"
	}`))
}

func handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID := r.PathValue("id")

	// Verify permission
	// client := getClientFromContext(ctx)
	// ok, err := client.Authz().Check(ctx, "users:delete")
	// if !ok {
	//     http.Error(w, "Permission denied", http.StatusForbidden)
	//     return
	// }

	_ = userID

	w.WriteHeader(http.StatusNoContent)
}

// Helper function to demonstrate context usage
func getContextValues(ctx context.Context) (userID, tenantID, requestID string) {
	userID, _ = iam.UserIDFromContext(ctx)
	tenantID, _ = iam.TenantIDFromContext(ctx)
	requestID, _ = iam.RequestIDFromContext(ctx)
	return
}

// Middleware example: Custom middleware for permission checking
func RequirePermission(client *iam.Client, permission string) middleware.Middleware {
	return func(handler middleware.Handler) middleware.Handler {
		return func(ctx context.Context, req interface{}) (interface{}, error) {
			// Check permission
			ok, err := client.Authz().Check(ctx, permission)
			if err != nil || !ok {
				// Return permission denied error
				// (implementation depends on your error handling)
				return nil, err
			}
			return handler(ctx, req)
		}
	}
}
