// Example: standard library net/http service with iam-go middleware.
//
// Demonstrates:
//   - JWT authentication via httpmw.Auth (with excluded health check)
//   - Tenant membership validation via httpmw.Tenant
//   - Permission gating via httpmw.Require / httpmw.RequireAny
//   - Middleware composition via httpmw.Chain
//   - Context helpers for accessing authenticated user info
//
// Try it:
//
//	go run ./examples/std-http-service
//	curl localhost:8080/health                                  # 200, no auth
//	curl localhost:8080/api/me                                  # 401
//	curl -H 'Authorization: Bearer user-123' localhost:8080/api/me      # 200
//	curl -H 'Authorization: Bearer user-123' localhost:8080/api/users   # 200 (users:read)
//	curl -X DELETE -H 'Authorization: Bearer user-123' localhost:8080/api/users  # 403
package main

import (
	"encoding/json"
	"log"
	"net/http"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/httpmw"
)

func main() {
	// Create IAM client with fake backend for demo.
	// In production, inject real implementations via iam.With*() options,
	// e.g. iam.WithVerifier(jwks.NewVerifier(jwksURL)).
	client := fake.NewClient(
		fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
		fake.WithTenant("tenant-001", "acme", "active"),
		fake.WithPermissions("user-123", []string{"users:read"}),
	)
	defer func() { _ = client.Close() }()

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.Handle("/api/me", meHandler())
	mux.Handle("/api/users", usersHandler(client))

	// Auth + Tenant for everything; /health skips auth.
	handler := httpmw.Chain(
		httpmw.Auth(client, httpmw.WithExcludedPaths("/health")),
		httpmw.Tenant(client),
	)(mux)

	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

// meHandler shows the iam context helpers.
func meHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"user_id":   iam.UserIDFromContext(ctx),
			"tenant_id": iam.TenantIDFromContext(ctx),
			"roles":     iam.RolesFromContext(ctx),
		})
	})
}

// usersHandler gates methods with different permissions.
func usersHandler(client *iam.Client) http.Handler {
	list := httpmw.Require(client, "users:read")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode([]string{"alice", "bob"})
		}),
	)
	del := httpmw.RequireAny(client, "users:delete", "admin:*")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			list.ServeHTTP(w, r)
		case http.MethodDelete:
			del.ServeHTTP(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
