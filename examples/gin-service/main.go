// Example: Gin service with iam-go middleware.
//
// Demonstrates:
//   - JWT authentication via ginmw.Auth
//   - Tenant membership validation via ginmw.Tenant
//   - Permission gating via ginmw.Require / ginmw.RequireAny
//   - Context helpers for accessing authenticated user info
//
// Try it:
//
//	go run ./examples/gin-service
//	curl localhost:8080/health                                  # 200, no auth
//	curl localhost:8080/api/me                                  # 401
//	curl -H 'Authorization: Bearer user-123' localhost:8080/api/me      # 200
//	curl -H 'Authorization: Bearer user-123' localhost:8080/api/users   # 200 (users:read)
//	curl -X DELETE -H 'Authorization: Bearer user-123' localhost:8080/api/users/1  # 403
package main

import (
	"log"
	"net/http"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/ginmw"
	"github.com/gin-gonic/gin"
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

	r := gin.Default()

	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })

	// Auth + Tenant for the whole /api group.
	api := r.Group("/api", ginmw.Auth(client), ginmw.Tenant(client))

	api.GET("/me", func(c *gin.Context) {
		ctx := c.Request.Context()
		c.JSON(http.StatusOK, gin.H{
			"user_id":   iam.UserIDFromContext(ctx),
			"tenant_id": iam.TenantIDFromContext(ctx),
			"roles":     iam.RolesFromContext(ctx),
		})
	})

	// Per-route permission gating.
	api.GET("/users", ginmw.Require(client, "users:read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, []string{"alice", "bob"})
	})
	api.DELETE("/users/:id", ginmw.RequireAny(client, "users:delete", "admin:*"), func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	log.Fatal(r.Run(":8080"))
}
