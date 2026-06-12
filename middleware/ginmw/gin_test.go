package ginmw_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/ginmw"
	"github.com/gin-gonic/gin"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newRouter(mws ...gin.HandlerFunc) (*gin.Engine, *string) {
	r := gin.New()
	var gotUserID string
	handlers := append(mws, func(c *gin.Context) {
		gotUserID = iam.UserIDFromContext(c.Request.Context())
		c.Status(http.StatusOK)
	})
	r.GET("/api/test", handlers...)
	return r, &gotUserID
}

func doRequest(t *testing.T, r *gin.Engine, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestAuth_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	r, gotUserID := newRouter(ginmw.Auth(client))

	rec := doRequest(t, r, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if *gotUserID != "user123" {
		t.Errorf("UserIDFromContext = %q, want %q", *gotUserID, "user123")
	}
}

func TestAuth_MissingToken(t *testing.T) {
	client := fake.NewClient()
	r, _ := newRouter(ginmw.Auth(client))

	rec := doRequest(t, r, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "UNAUTHORIZED") {
		t.Errorf("body = %s, want UNAUTHORIZED code", rec.Body)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	client := fake.NewClient()
	r, _ := newRouter(ginmw.Auth(client))

	rec := doRequest(t, r, "nonexistent-user", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuth_ExcludedPath(t *testing.T) {
	client := fake.NewClient()
	r := gin.New()
	r.Use(ginmw.Auth(client, ginmw.WithExcludedPaths("/health")))
	r.GET("/health", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/api/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	rec := doRequest(t, r, "", "/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("excluded path status = %d, want 200", rec.Code)
	}

	rec = doRequest(t, r, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-excluded path status = %d, want 401", rec.Code)
	}
}

func TestTenant_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	r, _ := newRouter(ginmw.Auth(client), ginmw.Tenant(client))

	rec := doRequest(t, r, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestTenant_MissingContext(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	// Tenant without Auth first — no user/tenant in context.
	r, _ := newRouter(ginmw.Tenant(client))

	rec := doRequest(t, r, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequire(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"user"}),
		fake.WithPermissions("user123", []string{"user:read"}),
	)

	allowed, _ := newRouter(ginmw.Auth(client), ginmw.Require(client, "user:read"))
	rec := doRequest(t, allowed, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	denied, _ := newRouter(ginmw.Auth(client), ginmw.Require(client, "user:write"))
	rec = doRequest(t, denied, "user123", "/api/test")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "FORBIDDEN") {
		t.Errorf("body = %s, want FORBIDDEN code", rec.Body)
	}
}

func TestRequireAny(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
		fake.WithPermissions("user123", []string{"user:delete"}),
	)

	allowed, _ := newRouter(ginmw.Auth(client), ginmw.RequireAny(client, "user:write", "user:delete"))
	rec := doRequest(t, allowed, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	denied, _ := newRouter(ginmw.Auth(client), ginmw.RequireAny(client, "user:write", "user:admin"))
	rec = doRequest(t, denied, "user123", "/api/test")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
}
