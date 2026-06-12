package httpmw_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/chimerakang/iam-go/middleware/httpmw"
)

func okHandler(captured *string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if captured != nil {
			*captured = iam.UserIDFromContext(r.Context())
		}
		w.WriteHeader(http.StatusOK)
	})
}

func doRequest(t *testing.T, h http.Handler, token, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuth_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	var gotUserID string
	h := httpmw.Auth(client)(okHandler(&gotUserID))

	rec := doRequest(t, h, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
	if gotUserID != "user123" {
		t.Errorf("UserIDFromContext = %q, want %q", gotUserID, "user123")
	}
}

func TestAuth_MissingToken(t *testing.T) {
	client := fake.NewClient()
	h := httpmw.Auth(client)(okHandler(nil))

	rec := doRequest(t, h, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "UNAUTHORIZED") {
		t.Errorf("body = %s, want UNAUTHORIZED code", rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestAuth_InvalidToken(t *testing.T) {
	client := fake.NewClient() // no users — any token is invalid
	h := httpmw.Auth(client)(okHandler(nil))

	rec := doRequest(t, h, "nonexistent-user", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestAuth_ExcludedPath(t *testing.T) {
	client := fake.NewClient()
	h := httpmw.Auth(client, httpmw.WithExcludedPaths("/health"))(okHandler(nil))

	rec := doRequest(t, h, "", "/health")
	if rec.Code != http.StatusOK {
		t.Fatalf("excluded path status = %d, want 200", rec.Code)
	}

	rec = doRequest(t, h, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("non-excluded path status = %d, want 401", rec.Code)
	}
}

func TestTenant_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	h := httpmw.Chain(
		httpmw.Auth(client),
		httpmw.Tenant(client),
	)(okHandler(nil))

	rec := doRequest(t, h, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestTenant_MissingContext(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	// Tenant without Auth first — no user/tenant in context.
	h := httpmw.Tenant(client)(okHandler(nil))

	rec := doRequest(t, h, "", "/api/test")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestRequire_Allowed(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
		fake.WithPermissions("user123", []string{"user:read", "user:write"}),
	)

	h := httpmw.Chain(
		httpmw.Auth(client),
		httpmw.Require(client, "user:read"),
	)(okHandler(nil))

	rec := doRequest(t, h, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}
}

func TestRequire_Denied(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"user"}),
		fake.WithPermissions("user123", []string{"user:read"}),
	)

	h := httpmw.Chain(
		httpmw.Auth(client),
		httpmw.Require(client, "user:write"),
	)(okHandler(nil))

	rec := doRequest(t, h, "user123", "/api/test")
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

	allowed := httpmw.Chain(
		httpmw.Auth(client),
		httpmw.RequireAny(client, "user:write", "user:delete"),
	)(okHandler(nil))

	rec := doRequest(t, allowed, "user123", "/api/test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body)
	}

	denied := httpmw.Chain(
		httpmw.Auth(client),
		httpmw.RequireAny(client, "user:write", "user:admin"),
	)(okHandler(nil))

	rec = doRequest(t, denied, "user123", "/api/test")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", rec.Code, rec.Body)
	}
}
