package kratosmw

import (
	"context"
	"testing"

	iam "github.com/chimerakang/iam-go"
	"github.com/chimerakang/iam-go/fake"
	"github.com/go-kratos/kratos/v2/errors"
	"github.com/go-kratos/kratos/v2/middleware"
	"github.com/go-kratos/kratos/v2/transport"
)

// mockTransport implements transport.Transporter
type mockTransport struct {
	headers map[string]string
	op      string
}

func (m *mockTransport) Kind() transport.Kind              { return transport.KindHTTP }
func (m *mockTransport) Endpoint() string                 { return "mock://test" }
func (m *mockTransport) Operation() string                { return m.op }
func (m *mockTransport) RequestHeader() transport.Header  { return &mockHeader{headers: m.headers} }
func (m *mockTransport) ReplyHeader() transport.Header    { return &mockHeader{headers: make(map[string]string)} }

type mockHeader struct {
	headers map[string]string
}

func (h *mockHeader) Get(key string) string      { return h.headers[key] }
func (h *mockHeader) Set(key, value string)      { h.headers[key] = value }
func (h *mockHeader) Add(key, value string)      { h.headers[key] = value }
func (h *mockHeader) Values(key string) []string { return []string{h.headers[key]} }
func (h *mockHeader) Keys() []string             {
	keys := make([]string, 0, len(h.headers))
	for k := range h.headers {
		keys = append(keys, k)
	}
	return keys
}

// mockServerContext embeds transport info in context
func mockServerContext(ctx context.Context, tr transport.Transporter) context.Context {
	return transport.NewServerContext(ctx, tr)
}

func TestAuth_Success(t *testing.T) {
	// Create a fake IAM client with a test user
	// Note: In fake verifier, the token is treated as userID
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
	)

	// Create auth middleware
	mw := Auth(client)

	// Create handler that returns the context
	var capturedCtx context.Context
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		capturedCtx = ctx
		return "ok", nil
	}

	// Create mock transport with Bearer token (use "user123" as token since fake verifier uses token as userID)
	tr := &mockTransport{
		headers: map[string]string{
			"Authorization": "Bearer user123",
		},
		op: "/test/operation",
	}
	ctx := mockServerContext(context.Background(), tr)

	// Execute middleware
	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}

	// Verify context was enriched
	if userID := iam.UserIDFromContext(capturedCtx); userID != "user123" {
		t.Errorf("expected userID user123, got %s", userID)
	}
	if tenantID := iam.TenantIDFromContext(capturedCtx); tenantID != "tenant123" {
		t.Errorf("expected tenantID tenant123, got %s", tenantID)
	}
}

func TestAuth_MissingToken(t *testing.T) {
	client := fake.NewClient()
	mw := Auth(client)

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	// Create mock transport without Authorization header
	tr := &mockTransport{headers: make(map[string]string), op: "/test/operation"}
	ctx := mockServerContext(context.Background(), tr)

	wrapped := mw(middleware.Handler(handler))
	_, err := wrapped(ctx, nil)

	if err == nil {
		t.Fatal("expected error for missing token")
	}
	if !errors.IsUnauthorized(err) {
		t.Fatalf("expected Unauthorized error, got %v", err)
	}
}

func TestAuth_ExcludedOperation(t *testing.T) {
	client := fake.NewClient()
	mw := Auth(client, WithExcludedOperations("/health/check"))

	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	// Create mock transport without Authorization header for excluded operation
	tr := &mockTransport{headers: make(map[string]string), op: "/health/check"}
	ctx := mockServerContext(context.Background(), tr)

	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("excluded operation should not return error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
}

func TestRequire_Success(t *testing.T) {
	// Create fake client with permissions
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
		fake.WithPermissions("user123", []string{"user:read", "user:write"}),
	)

	mw := Require(client, "user:read")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	// Set up context with user
	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user123")
	ctx = iam.WithTenantID(ctx, "tenant123")

	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
}

func TestRequire_PermissionDenied(t *testing.T) {
	// Create fake client with limited permissions
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"user"}),
		fake.WithPermissions("user123", []string{"user:read"}), // only read, not write
	)

	mw := Require(client, "user:write")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user123")
	ctx = iam.WithTenantID(ctx, "tenant123")

	wrapped := mw(middleware.Handler(handler))
	_, err := wrapped(ctx, nil)

	if err == nil {
		t.Fatal("expected permission denied error")
	}
	if !errors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}

func TestRequireAny_FirstPermissionMatches(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
		fake.WithPermissions("user123", []string{"user:read", "user:write"}),
	)

	mw := RequireAny(client, "user:read", "user:delete")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user123")
	ctx = iam.WithTenantID(ctx, "tenant123")

	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
}

func TestRequireAny_SecondPermissionMatches(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"admin"}),
		fake.WithPermissions("user123", []string{"user:read", "user:delete"}), // has delete, not write
	)

	mw := RequireAny(client, "user:write", "user:delete")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user123")
	ctx = iam.WithTenantID(ctx, "tenant123")

	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
}

func TestRequireAny_NoPermissionMatches(t *testing.T) {
	client := fake.NewClient(
		fake.WithUser("user123", "tenant123", "test@example.com", []string{"user"}),
		fake.WithPermissions("user123", []string{"user:read"}), // only read
	)

	mw := RequireAny(client, "user:write", "user:delete")
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	ctx := context.Background()
	ctx = iam.WithUserID(ctx, "user123")
	ctx = iam.WithTenantID(ctx, "tenant123")

	wrapped := mw(middleware.Handler(handler))
	_, err := wrapped(ctx, nil)

	if err == nil {
		t.Fatal("expected permission denied error")
	}
	if !errors.IsForbidden(err) {
		t.Fatalf("expected Forbidden error, got %v", err)
	}
}

func TestAPIKey_Success(t *testing.T) {
	client := fake.NewClient(
		fake.WithAPIKey("key123", "secret456", "user123"),
	)

	mw := APIKey(client)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	tr := &mockTransport{
		headers: map[string]string{
			"X-API-Key":    "key123",
			"X-API-Secret": "secret456",
		},
		op: "/test/operation",
	}
	ctx := mockServerContext(context.Background(), tr)

	wrapped := mw(middleware.Handler(handler))
	result, err := wrapped(ctx, nil)

	if err != nil {
		t.Fatalf("middleware returned error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected ok, got %v", result)
	}
}

func TestAPIKey_InvalidSecret(t *testing.T) {
	client := fake.NewClient(
		fake.WithAPIKey("key123", "secret456", "user123"),
	)

	mw := APIKey(client)
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return "ok", nil
	}

	tr := &mockTransport{
		headers: map[string]string{
			"X-API-Key":    "key123",
			"X-API-Secret": "wrongsecret",
		},
		op: "/test/operation",
	}
	ctx := mockServerContext(context.Background(), tr)

	wrapped := mw(middleware.Handler(handler))
	_, err := wrapped(ctx, nil)

	if err == nil {
		t.Fatal("expected error for invalid secret")
	}
	if !errors.IsUnauthorized(err) {
		t.Fatalf("expected Unauthorized error, got %v", err)
	}
}
