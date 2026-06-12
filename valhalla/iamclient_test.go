package valhalla

import (
	"testing"
	"time"

	"github.com/chimerakang/iam-go/authz"
	"github.com/chimerakang/iam-go/oauth2"
)

// grpc.NewClient connects lazily, so New succeeds without a running server.

func TestNew_AssemblesAllServices(t *testing.T) {
	client, err := New("localhost:50051")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.Verifier() == nil {
		t.Error("Verifier() is nil")
	}
	if client.Authz() == nil {
		t.Error("Authz() is nil")
	}
	if client.Users() == nil {
		t.Error("Users() is nil")
	}
	if client.Tenants() == nil {
		t.Error("Tenants() is nil")
	}
	if client.Sessions() == nil {
		t.Error("Sessions() is nil")
	}
	if client.Auth() == nil {
		t.Error("Auth() is nil")
	}
	if client.OAuth2() != nil {
		t.Error("OAuth2() should be nil without WithOAuth2")
	}

	if got := client.Config().Endpoint; got != "localhost:50051" {
		t.Errorf("Config().Endpoint = %q", got)
	}
	if got := client.Config().JWKSUrl; got != "http://localhost:50051/.well-known/jwks.json" {
		t.Errorf("Config().JWKSUrl = %q", got)
	}
}

func TestNew_EmptyEndpoint(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Fatal("New(\"\") expected error, got nil")
	}
}

func TestNew_ClaimsCheckerByDefault(t *testing.T) {
	client, err := New("localhost:50051")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, ok := client.Authz().(*authz.ClaimsChecker); !ok {
		t.Errorf("default Authz() = %T, want *authz.ClaimsChecker (local-first)", client.Authz())
	}
}

func TestNew_WithRemoteAuthz(t *testing.T) {
	client, err := New("localhost:50051", WithRemoteAuthz())
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, ok := client.Authz().(*authz.Authorizer); !ok {
		t.Errorf("WithRemoteAuthz Authz() = %T, want *authz.Authorizer (cached remote)", client.Authz())
	}
}

func TestNew_WithRemoteAuthzCacheDisabled(t *testing.T) {
	client, err := New("localhost:50051", WithRemoteAuthz(), WithCacheTTL(0))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if _, ok := client.Authz().(*authz.Authorizer); ok {
		t.Error("WithCacheTTL(0) should bypass the caching authorizer")
	}
	if _, ok := client.Authz().(*authz.ClaimsChecker); ok {
		t.Error("WithRemoteAuthz should bypass the claims checker")
	}
}

func TestNew_WithOAuth2(t *testing.T) {
	client, err := New("localhost:50051",
		WithOAuth2("client-id", "client-secret"),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	ex, ok := client.OAuth2().(*oauth2.Exchanger)
	if !ok {
		t.Fatalf("OAuth2() = %T, want *oauth2.Exchanger", client.OAuth2())
	}
	if ex == nil {
		t.Fatal("exchanger is nil")
	}
}

func TestNew_WithOAuth2Exchanger(t *testing.T) {
	ex := NewOAuth2Exchanger("id", "secret", "http://auth.example.com/token",
		oauth2.WithRefreshBuffer(time.Minute))

	client, err := New("localhost:50051", WithOAuth2Exchanger(ex))
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if client.OAuth2() != ex {
		t.Error("OAuth2() should return the injected exchanger")
	}
}

func TestNew_WithJWKSURL(t *testing.T) {
	client, err := New("localhost:50051",
		WithJWKSURL("https://auth.example.com/.well-known/jwks.json"),
	)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	defer func() { _ = client.Close() }()

	if got := client.Config().JWKSUrl; got != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("Config().JWKSUrl = %q", got)
	}
}

func TestNew_CloseClosesConnection(t *testing.T) {
	client, err := New("localhost:50051")
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error: %v", err)
	}
	// Closing twice must surface the underlying conn error, proving the
	// gRPC connection is actually wired into Close.
	if err := client.Close(); err == nil {
		t.Error("second Close() expected already-closed error, got nil")
	}
}
