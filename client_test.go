package iam_test

import (
	"testing"
	"time"

	iam "github.com/chimerakang/iam-go"
)

func TestNewClient_RequiresEndpointOrJWKS(t *testing.T) {
	_, err := iam.NewClient(iam.Config{})
	if err == nil {
		t.Fatal("NewClient() expected error when both Endpoint and JWKSUrl are empty")
	}
}

func TestNewClient_AcceptsEndpoint(t *testing.T) {
	c, err := iam.NewClient(iam.Config{Endpoint: "localhost:9000"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.Config().Endpoint != "localhost:9000" {
		t.Errorf("Endpoint = %q, want %q", c.Config().Endpoint, "localhost:9000")
	}
}

func TestNewClient_AcceptsJWKSUrl(t *testing.T) {
	c, err := iam.NewClient(iam.Config{JWKSUrl: "https://auth.example.com/.well-known/jwks.json"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.Config().JWKSUrl == "" {
		t.Error("JWKSUrl should not be empty")
	}
}

func TestNewClient_DefaultCacheTTL(t *testing.T) {
	c, err := iam.NewClient(iam.Config{Endpoint: "localhost:9000"})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.Config().CacheTTL != 5*time.Minute {
		t.Errorf("CacheTTL = %v, want %v", c.Config().CacheTTL, 5*time.Minute)
	}
}

func TestNewClient_CustomCacheTTL(t *testing.T) {
	c, err := iam.NewClient(iam.Config{Endpoint: "localhost:9000", CacheTTL: 10 * time.Minute})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	if c.Config().CacheTTL != 10*time.Minute {
		t.Errorf("CacheTTL = %v, want %v", c.Config().CacheTTL, 10*time.Minute)
	}
}

func TestNewClient_NilServicesBeforeInjection(t *testing.T) {
	c, _ := iam.NewClient(iam.Config{Endpoint: "localhost:9000"})

	if c.Verifier() != nil {
		t.Error("Verifier() should be nil before injection")
	}
	if c.Authz() != nil {
		t.Error("Authz() should be nil before injection")
	}
	if c.Users() != nil {
		t.Error("Users() should be nil before injection")
	}
	if c.Tenants() != nil {
		t.Error("Tenants() should be nil before injection")
	}
	if c.Sessions() != nil {
		t.Error("Sessions() should be nil before injection")
	}
	if c.Secrets() != nil {
		t.Error("Secrets() should be nil before injection")
	}
}

func TestClose_NoErrorWithoutClosers(t *testing.T) {
	c, _ := iam.NewClient(iam.Config{Endpoint: "localhost:9000"})
	if err := c.Close(); err != nil {
		t.Errorf("Close() error: %v", err)
	}
}
