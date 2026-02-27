package oauth2_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chimerakang/iam-go/oauth2"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if r.FormValue("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			return
		}

		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")
		if clientID != "app_test" || clientSecret != "secret_test" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        r.FormValue("scope"),
		})
	}))
}

func TestExchangeToken_Success(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, []string{"iam:introspect"})

	token, err := e.ExchangeToken(context.Background(), []string{"iam:introspect"})
	if err != nil {
		t.Fatalf("ExchangeToken() error: %v", err)
	}

	if token.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
	if token.TokenType != "Bearer" {
		t.Errorf("TokenType = %q, want %q", token.TokenType, "Bearer")
	}
	if token.ExpiresIn != 3600 {
		t.Errorf("ExpiresIn = %d, want 3600", token.ExpiresIn)
	}
	if token.Scope != "iam:introspect" {
		t.Errorf("Scope = %q, want %q", token.Scope, "iam:introspect")
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt should be in the future")
	}
}

func TestExchangeToken_InvalidCredentials(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	e := oauth2.New("wrong_id", "wrong_secret", server.URL, nil)

	_, err := e.ExchangeToken(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for invalid credentials")
	}
}

func TestExchangeToken_DefaultScopes(t *testing.T) {
	server := newTestServer(t)
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, []string{"iam:introspect", "iam:check-permission"})

	// Pass nil scopes — should use defaults
	token, err := e.ExchangeToken(context.Background(), nil)
	if err != nil {
		t.Fatalf("ExchangeToken() error: %v", err)
	}
	if token.Scope != "iam:introspect iam:check-permission" {
		t.Errorf("Scope = %q, want %q", token.Scope, "iam:introspect iam:check-permission")
	}
}

func TestGetCachedToken_CachesToken(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cached_token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "iam:introspect",
		})
	}))
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, []string{"iam:introspect"})

	// First call — fetches from server
	token1, err := e.GetCachedToken(context.Background())
	if err != nil {
		t.Fatalf("GetCachedToken() error: %v", err)
	}
	if token1 != "cached_token" {
		t.Errorf("token = %q, want %q", token1, "cached_token")
	}

	// Second call — should use cache
	token2, err := e.GetCachedToken(context.Background())
	if err != nil {
		t.Fatalf("GetCachedToken() error: %v", err)
	}
	if token2 != "cached_token" {
		t.Errorf("token = %q, want %q", token2, "cached_token")
	}

	if callCount.Load() != 1 {
		t.Errorf("server was called %d times, want 1 (cached)", callCount.Load())
	}
}

func TestGetCachedToken_Singleflight(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		time.Sleep(50 * time.Millisecond) // simulate latency
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "singleflight_token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "iam:introspect",
		})
	}))
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, []string{"iam:introspect"})

	// Launch 10 concurrent requests
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.GetCachedToken(context.Background())
			if err != nil {
				t.Errorf("GetCachedToken() error: %v", err)
			}
		}()
	}
	wg.Wait()

	// singleflight should collapse to 1 request
	if callCount.Load() != 1 {
		t.Errorf("server was called %d times, want 1 (singleflight)", callCount.Load())
	}
}

func TestGetCachedToken_RefreshBeforeExpiry(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "short_lived_token",
			"token_type":   "Bearer",
			"expires_in":   1, // 1 second
			"scope":        "iam:introspect",
		})
	}))
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, []string{"iam:introspect"},
		oauth2.WithRefreshBuffer(2*time.Second), // buffer > expiry → always refresh
	)

	// First call
	_, err := e.GetCachedToken(context.Background())
	if err != nil {
		t.Fatalf("GetCachedToken() error: %v", err)
	}

	// Second call — token should be considered expired due to refresh buffer
	_, err = e.GetCachedToken(context.Background())
	if err != nil {
		t.Fatalf("GetCachedToken() error: %v", err)
	}

	if callCount.Load() < 2 {
		t.Errorf("server was called %d times, want >= 2 (expired token)", callCount.Load())
	}
}

func TestExchangeToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("internal server error"))
	}))
	defer server.Close()

	e := oauth2.New("app_test", "secret_test", server.URL, nil)

	_, err := e.ExchangeToken(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for server error")
	}
}
