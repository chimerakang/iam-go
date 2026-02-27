// Package oauth2 provides an OAuth2 Client Credentials token exchanger for M2M authentication.
package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	iam "github.com/chimerakang/iam-go"
	"golang.org/x/sync/singleflight"
)

// Exchanger implements iam.OAuth2TokenExchanger using HTTP token endpoint.
type Exchanger struct {
	clientID      string
	clientSecret  string
	tokenURL      string
	defaultScopes []string
	refreshBuffer time.Duration
	httpClient    *http.Client

	mu    sync.RWMutex
	token *iam.OAuth2Token

	sf singleflight.Group
}

// compile-time check
var _ iam.OAuth2TokenExchanger = (*Exchanger)(nil)

// Option configures the Exchanger.
type Option func(*Exchanger)

// WithHTTPClient sets a custom HTTP client for token requests.
func WithHTTPClient(c *http.Client) Option {
	return func(e *Exchanger) { e.httpClient = c }
}

// WithRefreshBuffer sets how long before expiry to refresh the token.
func WithRefreshBuffer(d time.Duration) Option {
	return func(e *Exchanger) { e.refreshBuffer = d }
}

// New creates a new OAuth2 token exchanger.
func New(clientID, clientSecret, tokenURL string, scopes []string, opts ...Option) *Exchanger {
	e := &Exchanger{
		clientID:      clientID,
		clientSecret:  clientSecret,
		tokenURL:      tokenURL,
		defaultScopes: scopes,
		refreshBuffer: 5 * time.Minute,
		httpClient:    &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(e)
	}
	return e
}

// tokenResponse is the raw JSON response from the token endpoint.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int32  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// ExchangeToken requests a new access token using client credentials.
func (e *Exchanger) ExchangeToken(ctx context.Context, scopes []string) (*iam.OAuth2Token, error) {
	if len(scopes) == 0 {
		scopes = e.defaultScopes
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {e.clientID},
		"client_secret": {e.clientSecret},
	}
	if len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, "POST", e.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth2: token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oauth2: token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("oauth2: failed to decode response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("oauth2: empty access_token in response")
	}

	return &iam.OAuth2Token{
		AccessToken: tokenResp.AccessToken,
		TokenType:   tokenResp.TokenType,
		ExpiresIn:   tokenResp.ExpiresIn,
		ExpiresAt:   time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second),
		Scope:       tokenResp.Scope,
	}, nil
}

// GetCachedToken returns a valid cached token, or fetches a new one if expired/missing.
func (e *Exchanger) GetCachedToken(ctx context.Context) (string, error) {
	e.mu.RLock()
	if e.token != nil && time.Now().Before(e.token.ExpiresAt.Add(-e.refreshBuffer)) {
		defer e.mu.RUnlock()
		return e.token.AccessToken, nil
	}
	e.mu.RUnlock()

	// singleflight prevents thundering herd
	result, err, _ := e.sf.Do("token", func() (interface{}, error) {
		return e.ExchangeToken(ctx, e.defaultScopes)
	})
	if err != nil {
		return "", fmt.Errorf("oauth2 token exchange failed: %w", err)
	}

	token := result.(*iam.OAuth2Token)
	e.mu.Lock()
	e.token = token
	e.mu.Unlock()

	return token.AccessToken, nil
}
