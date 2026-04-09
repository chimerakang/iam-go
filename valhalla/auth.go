package valhalla

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	iam "github.com/chimerakang/iam-go"
)

// valhallaAuthService implements iam.AuthService via Valhalla REST API.
// Automatically injects client_id when configured.
type valhallaAuthService struct {
	httpClient *http.Client
	baseURL    string   // e.g., "http://localhost:8080"
	clientID   string   // auto-injected into login requests
}

// socialLoginRequestBody is the JSON body for POST /api/v1/auth/social/{provider}.
type socialLoginRequestBody struct {
	Provider string `json:"provider"`
	IDToken  string `json:"id_token"`
	Nonce    string `json:"nonce,omitempty"`
	AppID    string `json:"app_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
}

// loginRequestBody is the JSON body for POST /api/v1/auth/login.
type loginRequestBody struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantID string `json:"tenant_id,omitempty"`
	ClientID string `json:"client_id,omitempty"`
}

// loginResponseBody is the JSON response from Valhalla's Login endpoint.
type loginResponseBody struct {
	User   *loginUser   `json:"user"`
	Tokens *loginTokens `json:"tokens"`
}

type loginUser struct {
	ID       string   `json:"id"`
	Email    string   `json:"email"`
	Name     string   `json:"name"`
	TenantID string   `json:"tenantId"`
	Roles    []string `json:"roles"`
}

type loginTokens struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	ExpiresIn    int32  `json:"expiresIn"`
	TokenType    string `json:"tokenType"`
}

// Login authenticates a user via Valhalla's REST API.
// If client_id is not explicitly set in the request but configured on the adapter,
// it is automatically injected so that the resulting JWT contains app_scopes.
func (a *valhallaAuthService) Login(ctx context.Context, req iam.LoginRequest) (*iam.LoginResponse, error) {
	// Auto-inject client_id from adapter config if not explicitly provided
	clientID := req.ClientID
	if clientID == "" && a.clientID != "" {
		clientID = a.clientID
	}

	body := loginRequestBody{
		Email:    req.Email,
		Password: req.Password,
		TenantID: req.TenantID,
		ClientID: clientID,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login request: %w", err)
	}

	url := a.baseURL + "/api/v1/auth/login"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var loginResp loginResponseBody
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to decode login response: %w", err)
	}

	result := &iam.LoginResponse{
		Tokens: &iam.TokenPair{
			TokenType: "Bearer",
		},
	}

	if loginResp.User != nil {
		roles := make([]iam.Role, len(loginResp.User.Roles))
		for i, r := range loginResp.User.Roles {
			roles[i] = iam.Role{Name: r}
		}
		result.User = &iam.User{
			ID:       loginResp.User.ID,
			Email:    loginResp.User.Email,
			Name:     loginResp.User.Name,
			TenantID: loginResp.User.TenantID,
			Roles:    roles,
		}
	}

	if loginResp.Tokens != nil {
		result.Tokens.AccessToken = loginResp.Tokens.AccessToken
		result.Tokens.RefreshToken = loginResp.Tokens.RefreshToken
		result.Tokens.ExpiresIn = loginResp.Tokens.ExpiresIn
		if loginResp.Tokens.TokenType != "" {
			result.Tokens.TokenType = loginResp.Tokens.TokenType
		}
	}

	return result, nil
}

// SocialLogin authenticates a user via a third-party OAuth2 provider.
// Calls POST /api/v1/auth/social/{provider} on Valhalla.
func (a *valhallaAuthService) SocialLogin(ctx context.Context, req iam.SocialLoginRequest) (*iam.LoginResponse, error) {
	body := socialLoginRequestBody{
		Provider: req.Provider,
		IDToken:  req.IDToken,
		Nonce:    req.Nonce,
		AppID:    req.AppID,
		TenantID: req.TenantID,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal social login request: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/auth/social/%s", a.baseURL, req.Provider)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create social login request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("social login request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read social login response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("social login failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var loginResp loginResponseBody
	if err := json.Unmarshal(respBody, &loginResp); err != nil {
		return nil, fmt.Errorf("failed to decode social login response: %w", err)
	}

	result := &iam.LoginResponse{
		Tokens: &iam.TokenPair{
			TokenType: "Bearer",
		},
	}

	if loginResp.User != nil {
		roles := make([]iam.Role, len(loginResp.User.Roles))
		for i, r := range loginResp.User.Roles {
			roles[i] = iam.Role{Name: r}
		}
		result.User = &iam.User{
			ID:       loginResp.User.ID,
			Email:    loginResp.User.Email,
			Name:     loginResp.User.Name,
			TenantID: loginResp.User.TenantID,
			Roles:    roles,
		}
	}

	if loginResp.Tokens != nil {
		result.Tokens.AccessToken = loginResp.Tokens.AccessToken
		result.Tokens.RefreshToken = loginResp.Tokens.RefreshToken
		result.Tokens.ExpiresIn = loginResp.Tokens.ExpiresIn
		if loginResp.Tokens.TokenType != "" {
			result.Tokens.TokenType = loginResp.Tokens.TokenType
		}
	}

	return result, nil
}
