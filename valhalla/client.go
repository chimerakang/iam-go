/**
 * Valhalla IAM 適配器
 * 通過 gRPC 將 iam-go 接口連接到 Valhalla IAM 服務
 *
 * Usage:
 *   client, err := valhalla.NewClient("localhost:50051")
 *   if err != nil {
 *       log.Fatal(err)
 *   }
 *   defer client.Close()
 *
 *   iamClient := iam.NewClient(
 *       iam.WithTokenVerifier(client.Verifier()),
 *       iam.WithAuthorizer(client.Authz()),
 *       iam.WithUserService(client.Users()),
 *   )
 */

package valhalla

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	iam "github.com/chimerakang/iam-go"
	iamv1 "github.com/chimerakang/iam-go/proto/iam/v1"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
)

// Client 包裝 gRPC 連接到 Valhalla IAM 服務
type Client struct {
	conn *grpc.ClientConn

	// gRPC 服務客戶端
	authzClient   iamv1.AuthzServiceClient
	userClient    iamv1.UserServiceClient
	tenantClient  iamv1.TenantServiceClient
	sessionClient iamv1.SessionServiceClient
	secretClient  iamv1.SecretServiceClient

	// iam-go 接口實現
	verifier   iam.TokenVerifier
	authz      iam.Authorizer
	users      iam.UserService
	tenants    iam.TenantService
	sessions   iam.SessionService
	secrets    iam.SecretService

	// 當前用戶上下文（從 token 中提取）
	currentUserID   string
	currentTenantID string
}

// NewClient 建立到 Valhalla IAM 服務的連接
func NewClient(target string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) == 0 {
		// 預設不安全連接（開發用）
		opts = []grpc.DialOption{grpc.WithInsecure()}
	}

	conn, err := grpc.Dial(target, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Valhalla: %w", err)
	}

	client := &Client{
		conn:          conn,
		authzClient:   iamv1.NewAuthzServiceClient(conn),
		userClient:    iamv1.NewUserServiceClient(conn),
		tenantClient:  iamv1.NewTenantServiceClient(conn),
		sessionClient: iamv1.NewSessionServiceClient(conn),
		secretClient:  iamv1.NewSecretServiceClient(conn),
	}

	// 初始化 iam-go 接口實現
	httpClient := &http.Client{Timeout: 10 * time.Second}
	jwksURL := fmt.Sprintf("http://%s/.well-known/jwks.json", target)

	client.verifier = &valhallaTokenVerifier{
		secretClient:  client.secretClient,
		jwksURL:       jwksURL,
		httpClient:    httpClient,
		jwksCacheTTL:  1 * time.Hour,
	}
	client.authz = &valhallaAuthorizer{authzClient: client.authzClient, client: client}
	client.users = &valhallaUserService{userClient: client.userClient, client: client}
	client.tenants = &valhallaTenantService{tenantClient: client.tenantClient}
	client.sessions = &valhallaSessionService{sessionClient: client.sessionClient, client: client}
	client.secrets = &valhallaSecretService{secretClient: client.secretClient}

	return client, nil
}

// Close 關閉到 Valhalla 的連接
func (c *Client) Close() error {
	return c.conn.Close()
}

// Verifier 返回 TokenVerifier 實現
func (c *Client) Verifier() iam.TokenVerifier {
	return c.verifier
}

// Authz 返回 Authorizer 實現
func (c *Client) Authz() iam.Authorizer {
	return c.authz
}

// Users 返回 UserService 實現
func (c *Client) Users() iam.UserService {
	return c.users
}

// Tenants 返回 TenantService 實現
func (c *Client) Tenants() iam.TenantService {
	return c.tenants
}

// Sessions 返回 SessionService 實現
func (c *Client) Sessions() iam.SessionService {
	return c.sessions
}

// Secrets 返回 SecretService 實現
func (c *Client) Secrets() iam.SecretService {
	return c.secrets
}

// SetCurrentUser 設置當前用戶上下文（通常在驗證 token 後調用）
func (c *Client) SetCurrentUser(userID, tenantID string) {
	c.currentUserID = userID
	c.currentTenantID = tenantID
}

// --- TokenVerifier Implementation ---

type valhallaTokenVerifier struct {
	secretClient  iamv1.SecretServiceClient
	jwksURL       string
	httpClient    *http.Client
	jwksCache     map[string]interface{}
	jwksCacheTime time.Time
	jwksCacheTTL  time.Duration
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// fetchJWKS retrieves JWKS from Valhalla with caching
func (v *valhallaTokenVerifier) fetchJWKS(ctx context.Context) (*JWKS, error) {
	// Check cache
	if v.jwksCache != nil && time.Since(v.jwksCacheTime) < v.jwksCacheTTL {
		data, _ := json.Marshal(v.jwksCache)
		jwks := &JWKS{}
		json.Unmarshal(data, jwks)
		return jwks, nil
	}

	// Fetch from endpoint
	req, err := http.NewRequestWithContext(ctx, "GET", v.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("JWKS endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	jwks := &JWKS{}
	if err := json.NewDecoder(resp.Body).Decode(jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Cache the result
	v.jwksCache = make(map[string]interface{})
	jwksData, _ := json.Marshal(jwks)
	json.Unmarshal(jwksData, &v.jwksCache)
	v.jwksCacheTime = time.Now()

	return jwks, nil
}

// verifyTokenSignature verifies RS256 signature using JWKS
func (v *valhallaTokenVerifier) verifyTokenSignature(ctx context.Context, tokenString string) (jwt.MapClaims, error) {
	// Parse token header to get kid
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header
	headerJSON, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to parse header: %w", err)
	}

	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s", header.Alg)
	}

	// Fetch JWKS
	jwks, err := v.fetchJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Find key
	var key *JWK
	for i := range jwks.Keys {
		if jwks.Keys[i].Kid == header.Kid {
			key = &jwks.Keys[i]
			break
		}
	}
	if key == nil && len(jwks.Keys) > 0 {
		// Fallback to first key if kid not found
		key = &jwks.Keys[0]
	}
	if key == nil {
		return nil, fmt.Errorf("no keys available in JWKS")
	}

	// Verify token using jwt library with public key
	claims := jwt.MapClaims{}
	_, err = jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "RS256" {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Convert JWK to RSA public key
		publicKey, err := jwkToRSAPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to convert JWK to RSA key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	return claims, nil
}

// Verify implements iam.TokenVerifier
func (v *valhallaTokenVerifier) Verify(ctx context.Context, token string) (*iam.Claims, error) {
	token = strings.TrimPrefix(token, "Bearer ")

	// Verify signature
	claims, err := v.verifyTokenSignature(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Extract standard claims
	result := &iam.Claims{
		Extra: make(map[string]any),
	}

	if sub, ok := claims["sub"].(string); ok {
		result.Subject = sub
	}
	if tenantID, ok := claims["tenant_id"].(string); ok {
		result.TenantID = tenantID
	}
	if email, ok := claims["email"].(string); ok {
		result.Email = email
	}
	if issuer, ok := claims["iss"].(string); ok {
		result.Issuer = issuer
	}

	// Extract roles array
	if roles, ok := claims["roles"].([]interface{}); ok {
		result.Roles = make([]string, len(roles))
		for i, role := range roles {
			if r, ok := role.(string); ok {
				result.Roles[i] = r
			}
		}
	}

	// Extract timestamps
	if exp, ok := claims["exp"].(float64); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Store extra claims
	for key, value := range claims {
		if key != "sub" && key != "tenant_id" && key != "email" &&
			key != "iss" && key != "roles" && key != "exp" && key != "iat" &&
			key != "aud" && key != "nbf" && key != "jti" {
			result.Extra[key] = value
		}
	}

	return result, nil
}

// --- Authorizer Implementation ---

type valhallaAuthorizer struct {
	authzClient iamv1.AuthzServiceClient
	client      *Client
}

func (a *valhallaAuthorizer) Check(ctx context.Context, permission string) (bool, error) {
	resp, err := a.authzClient.CheckPermission(ctx, &iamv1.CheckPermissionRequest{
		UserId:     a.client.currentUserID,
		Permission: permission,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check permission: %w", err)
	}
	return resp.Allowed, nil
}

func (a *valhallaAuthorizer) CheckResource(ctx context.Context, resource, action string) (bool, error) {
	resp, err := a.authzClient.CheckResourcePermission(ctx, &iamv1.CheckResourcePermissionRequest{
		UserId:   a.client.currentUserID,
		Resource: resource,
		Action:   action,
	})
	if err != nil {
		return false, fmt.Errorf("failed to check resource permission: %w", err)
	}
	return resp.Allowed, nil
}

func (a *valhallaAuthorizer) GetPermissions(ctx context.Context) ([]string, error) {
	resp, err := a.authzClient.GetPermissions(ctx, &iamv1.GetPermissionsRequest{
		UserId: a.client.currentUserID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get permissions: %w", err)
	}
	return resp.Permissions, nil
}

// --- UserService Implementation ---

type valhallaUserService struct {
	userClient iamv1.UserServiceClient
	client     *Client
}

func (u *valhallaUserService) GetCurrent(ctx context.Context) (*iam.User, error) {
	if u.client.currentUserID == "" {
		return nil, fmt.Errorf("no current user set")
	}
	return u.Get(ctx, u.client.currentUserID)
}

func (u *valhallaUserService) Get(ctx context.Context, userID string) (*iam.User, error) {
	resp, err := u.userClient.GetUser(ctx, &iamv1.GetUserRequest{
		UserId: userID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	roles := make([]iam.Role, len(resp.Roles))
	for i, r := range resp.Roles {
		roles[i] = iam.Role{
			ID:   r.Id,
			Name: r.Name,
		}
	}

	metadata := make(map[string]any)
	for k, v := range resp.Metadata {
		metadata[k] = v
	}

	return &iam.User{
		ID:       resp.Id,
		Email:    resp.Email,
		Name:     resp.Name,
		TenantID: resp.TenantId,
		Roles:    roles,
		Metadata: metadata,
	}, nil
}

func (u *valhallaUserService) List(ctx context.Context, opts iam.ListOptions) ([]*iam.User, int, error) {
	resp, err := u.userClient.ListUsers(ctx, &iamv1.ListUsersRequest{
		Page:     int32(opts.Page),
		PageSize: int32(opts.PageSize),
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]*iam.User, len(resp.Users))
	for i, u := range resp.Users {
		roles := make([]iam.Role, len(u.Roles))
		for j, r := range u.Roles {
			roles[j] = iam.Role{
				ID:   r.Id,
				Name: r.Name,
			}
		}

		metadata := make(map[string]any)
		for k, v := range u.Metadata {
			metadata[k] = v
		}

		users[i] = &iam.User{
			ID:       u.Id,
			Email:    u.Email,
			Name:     u.Name,
			TenantID: u.TenantId,
			Roles:    roles,
			Metadata: metadata,
		}
	}

	return users, int(resp.Total), nil
}

func (u *valhallaUserService) GetRoles(ctx context.Context, userID string) ([]iam.Role, error) {
	resp, err := u.userClient.GetUserRoles(ctx, &iamv1.GetUserRolesRequest{
		UserId: userID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get user roles: %w", err)
	}

	roles := make([]iam.Role, len(resp.Roles))
	for i, r := range resp.Roles {
		roles[i] = iam.Role{
			ID:   r.Id,
			Name: r.Name,
		}
	}

	return roles, nil
}

// --- TenantService Implementation ---

type valhallaTenantService struct {
	tenantClient iamv1.TenantServiceClient
}

func (t *valhallaTenantService) Resolve(ctx context.Context, identifier string) (*iam.Tenant, error) {
	resp, err := t.tenantClient.ResolveTenant(ctx, &iamv1.ResolveTenantRequest{
		Identifier: identifier,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to resolve tenant: %w", err)
	}

	return &iam.Tenant{
		ID:     resp.Id,
		Name:   resp.Name,
		Slug:   resp.Slug,
		Status: resp.Status,
	}, nil
}

func (t *valhallaTenantService) ValidateMembership(ctx context.Context, userID, tenantID string) (bool, error) {
	resp, err := t.tenantClient.ValidateMembership(ctx, &iamv1.ValidateMembershipRequest{
		UserId:   userID,
		TenantId: tenantID,
	})
	if err != nil {
		return false, fmt.Errorf("failed to validate membership: %w", err)
	}

	return resp.IsMember, nil
}

// --- SessionService Implementation ---

type valhallaSessionService struct {
	sessionClient iamv1.SessionServiceClient
	client        *Client
}

func (s *valhallaSessionService) List(ctx context.Context) ([]iam.Session, error) {
	resp, err := s.sessionClient.ListSessions(ctx, &iamv1.ListSessionsRequest{
		UserId: s.client.currentUserID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list sessions: %w", err)
	}

	sessions := make([]iam.Session, len(resp.Sessions))
	for i, sess := range resp.Sessions {
		sessions[i] = iam.Session{
			ID:        sess.Id,
			UserID:    sess.UserId,
			CreatedAt: sess.CreatedAt.AsTime(),
			ExpiresAt: sess.ExpiresAt.AsTime(),
			UserAgent: sess.UserAgent,
			IP:        sess.Ip,
		}
	}

	return sessions, nil
}

func (s *valhallaSessionService) Revoke(ctx context.Context, sessionID string) error {
	_, err := s.sessionClient.RevokeSession(ctx, &iamv1.RevokeSessionRequest{
		SessionId: sessionID,
	})
	if err != nil {
		return fmt.Errorf("failed to revoke session: %w", err)
	}
	return nil
}

func (s *valhallaSessionService) RevokeAllOthers(ctx context.Context) error {
	_, err := s.sessionClient.RevokeAllOtherSessions(ctx, &iamv1.RevokeAllOtherSessionsRequest{
		UserId:           s.client.currentUserID,
		CurrentSessionId: "",
	})
	if err != nil {
		return fmt.Errorf("failed to revoke other sessions: %w", err)
	}
	return nil
}

// --- SecretService Implementation ---

type valhallaSecretService struct {
	secretClient iamv1.SecretServiceClient
}

func (s *valhallaSecretService) Create(ctx context.Context, description string) (*iam.Secret, error) {
	resp, err := s.secretClient.CreateSecret(ctx, &iamv1.CreateSecretRequest{
		Description: description,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secret: %w", err)
	}

	return &iam.Secret{
		ID:        resp.Id,
		APIKey:    resp.ApiKey,
		APISecret: resp.ApiSecret,
		CreatedAt: resp.CreatedAt.AsTime(),
		ExpiresAt: resp.ExpiresAt.AsTime(),
	}, nil
}

func (s *valhallaSecretService) List(ctx context.Context) ([]iam.Secret, error) {
	resp, err := s.secretClient.ListSecrets(ctx, &iamv1.ListSecretsRequest{})
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	secrets := make([]iam.Secret, len(resp.Secrets))
	for i, secret := range resp.Secrets {
		secrets[i] = iam.Secret{
			ID:        secret.Id,
			APIKey:    secret.ApiKey,
			APISecret: secret.ApiSecret,
			CreatedAt: secret.CreatedAt.AsTime(),
			ExpiresAt: secret.ExpiresAt.AsTime(),
		}
	}

	return secrets, nil
}

func (s *valhallaSecretService) Delete(ctx context.Context, secretID string) error {
	_, err := s.secretClient.DeleteSecret(ctx, &iamv1.DeleteSecretRequest{
		SecretId: secretID,
	})
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}
	return nil
}

func (s *valhallaSecretService) Verify(ctx context.Context, apiKey, apiSecret string) (*iam.Claims, error) {
	resp, err := s.secretClient.VerifySecret(ctx, &iamv1.VerifySecretRequest{
		ApiKey:    apiKey,
		ApiSecret: apiSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to verify secret: %w", err)
	}

	extra := make(map[string]any)
	for k, v := range resp.Claims.Extra {
		extra[k] = v
	}

	return &iam.Claims{
		Subject:   resp.Claims.Subject,
		TenantID:  resp.Claims.TenantId,
		Roles:     resp.Claims.Roles,
		Email:     resp.Claims.Email,
		ExpiresAt: resp.Claims.ExpiresAt.AsTime(),
		IssuedAt:  resp.Claims.IssuedAt.AsTime(),
		Issuer:    resp.Claims.Issuer,
		Extra:     extra,
	}, nil
}

func (s *valhallaSecretService) Rotate(ctx context.Context, secretID string) (*iam.Secret, error) {
	resp, err := s.secretClient.RotateSecret(ctx, &iamv1.RotateSecretRequest{
		SecretId: secretID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to rotate secret: %w", err)
	}

	return &iam.Secret{
		ID:        resp.Id,
		APIKey:    resp.ApiKey,
		APISecret: resp.ApiSecret,
		CreatedAt: resp.CreatedAt.AsTime(),
		ExpiresAt: resp.ExpiresAt.AsTime(),
	}, nil
}

// --- Helper Functions ---

// decodeBase64URL decodes a base64url-encoded string
func decodeBase64URL(encoded string) ([]byte, error) {
	// Add padding if necessary
	switch len(encoded) % 4 {
	case 2:
		encoded += "=="
	case 3:
		encoded += "="
	}

	// Replace URL-safe characters and decode
	return base64.URLEncoding.DecodeString(encoded)
}

// jwkToRSAPublicKey converts JWK to RSA public key
func jwkToRSAPublicKey(key *JWK) (interface{}, error) {
	// Decode modulus (n)
	nBytes, err := decodeBase64URL(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := decodeBase64URL(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert bytes to big.Int
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	// Convert exponent to int
	eInt := int(e.Int64())
	if eInt == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: n,
		E: eInt,
	}

	return publicKey, nil
}
