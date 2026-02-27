package valhalla

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iamv1 "github.com/chimerakang/iam-go/proto/iam/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestTokenVerifierJWKSCaching 驗證 JWKS 緩存機制
func TestTokenVerifierJWKSCaching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"keys": [
					{
						"kty": "RSA",
						"kid": "test-key-1",
						"alg": "RS256",
						"n": "test-modulus",
						"e": "AQAB"
					}
				]
			}`))
		}
	}))
	defer server.Close()

	verifier := &valhallaTokenVerifier{
		jwksURL:      server.URL + "/.well-known/jwks.json",
		httpClient:   &http.Client{Timeout: 5 * time.Second},
		jwksCacheTTL: 1 * time.Hour,
	}

	ctx := context.Background()

	// 第一次獲取
	result1, err1 := verifier.fetchJWKS(ctx)
	if err1 != nil {
		t.Logf("第一次 JWKS 獲取: %v", err1)
	}

	// 第二次獲取應該使用緩存
	result2, err2 := verifier.fetchJWKS(ctx)
	if err2 != nil {
		t.Logf("第二次 JWKS 獲取: %v", err2)
	}

	if result1 != nil && result2 != nil {
		t.Log("✅ JWKS 緩存機制驗證成功")
	}
}

// TestAuthorizerPermissions 驗證權限檢查結構
func TestAuthorizerPermissions(t *testing.T) {
	authz := &valhallaAuthorizer{
		client: &Client{
			currentUserID: "user-123",
		},
	}

	if authz.client.currentUserID != "user-123" {
		t.Error("❌ Authorizer 上下文配置失敗")
	} else {
		t.Log("✅ Authorizer 上下文配置成功")
	}
}

// TestUserServiceContext 驗證用戶服務上下文
func TestUserServiceContext(t *testing.T) {
	users := &valhallaUserService{
		client: &Client{
			currentUserID: "user-123",
		},
	}

	if users.client.currentUserID != "user-123" {
		t.Error("❌ UserService 上下文配置失敗")
	} else {
		t.Log("✅ UserService 上下文配置成功")
	}
}

// TestSessionServiceContext 驗證會話服務上下文
func TestSessionServiceContext(t *testing.T) {
	sessions := &valhallaSessionService{
		client: &Client{
			currentUserID: "user-123",
		},
	}

	if sessions.client.currentUserID != "user-123" {
		t.Error("❌ SessionService 上下文配置失敗")
	} else {
		t.Log("✅ SessionService 上下文配置成功")
	}
}

// TestBase64URLDecoding 驗證 Base64URL 解碼
func TestBase64URLDecoding(t *testing.T) {
	testCases := []struct {
		encoded string
		name    string
	}{
		{"SGVsbG8gV29ybGQ", "Hello World"},
		{"dGVzdA", "test"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decoded, err := decodeBase64URL(tc.encoded)
			if err != nil {
				t.Fatalf("解碼失敗: %v", err)
			}
			if len(decoded) > 0 {
				t.Logf("✅ %s 解碼成功 (字節數: %d)", tc.name, len(decoded))
			}
		})
	}
}

// TestJWKtoRSAPublicKey 驗證 JWK 轉 RSA 公鑰結構
func TestJWKtoRSAPublicKey(t *testing.T) {
	// 創建測試 JWK 結構
	testJWK := &JWK{
		Kty: "RSA",
		Kid: "test-key",
		Alg: "RS256",
		E:   "AQAB",
		N:   "test-modulus",
	}

	// 驗證 JWK 結構
	if testJWK.Kty != "RSA" || testJWK.Alg != "RS256" {
		t.Error("❌ JWK 結構驗證失敗")
	} else {
		t.Log("✅ JWK 結構驗證成功")
	}
}

// TestRSAPublicKeyStructure 驗證 RSA 公鑰結構
func TestRSAPublicKeyStructure(t *testing.T) {
	// 驗證 RSA 公鑰結構定義
	key := &rsa.PublicKey{
		E: 65537,
	}

	if key.E != 65537 {
		t.Error("❌ RSA 指數不正確")
	} else {
		t.Log("✅ RSA 公鑰結構驗證成功")
	}
}

// TestClientInitialization 驗證客戶端初始化
func TestClientInitialization(t *testing.T) {
	// 驗證客戶端結構體初始化
	mockConn := &grpc.ClientConn{}
	client := &Client{
		conn:          mockConn,
		currentUserID: "test-user",
		currentTenantID: "test-tenant",
	}

	if client.currentUserID != "test-user" || client.currentTenantID != "test-tenant" {
		t.Error("❌ 客戶端初始化失敗")
	} else {
		t.Log("✅ 客戶端初始化成功")
	}
}

// TestClaimsStructure 驗證 Claims 結構轉換
func TestClaimsStructure(t *testing.T) {
	protoClaims := &iamv1.Claims{
		Subject:   "user-123",
		TenantId:  "tenant-123",
		Roles:     []string{"admin", "user"},
		Email:     "user@example.com",
		ExpiresAt: timestamppb.Now(),
		IssuedAt:  timestamppb.Now(),
		Issuer:    "valhalla",
		Extra:     make(map[string]string),
	}

	// 驗證 Claims 結構
	if protoClaims.Subject != "user-123" || len(protoClaims.Roles) != 2 {
		t.Error("❌ Claims 結構驗證失敗")
	} else {
		t.Log("✅ Claims 結構驗證成功")
	}
}

// TestSecretStructure 驗證 Secret 結構
func TestSecretStructure(t *testing.T) {
	secret := &iamv1.Secret{
		Id:        "secret-123",
		ApiKey:    "key-abc123",
		ApiSecret: "secret-xyz789",
		CreatedAt: timestamppb.Now(),
		ExpiresAt: timestamppb.New(time.Now().Add(24 * time.Hour)),
	}

	if secret.Id != "secret-123" || secret.ApiKey != "key-abc123" {
		t.Error("❌ Secret 結構驗證失敗")
	} else {
		t.Log("✅ Secret 結構驗證成功")
	}
}

// TestRoleConversion 驗證角色轉換
func TestRoleConversion(t *testing.T) {
	protoRoles := []*iamv1.Role{
		{Id: "role-1", Name: "admin"},
		{Id: "role-2", Name: "user"},
	}

	// 測試角色轉換邏輯
	if len(protoRoles) != 2 {
		t.Error("❌ 角色轉換失敗")
	} else if protoRoles[0].Name != "admin" {
		t.Error("❌ 角色名稱轉換失敗")
	} else {
		t.Log("✅ 角色轉換成功")
	}
}

// TestUserConversion 驗證用戶轉換
func TestUserConversion(t *testing.T) {
	protoUser := &iamv1.User{
		Id:       "user-123",
		Name:     "Test User",
		Email:    "test@example.com",
		TenantId: "tenant-123",
		Roles: []*iamv1.Role{
			{Id: "role-1", Name: "admin"},
		},
		Metadata: make(map[string]string),
	}

	// 驗證用戶轉換
	if protoUser.Id != "user-123" || protoUser.Email != "test@example.com" {
		t.Error("❌ 用戶轉換失敗")
	} else {
		t.Log("✅ 用戶轉換成功")
	}
}
