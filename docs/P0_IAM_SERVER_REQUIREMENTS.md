# P0: IAM Server Requirements
## 標準 IAM Server 應實現的功能規範

> 本文檔定義了任何 IAM server 都應該實現的標準功能。
> 這些功能是 iam-go SDK 的運作基礎，確保 SDK 可與任何符合 P0 標準的 IAM server 互操作。
>
> **最後更新：** 2026-02-26
> **適用版本：** iam-go v0.1.0+

---

## 目錄

1. [概述](#概述)
2. [P0.1: RS256 JWT + JWKS Endpoint](#p01-rs256-jwt--jwks-endpoint)
3. [P0.2: OAuth2 Client Credentials Grant](#p02-oauth2-client-credentials-grant)
4. [P0.3: IAM Service API for External Consumers](#p03-iam-service-api-for-external-consumers)
5. [實現檢查清單](#實現檢查清單)

---

## 概述

### 為什麼需要 P0？

iam-go SDK 是後端無關的，設計用於與任何 IAM server 整合。P0 定義了這種整合的**最小要求**，確保：

- ✅ 服務可以**本地驗證 JWT**（無需每次都呼叫 IAM server）
- ✅ 服務可以**透過 OAuth2 Client Credentials** 取得 M2M access token
- ✅ 外部系統可以**查詢權限和租戶信息**（無需存儲副本）

### 使用場景

```
┌─────────────────────────────────────────────┐
│          IAM Server (P0 實現)                 │
│  ┌─────────────────────────────────────┐   │
│  │ P0.1: JWT + JWKS                    │   │
│  │ P0.2: OAuth2 Client Credentials     │   │
│  │ P0.3: External Service API          │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
            ↓
┌─────────────────────────────────────────────┐
│       應用服務 (使用 iam-go SDK)              │
│  ┌─────────────────────────────────────┐   │
│  │ P1.1: 本地驗證 JWT (via JWKS)       │   │
│  │ P1.3: 檢查權限 (cached)             │   │
│  │ P1.4: OAuth2 Token Exchange          │   │
│  └─────────────────────────────────────┘   │
└─────────────────────────────────────────────┘
```

---

## P0.1: RS256 JWT + JWKS Endpoint

### 概述

IAM server 必須支援 RS256 簽名的 JWT token，並提供 JWKS（JSON Web Key Set）端點供外部服務驗證。

### 技術規格

| 項目 | 要求 |
|------|------|
| **簽名算法** | RS256（RSA Signature with SHA-256） |
| **JWKS 端點** | `GET /.well-known/jwks.json` |
| **公鑰格式** | JWK（JSON Web Key）- RFC 7517 |
| **金鑰輪換** | 支援多個活躍金鑰（`kid` 欄位） |
| **緩存策略** | 客戶端應緩存 JWKS，提供 `Cache-Control` 頭 |

### 1.1 JWKS 端點規格

#### 請求

```http
GET /.well-known/jwks.json HTTP/1.1
Host: iam-server.example.com
```

#### 響應格式

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-01-primary",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-02-secondary",
      "n": "xjlCRBqkQwVJ...",
      "e": "AQAB"
    }
  ]
}
```

#### 響應頭（重要）

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: public, max-age=3600
```

### 1.2 JWT Token 格式

#### Token 結構

```
eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjQtMDEtcHJpbWFyeSJ9.
eyJzdWIiOiJ1c2VyLWFiYzEyMyIsInRlbmFudF9pZCI6InRlbmFudC14eXoxMjMiLCJyb2xlcyI6WyJhZG1pbiJdLCJpc3MiOiJodHRwczovL2lhbS5leGFtcGxlLmNvbSIsImV4cCI6MTcwODc2OTk5OSwiaWF0IjoxNzA4NjgzNTk5fQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c...
```

#### Token Payload（Required Claims）

```json
{
  "sub": "user-abc123",           // 用戶 ID（必須）
  "tenant_id": "tenant-xyz123",   // 租戶 ID（必須）
  "roles": ["admin", "editor"],   // 角色列表（必須）
  "iss": "https://iam.example.com", // 發行者（必須）
  "exp": 1708769999,              // 過期時間（必須）
  "iat": 1708683599,              // 發行時間（必須）
  "email": "user@example.com",    // 電子郵件（必須）
  "name": "John Doe"              // 用戶名稱（推薦）
}
```

### 1.3 實現參考代碼

#### Go 實現示例

```go
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateRSAKeyPair 生成 RSA 金鑰對
func GenerateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// JWKSResponse 表示 JWKS 端點的響應
type JWKSResponse struct {
	Keys []map[string]interface{} `json:"keys"`
}

// PrivateKeyToJWK 將私鑰轉換為 JWK 格式
func PrivateKeyToJWK(privKey *rsa.PrivateKey, kid string) map[string]interface{} {
	pubKey := privKey.Public().(*rsa.PublicKey)
	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": kid,
		"n":   base64url.EncodeToString(pubKey.N.Bytes()),
		"e":   base64url.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes()),
	}
}

// GenerateJWT 生成 RS256 簽名的 JWT
func GenerateJWT(userID, tenantID, email string, roles []string, privKey *rsa.PrivateKey) (string, error) {
	claims := jwt.MapClaims{
		"sub":       userID,
		"tenant_id": tenantID,
		"roles":     roles,
		"email":     email,
		"iss":       "https://iam.example.com",
		"exp":       time.Now().Add(24 * time.Hour).Unix(),
		"iat":       time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "2024-01-primary"

	return token.SignedString(privKey)
}

// HTTP Handler 示例
func JWKSHandler(w http.ResponseWriter, r *http.Request) {
	// 從存儲中取出公鑰
	jwkResponse := JWKSResponse{
		Keys: []map[string]interface{}{
			PrivateKeyToJWK(privKey1, "2024-01-primary"),
			PrivateKeyToJWK(privKey2, "2024-02-secondary"),
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	json.NewEncoder(w).Encode(jwkResponse)
}
```

### 1.4 驗證方法

#### iam-go SDK 如何驗證

```go
// iam-go 的 JWKS Client（P1.1）會：
// 1. 定期從 /.well-known/jwks.json 取得公鑰
// 2. 本地使用公鑰驗證 JWT 簽名
// 3. 無需調用 IAM server

verifier, _ := jwks.NewVerifier("https://iam.example.com")
claims, err := verifier.Verify(ctx, tokenString)
// err == nil 表示簽名有效
```

---

## P0.2: OAuth2 Client Credentials Grant

### 概述

IAM server 必須提供 OAuth2 Client Credentials Grant（RFC 6749 Section 4.4），供服務間（M2M）認證。應用程式使用 client_id 和 client_secret 交換 access token。

### 技術規格

| 項目 | 要求 |
|------|------|
| **授權類型** | `client_credentials`（RFC 6749 Section 4.4） |
| **Token 端點** | `POST /oauth2/token` |
| **認證方式** | HTTP Basic 或 POST body（client_id + client_secret） |
| **Token 格式** | Bearer access token（JWT 或 opaque） |
| **Scope** | 支援可配置的 scope 列表 |
| **TTL** | 可配置的 token 過期時間（建議 3600 秒） |

### 2.1 OAuth2 Client 資料結構

#### 資料庫 Schema

```sql
CREATE TABLE oauth2_clients (
  id UUID PRIMARY KEY,
  client_id VARCHAR(64) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255) NOT NULL,   -- bcrypt 雜湊
  name TEXT,
  allowed_scopes TEXT[],                       -- 允許的 scope 列表
  status VARCHAR(20) DEFAULT 'active',         -- active, revoked
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  INDEX (client_id)
);
```

#### OAuth2 Client 物件

```json
{
  "client_id": "svc-order-service",
  "client_secret": "cs_live_abcd1234...",     // 僅在建立時返回
  "name": "Order Service",
  "allowed_scopes": ["read", "write", "admin"],
  "status": "active",
  "created_at": "2024-01-15T10:30:00Z"
}
```

### 2.2 Token 端點規格

#### Token Exchange - 交換 Access Token

```http
POST /oauth2/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=svc-order-service&
client_secret=cs_live_abcd1234...&
scope=read write
```

**響應 (200 OK)**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiI...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "read write"
}
```

**錯誤響應 (401 Unauthorized)**
```json
{
  "error": "invalid_client",
  "error_description": "Client authentication failed"
}
```

### 2.3 實現參考代碼

#### Go 實現示例

```go
package main

import (
	"crypto/rand"
	"encoding/base64"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// OAuth2Client 表示一個 OAuth2 client 應用程式
type OAuth2Client struct {
	ID               string    `db:"id"`
	ClientID         string    `db:"client_id"`
	ClientSecretHash string    `db:"client_secret_hash"`
	Name             string    `db:"name"`
	AllowedScopes    []string  `db:"allowed_scopes"`
	Status           string    `db:"status"`
	CreatedAt        time.Time `db:"created_at"`
}

// TokenResponse 表示 OAuth2 token 響應
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int32  `json:"expires_in"`
	Scope       string `json:"scope"`
}

// HandleTokenRequest 處理 /oauth2/token 請求
func HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	grantType := r.FormValue("grant_type")
	if grantType != "client_credentials" {
		http.Error(w, `{"error":"unsupported_grant_type"}`, 400)
		return
	}

	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	// 驗證 client credentials
	client, err := validateClient(r.Context(), clientID, clientSecret)
	if err != nil {
		http.Error(w, `{"error":"invalid_client"}`, 401)
		return
	}

	// 驗證 scope
	requestedScopes := strings.Split(r.FormValue("scope"), " ")
	validScopes := validateScopes(requestedScopes, client.AllowedScopes)

	// 產生 access token
	token, expiresIn := generateAccessToken(client, validScopes)

	json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		Scope:       strings.Join(validScopes, " "),
	})
}
```

---

## P0.3: IAM Service API for External Consumers

### 概述

IAM server 必須提供一個 gRPC（或 REST）服務，供外部系統查詢權限、驗證 token、驗證租戶成員身份。該服務透過 OAuth2 Bearer token 認證。

### 技術規格

| 項目 | 要求 |
|------|------|
| **協議** | gRPC (Protocol Buffers) 或 REST |
| **認證** | OAuth2 Bearer Token（`Authorization: Bearer {token}`） |
| **快取** | 支援響應快取（TTL 可配置） |
| **限流** | 按 client ID 實施速率限制 |

### 3.1 Proto 服務定義

```protobuf
syntax = "proto3";

package iam.v1;

service IAMService {
  // IntrospectToken 驗證 token 並返回 claims
  rpc IntrospectToken(IntrospectRequest) returns (IntrospectResponse);

  // CheckPermission 檢查用戶是否有特定權限
  rpc CheckPermission(CheckPermissionRequest) returns (CheckPermissionResponse);

  // GetUserPermissions 取得用戶的所有權限
  rpc GetUserPermissions(GetUserPermissionsRequest) returns (GetUserPermissionsResponse);

  // GetUser 按 ID 查詢用戶信息
  rpc GetUser(GetUserRequest) returns (User);

  // ValidateTenantMembership 驗證用戶是否屬於租戶
  rpc ValidateTenantMembership(ValidateMembershipRequest) returns (ValidateMembershipResponse);

  // GetTenantBySlug 按 slug 查詢租戶
  rpc GetTenantBySlug(GetTenantBySlugRequest) returns (Tenant);
}

// IntrospectToken 相關
message IntrospectRequest {
  string token = 1;
}

message IntrospectResponse {
  bool active = 1;
  string subject = 2;
  string tenant_id = 3;
  repeated string roles = 4;
  string email = 5;
  int64 issued_at = 6;
  int64 expires_at = 7;
}

// CheckPermission 相關
message CheckPermissionRequest {
  string user_id = 1;
  string tenant_id = 2;
  string permission = 3;
}

message CheckPermissionResponse {
  bool allowed = 1;
}

// GetUserPermissions 相關
message GetUserPermissionsRequest {
  string user_id = 1;
  string tenant_id = 2;
}

message GetUserPermissionsResponse {
  repeated string permissions = 1;
}

// GetUser 相關
message GetUserRequest {
  string user_id = 1;
}

message User {
  string id = 1;
  string email = 2;
  string name = 3;
  string tenant_id = 4;
  repeated string roles = 5;
}

// ValidateTenantMembership 相關
message ValidateMembershipRequest {
  string user_id = 1;
  string tenant_id = 2;
}

message ValidateMembershipResponse {
  bool is_member = 1;
  string role = 2;
}

// GetTenantBySlug 相關
message GetTenantBySlugRequest {
  string slug = 1;
}

message Tenant {
  string id = 1;
  string name = 2;
  string slug = 3;
  string status = 4;
}
```

### 3.2 REST API 替代方案

如果使用 REST 而非 gRPC：

#### IntrospectToken

```http
POST /api/v1/introspect HTTP/1.1
Authorization: Bearer {access_token}

{
  "token": "eyJhbGciOiJSUzI1NiI..."
}
```

**響應**
```json
{
  "active": true,
  "subject": "user-123",
  "tenant_id": "tenant-xyz",
  "roles": ["admin"],
  "email": "user@example.com",
  "issued_at": 1708683599,
  "expires_at": 1708769999
}
```

#### CheckPermission

```http
POST /api/v1/check-permission HTTP/1.1
Authorization: Bearer {access_token}

{
  "user_id": "user-123",
  "tenant_id": "tenant-xyz",
  "permission": "user:read"
}
```

**響應**
```json
{
  "allowed": true
}
```

#### GetUserPermissions

```http
GET /api/v1/users/user-123/permissions?tenant_id=tenant-xyz HTTP/1.1
Authorization: Bearer {access_token}
```

**響應**
```json
{
  "permissions": ["user:read", "user:write", "admin"]
}
```

#### ValidateTenantMembership

```http
POST /api/v1/validate-membership HTTP/1.1
Authorization: Bearer {access_token}

{
  "user_id": "user-123",
  "tenant_id": "tenant-xyz"
}
```

**響應**
```json
{
  "is_member": true,
  "role": "admin"
}
```

#### GetUser

```http
GET /api/v1/users/user-123 HTTP/1.1
Authorization: Bearer {access_token}
```

**響應**
```json
{
  "id": "user-123",
  "email": "user@example.com",
  "name": "John Doe",
  "tenant_id": "tenant-xyz",
  "roles": ["admin", "editor"]
}
```

#### GetTenantBySlug

```http
GET /api/v1/tenants/my-company HTTP/1.1
Authorization: Bearer {access_token}
```

**響應**
```json
{
  "id": "tenant-xyz123",
  "name": "My Company",
  "slug": "my-company",
  "status": "active"
}
```

### 3.3 實現參考代碼

#### Go gRPC 實現示例

```go
package main

import (
	"context"
	"fmt"
	pb "github.com/chimerakang/iam-go/proto/iam/v1"
)

type IAMServiceServer struct {
	pb.UnimplementedIAMServiceServer
	db *sql.DB
}

// IntrospectToken 驗證 token
func (s *IAMServiceServer) IntrospectToken(ctx context.Context, req *pb.IntrospectRequest) (*pb.IntrospectResponse, error) {
	// 使用 JWT 驗證庫驗證 token
	claims, err := verifyJWT(req.Token)
	if err != nil {
		return &pb.IntrospectResponse{Active: false}, nil
	}

	return &pb.IntrospectResponse{
		Active:    true,
		Subject:   claims.Subject,
		TenantId:  claims.TenantID,
		Roles:     claims.Roles,
		Email:     claims.Email,
		IssuedAt:  claims.IssuedAt.Unix(),
		ExpiresAt: claims.ExpiresAt.Unix(),
	}, nil
}

// CheckPermission 檢查權限
func (s *IAMServiceServer) CheckPermission(ctx context.Context, req *pb.CheckPermissionRequest) (*pb.CheckPermissionResponse, error) {
	// 查詢資料庫檢查權限
	var allowed bool
	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM role_permissions rp
			JOIN user_roles ur ON ur.role_id = rp.role_id
			WHERE ur.user_id = ? AND rp.permission = ? AND ur.tenant_id = ?
		)`,
		req.UserId, req.Permission, req.TenantId,
	).Scan(&allowed)

	if err != nil {
		return nil, fmt.Errorf("permission check failed: %w", err)
	}

	return &pb.CheckPermissionResponse{Allowed: allowed}, nil
}

// GetUserPermissions 取得用戶權限
func (s *IAMServiceServer) GetUserPermissions(ctx context.Context, req *pb.GetUserPermissionsRequest) (*pb.GetUserPermissionsResponse, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT rp.permission FROM role_permissions rp
		 JOIN user_roles ur ON ur.role_id = rp.role_id
		 WHERE ur.user_id = ? AND ur.tenant_id = ?`,
		req.UserId, req.TenantId,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var permissions []string
	for rows.Next() {
		var perm string
		if err := rows.Scan(&perm); err != nil {
			return nil, err
		}
		permissions = append(permissions, perm)
	}

	return &pb.GetUserPermissionsResponse{Permissions: permissions}, nil
}

// ValidateTenantMembership 驗證租戶成員
func (s *IAMServiceServer) ValidateTenantMembership(ctx context.Context, req *pb.ValidateMembershipRequest) (*pb.ValidateMembershipResponse, error) {
	var isMember bool
	var role string

	err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_tenants WHERE user_id = ? AND tenant_id = ?),
		        COALESCE((SELECT role FROM user_tenants WHERE user_id = ? AND tenant_id = ?), '')`,
		req.UserId, req.TenantId, req.UserId, req.TenantId,
	).Scan(&isMember, &role)

	if err != nil {
		return nil, err
	}

	return &pb.ValidateMembershipResponse{
		IsMember: isMember,
		Role:     role,
	}, nil
}

// GetUser 按 ID 查詢用戶
func (s *IAMServiceServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.User, error) {
	var user pb.User

	err := s.db.QueryRowContext(ctx,
		`SELECT id, email, name, tenant_id FROM users WHERE id = ?`,
		req.UserId,
	).Scan(&user.Id, &user.Email, &user.Name, &user.TenantId)

	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// 查詢用戶角色
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = ?`,
		req.UserId,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var role string
		if err := rows.Scan(&role); err != nil {
			return nil, err
		}
		user.Roles = append(user.Roles, role)
	}

	return &user, nil
}

// GetTenantBySlug 按 slug 查詢租戶
func (s *IAMServiceServer) GetTenantBySlug(ctx context.Context, req *pb.GetTenantBySlugRequest) (*pb.Tenant, error) {
	var tenant pb.Tenant

	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, slug, status FROM tenants WHERE slug = ?`,
		req.Slug,
	).Scan(&tenant.Id, &tenant.Name, &tenant.Slug, &tenant.Status)

	if err != nil {
		return nil, fmt.Errorf("tenant not found")
	}

	return &tenant, nil
}
```

---

## 實現檢查清單

在 IAM server 實現完成前，請確認以下所有項目：

### P0.1 - RS256 JWT + JWKS

- [ ] RSA 金鑰對已生成並安全儲存
- [ ] JWT 簽名演算法已更改為 RS256
- [ ] `/.well-known/jwks.json` 端點已實現
- [ ] JWT payload 包含所有必需欄位（sub, tenant_id, roles, email, iss, exp, iat）
- [ ] JWKS 響應包含 `Cache-Control: public, max-age=3600` 頭
- [ ] 支援多個活躍金鑰（`kid` 欄位）
- [ ] 可以驗證：`curl https://iam-server/.well-known/jwks.json | jq .`
- [ ] 可以驗證：用公鑰驗證 RS256 簽名的 token 成功

### P0.2 - OAuth2 Client Credentials

- [ ] `oauth2_clients` 資料表已建立
- [ ] `POST /oauth2/token` 端點已實現
- [ ] 支援 `grant_type=client_credentials`
- [ ] Client secret 以 bcrypt 儲存，不存明文
- [ ] 支援 scope 驗證
- [ ] Token 過期時間可配置
- [ ] 可以驗證：
  ```bash
  # 交換 token
  curl -X POST https://iam-server/oauth2/token \
    -d 'grant_type=client_credentials&client_id=svc-test&client_secret=cs_live_xxx&scope=read write' \
    | jq .
  ```

### P0.3 - IAM Service API

- [ ] IAMService gRPC 或 REST 已實現
- [ ] IntrospectToken 方法已實現
- [ ] CheckPermission 方法已實現
- [ ] GetUserPermissions 方法已實現
- [ ] GetUser 方法已實現
- [ ] ValidateTenantMembership 方法已實現
- [ ] GetTenantBySlug 方法已實現
- [ ] OAuth2 Bearer token 認證已實現
- [ ] 速率限制已實現（按 client ID）
- [ ] 可以驗證：
  ```bash
  # gRPC
  grpcurl -plaintext \
    -H "authorization: Bearer $ACCESS_TOKEN" \
    -d '{"token":"..."}' \
    iam-server:50051 iam.v1.IAMService/IntrospectToken

  # REST
  curl -X POST https://iam-server/api/v1/introspect \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -d '{"token":"..."}' | jq .
  ```

### 整合測試

- [ ] iam-go SDK 能成功驗證 P0.1 的 JWT
- [ ] iam-go SDK 能成功透過 P0.2 的 OAuth2 端點交換 token
- [ ] iam-go SDK 能成功查詢 P0.3 的權限信息
- [ ] 所有端點都支援 HTTPS
- [ ] 所有端點都有適當的錯誤處理和日誌記錄

---

## 參考資源

- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [JWKS RFC 7517](https://tools.ietf.org/html/rfc7517)
- [RS256 演算法](https://tools.ietf.org/html/rfc7518#section-3.3)
- [iam-go SDK 文檔](../README.md)

---

**有任何問題或建議，請提出 GitHub Issue：**
https://github.com/chimerakang/iam-go/issues
