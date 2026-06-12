# iam-go Quick Start Guide

歡迎使用 iam-go SDK！本指南將帶您快速上手。

## 📦 安裝

```bash
go get github.com/chimerakang/iam-go
```

## 🚀 5 分鐘快速開始

### 1. 一行式建立 IAM 客戶端（Valhalla）

`valhalla.New()` 自動初始化 JWKS verifier（RS256 + 30s leeway）、快取 Authorizer、
User / Tenant / Session / Auth 服務並組好 `*iam.Client` — 不需手動注入：

```go
package main

import (
    "log"
    "github.com/chimerakang/iam-go/valhalla"
)

func main() {
    client, err := valhalla.New("iam.example.com:50051")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close() // 同時關閉 gRPC 連線
}
```

需要 M2M 認證或調整快取時，加上選項即可：

```go
client, err := valhalla.New("iam.example.com:50051",
    valhalla.WithOAuth2(os.Getenv("IAM_CLIENT_ID"), os.Getenv("IAM_CLIENT_SECRET")),
    valhalla.WithCacheTTL(time.Minute),                  // 權限快取 TTL（預設 5 分鐘，0 停用）
    valhalla.WithClientID("my_app"),                     // Login 自動注入的 client_id
    valhalla.WithJWKSURL("https://auth.example.com/.well-known/jwks.json"), // 覆寫預設
)
```

> **非 Valhalla 後端？** 使用 `iam.NewClient(cfg, iam.With*()...)` 手動注入各服務實現
> （見下方〈常見配置〉），SDK 本身與後端無關。

### 2. 驗證 JWT Token

```go
import "context"

ctx := context.Background()

// 使用 JWKS 端點本地驗證 JWT
claims, err := client.Verifier().Verify(ctx, tokenString)
if err != nil {
    log.Fatal("Token verification failed:", err)
}

log.Println("User ID:", claims.Subject)
log.Println("Tenant ID:", claims.TenantID)
log.Println("Roles:", claims.Roles)
```

### 3. 檢查權限

```go
// 檢查單個權限
allowed, err := client.Authz().Check(ctx, "users:read")
if !allowed {
    log.Println("Permission denied")
    return
}

// 獲取用戶的所有權限
permissions, err := client.Authz().GetPermissions(ctx)
```

### 4. OAuth2 服務間認證（M2M）

`valhalla.New(..., valhalla.WithOAuth2(id, secret))` 已自動配置 exchanger
（token URL 預設 `http://<endpoint>/api/v1/oauth/token`）：

```go
// 取得已快取的 M2M token（到期前自動刷新，singleflight 防止驚群）
token, err := client.OAuth2().GetCachedToken(ctx)
if err != nil {
    log.Println("Failed to get OAuth2 token:", err)
}
// token 是 Bearer access token，可直接附加到請求標頭
```

自訂 token URL 時改用獨立建構函數：

```go
ex := valhalla.NewOAuth2Exchanger("client-id", "client-secret",
    "https://auth.example.com/oauth/token",
    oauth2.WithRefreshBuffer(2*time.Minute))

client, _ := valhalla.New("iam.example.com:50051", valhalla.WithOAuth2Exchanger(ex))
```

## 🔌 與 Kratos 整合

### HTTP 服務

```go
import (
    "github.com/chimerakang/iam-go/middleware/kratosmw"
    "github.com/go-kratos/kratos/v2/transport/http"
)

httpSrv := http.NewServer(
    http.Address(":8080"),
    http.Middleware(
        // JWT 驗證
        kratosmw.Auth(client),
        // 租戶注入
        kratosmw.Tenant(client),
        // 權限檢查
        kratosmw.Require(client, "users:read"),
    ),
)
```

### gRPC 服務

```go
import (
    "github.com/chimerakang/iam-go/middleware/grpcmw"
    kgrpc "github.com/go-kratos/kratos/v2/transport/grpc"
)

grpcSrv := kgrpc.NewServer(
    kgrpc.Address(":50051"),
    kgrpc.Middleware(
        grpcmw.UnaryServerAuthInterceptor(client),
        grpcmw.UnaryServerTenantInterceptor(client),
    ),
)
```

## 🧪 測試（無需 IAM Server）

使用 `fake` 包進行單元測試：

```go
import "github.com/chimerakang/iam-go/fake"

func TestMyHandler(t *testing.T) {
    // 建立假 IAM 客戶端
    client := fake.NewClient(
        fake.WithUser("user-123", "tenant-001", "user@example.com", []string{"admin"}),
        fake.WithPermissions("user-123", []string{"users:read", "users:write"}),
    )

    // 設定上下文
    ctx := iam.WithUserID(context.Background(), "user-123")
    ctx = iam.WithTenantID(ctx, "tenant-001")

    // 使用客戶端進行測試
    ok, _ := client.Authz().Check(ctx, "users:read")
    if !ok {
        t.Fatal("Permission should be allowed")
    }
}
```

## 🏗️ 使用整合測試

### 1. 啟動測試環境

```bash
# 使用 Docker Compose 啟動 IAM Server、PostgreSQL、Redis
docker-compose -f docker-compose.example.yml up -d

# 等待服務就緒
sleep 10
```

### 2. 運行整合測試

```bash
# 設定環境變數
export IAM_ENDPOINT=http://localhost:8080
export JWKS_URL=http://localhost:8080/.well-known/jwks.json

# 運行帶 integration tag 的測試
go test -tags=integration ./...
```

### 3. 停止測試環境

```bash
docker-compose -f docker-compose.example.yml down
```

## 📋 API 概述

### TokenVerifier

```go
// 驗證 JWT 並返回 claims
claims, err := client.Verifier().Verify(ctx, token)

type Claims struct {
    Subject   string    // user ID
    TenantID  string    // tenant ID
    Roles     []string  // user roles
    Email     string    // user email
    IssuedAt  time.Time
    ExpiresAt time.Time
}
```

### Authorizer

```go
// 檢查單個權限
ok, err := client.Authz().Check(ctx, "users:read")

// 檢查任何一個權限
ok, err := client.Authz().CheckAny(ctx, "users:read", "admin:*")

// 獲取所有權限
permissions, err := client.Authz().GetPermissions(ctx)

// 檢查資源級權限
ok, err := client.Authz().CheckResource(ctx, "user", "user-123", "write")
```

### UserService

```go
// 獲取當前用戶
user, err := client.Users().GetCurrent(ctx)

// 按 ID 獲取用戶
user, err := client.Users().Get(ctx, userID)

// 列出用戶
users, total, err := client.Users().List(ctx, &iam.ListOptions{
    Limit:  10,
    Offset: 0,
})

// 獲取用戶角色
roles, err := client.Users().GetRoles(ctx, userID)
```

### TenantService

```go
// 按 ID 或 Slug 解析租戶
tenant, err := client.Tenants().Resolve(ctx, "tenant-001")

// 驗證租戶成員資格
ok, err := client.Tenants().ValidateMembership(ctx, userID, tenantID)
```

### OAuth2TokenExchanger

```go
// 使用 Client Credentials 交換 access token
token, err := client.OAuth2().ExchangeToken(ctx, []string{"read", "write"})
// token.AccessToken — Bearer token
// token.ExpiresAt — 過期時間

// 取得快取的 token（自動刷新）
accessToken, err := client.OAuth2().GetCachedToken(ctx)
// accessToken 為 string，可直接使用
```

### SessionService

```go
// 列出用戶 Session
sessions, total, err := client.Sessions().List(ctx, userID, tenantID)

// 撤銷 Session
err := client.Sessions().Revoke(ctx, sessionID)

// 撤銷其他所有 Session
err := client.Sessions().RevokeAllOthers(ctx, currentSessionID)
```

## 🔐 上下文管理

```go
import iam "github.com/chimerakang/iam-go"

// 在上下文中設定用戶信息
ctx = iam.WithUserID(ctx, "user-123")
ctx = iam.WithTenantID(ctx, "tenant-001")
ctx = iam.WithRequestID(ctx, "req-123")

// 從上下文提取
userID, _ := iam.UserIDFromContext(ctx)
tenantID, _ := iam.TenantIDFromContext(ctx)
requestID, _ := iam.RequestIDFromContext(ctx)
```

## 🛠️ 常見配置

### 配置 JWKS 刷新間隔 / Leeway

使用 `valhalla.New` 時直接傳入 jwks 選項：

```go
import "github.com/chimerakang/iam-go/jwks"

client, _ := valhalla.New("iam.example.com:50051",
    valhalla.WithJWKSOptions(
        jwks.WithRefreshInterval(5*time.Minute),
        jwks.WithLeeway(30*time.Second), // 預設即 30s
    ),
)
```

手動組裝時：

```go
verifier := jwks.NewVerifier(
    jwksURL,
    jwks.WithRefreshInterval(5*time.Minute),
)

client, _ := iam.NewClient(
    cfg,
    iam.WithTokenVerifier(verifier),
)
```

### 配置權限快取 TTL

使用 `valhalla.New` 時：

```go
client, _ := valhalla.New("iam.example.com:50051",
    valhalla.WithCacheTTL(time.Minute), // 0 = 停用快取，每次都打 AuthzService
)
```

手動組裝時：

```go
import "github.com/chimerakang/iam-go/authz"

authorizer := authz.New(
    backend,
    authz.WithCacheTTL(5*time.Minute),
)

client, _ := iam.NewClient(
    cfg,
    iam.WithAuthorizer(authorizer),
)
```

### 自訂中間件

```go
// 排除某些操作的驗證
kratosmw.Auth(
    client,
    kratosmw.WithExcludedOperations("/health", "/login"),
)

// 檢查多個權限之一
kratosmw.RequireAny(client, "users:read", "users:admin")
```

## 📚 完整示例

- **標準庫 net/http**: `examples/std-http-service/`
- **Gin**: `examples/gin-service/`
- **Kratos (HTTP + gRPC)**: `examples/kratos-service/`
- **純 gRPC**: `examples/grpc-service/`

## 🐳 Docker Compose 測試環境

```bash
# 查看 docker-compose 配置
cat docker-compose.example.yml

# 自訂您的環境，然後啟動
docker-compose -f docker-compose.example.yml up -d

# 檢查日誌
docker-compose -f docker-compose.example.yml logs -f iam

# 停止
docker-compose -f docker-compose.example.yml down
```

## ❓ 常見問題

### Q: 我可以不使用 Kratos 嗎？

**A:** 可以！官方提供 `middleware/httpmw`（標準庫 net/http）與 `middleware/ginmw`（Gin），
與 kratosmw 相同的 Auth / Tenant / Require / RequireAny 堆疊：

```go
// net/http
handler := httpmw.Chain(httpmw.Auth(client), httpmw.Tenant(client))(mux)

// Gin
r.Use(ginmw.Auth(client), ginmw.Tenant(client))
```

### Q: 如何在多個 goroutine 中安全使用客戶端？

**A:** `iam.Client` 是線程安全的。可以安全地在多個 goroutine 中共享：

```go
var client *iam.Client

func init() {
    client, _ = iam.NewClient(cfg)
}

// 可以在任何 goroutine 中使用
go func() {
    client.Authz().Check(ctx, "permission")
}()
```

### Q: 支援哪些 JWT 簽名算法？

**A:** iam-go 優先支援 RS256（RSA）。JWKS 驗證器會自動選擇正確的公鑰。如果 IAM Server 使用其他算法，請確保在 JWKS 響應中指定。

### Q: 如何自訂錯誤處理？

**A:** 所有服務都返回標準 Go 錯誤。您可以檢查錯誤類型：

```go
_, err := client.Users().Get(ctx, "id")
if err != nil {
    if strings.Contains(err.Error(), "not found") {
        // 處理未找到
    }
}
```

## 📖 更多資源

- [完整 API 文檔](../README.md)
- [權限檢查：本地 vs 遠端選擇指南](PERMISSION_CHECKING.md)
- [IAM Server 規格 (P0)](P0_IAM_SERVER_REQUIREMENTS.md)
- [net/http 服務範例](../examples/std-http-service/main.go)
- [Gin 服務範例](../examples/gin-service/main.go)
- [Kratos 服務範例](../examples/kratos-service/main.go)
- [gRPC 服務範例](../examples/grpc-service/main.go)

## 🆘 獲得幫助

遇到問題？

1. 查看 [GitHub Issues](https://github.com/chimerakang/iam-go/issues)
2. 查看 [完整測試](../auth*_test.go) 了解用法
3. 查看 [整合測試範例](../integration_tests_example.go) 了解完整工作流程

---

**準備好了嗎？** 選擇一個範例開始：

- 📝 [net/http 服務](../examples/std-http-service/main.go) — 最常見的用例
- 🍸 [Gin 服務](../examples/gin-service/main.go) — Gin 框架
- 🔌 [gRPC 服務](../examples/grpc-service/main.go) — 微服務架構
