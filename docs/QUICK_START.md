# iam-go Quick Start Guide

歡迎使用 iam-go SDK！本指南將帶您快速上手。

## 📦 安裝

```bash
go get github.com/chimerakang/iam-go
```

## 🚀 5 分鐘快速開始

### 1. 建立 IAM 客戶端

```go
package main

import (
    "log"
    iam "github.com/chimerakang/iam-go"
)

func main() {
    client, err := iam.NewClient(
        iam.Config{
            Endpoint: "iam-server:9000",
            JWKSUrl:  "https://iam.example.com/.well-known/jwks.json",
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
}
```

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

### 4. 驗證 API Key

```go
// 驗證服務間認證
ok, err := client.Secrets().Verify(ctx, apiKey, apiSecret)
if !ok {
    log.Println("Invalid API credentials")
}
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

### SecretService

```go
// 驗證 API Key/Secret
ok, err := client.Secrets().Verify(ctx, apiKey, apiSecret)

// 列出 Secret
secrets, total, err := client.Secrets().List(ctx, &iam.ListOptions{})

// 建立新 Secret
secret, err := client.Secrets().Create(ctx, userID, tenantID, "desc")

// 輪換 Secret
newSecret, err := client.Secrets().Rotate(ctx, secretID)

// 刪除 Secret
err := client.Secrets().Delete(ctx, secretID)
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

### 配置 JWKS 刷新間隔

```go
import "github.com/chimerakang/iam-go/jwks"

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

- **HTTP Service**: `examples/http-service.go`
- **gRPC Service**: `examples/grpc-service.go`
- **Integration Tests**: `integration_tests_example.go`

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

**A:** 可以！iam-go 是獨立的。您可以在任何 Go 框架（Gin、Echo、標準庫等）中使用它：

```go
func MyHandler(w http.ResponseWriter, r *http.Request) {
    token := r.Header.Get("Authorization")
    claims, _ := client.Verifier().Verify(r.Context(), token)
    // ...
}
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
- [IAM Server 規格 (P0)](P0_IAM_SERVER_REQUIREMENTS.md)
- [整合測試範例](../integration_tests_example.go)
- [HTTP 服務範例](../examples/http-service.go)
- [gRPC 服務範例](../examples/grpc-service.go)

## 🆘 獲得幫助

遇到問題？

1. 查看 [GitHub Issues](https://github.com/chimerakang/iam-go/issues)
2. 查看 [完整測試](../auth*_test.go) 了解用法
3. 查看 [整合測試範例](../integration_tests_example.go) 了解完整工作流程

---

**準備好了嗎？** 選擇一個範例開始：

- 📝 [HTTP 服務](../examples/http-service.go) — 最常見的用例
- 🔌 [gRPC 服務](../examples/grpc-service.go) — 微服務架構
- 🧪 [整合測試](../integration_tests_example.go) — 與真實 IAM Server 測試
