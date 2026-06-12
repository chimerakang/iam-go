# 權限檢查：本地 vs 遠端選擇指南

iam-go 提供兩條權限檢查路徑。`valhalla.New()` 預設**本地優先、遠端 fallback**，
多數服務不需要任何額外設定。

## 兩條路徑

### 1. 本地（Claims-based）— `authz.ClaimsChecker`

IAM Server（Valhalla P21.2+）簽發 JWT 時內嵌 `permissions` claim：

```json
{
  "sub": "user-123",
  "tenant_id": "tenant-001",
  "permissions": ["users:read", "orders:*"],
  "exp": 1718200000
}
```

`Require()` / `RequireAny()` middleware 透過 `client.Authz().Check()` 直接比對
token 內的 permissions —— **零網路呼叫、零延遲**。

支援 wildcard（segment-wise，`:` 分隔）：

| Granted（token 內） | Required（檢查目標） | 結果 |
|---------------------|----------------------|------|
| `users:read` | `users:read` | ✅ |
| `users:*` | `users:read` | ✅ |
| `users:*` | `users:read:all` | ✅（尾端 `*` 涵蓋其餘 segment）|
| `users:*:read` | `users:profile:read` | ✅（中段 `*` 比對單一 segment）|
| `*` | 任何權限 | ✅ |
| `users:read` | `users:write` | ❌ |

### 2. 遠端（gRPC）— `authz.Authorizer`（含本地快取）

每次檢查呼叫 Valhalla AuthzService（結果快取 `WithCacheTTL`，預設 5 分鐘）。

## Fallback 規則（預設行為）

`ClaimsChecker` 在以下情況自動 fallback 到遠端：

1. **`permissions` claim 不存在**（`Claims.Permissions == nil`）—— 舊版 token 或
   IAM Server 尚未升級
2. **Token 標記降級**（`permissions_degraded: true` claim）—— issuer 表示權限
   清單不完整（例如權限太多塞不進 token）

注意：**空陣列 `[]` 不會 fallback** —— 它代表「使用者沒有任何權限」，直接拒絕。

## 一致性 Trade-off

| | 本地（claims）| 遠端（gRPC + 快取）|
|---|---|---|
| 延遲 | ~0 | 網路 RTT（快取命中時 ~0）|
| IAM Server 負載 | 無 | 每 TTL 一次/權限 |
| 權限撤銷生效時間 | **token 到期/刷新** | 快取 TTL（或 webhook 立即）|
| Token 大小 | 變大（權限多時注意）| 不變 |

**核心原則：本地檢查的新鮮度 = token 的新鮮度。**

- 使用本地檢查時，**access token TTL 應保持在分鐘級**（建議 5-15 分鐘），
  撤銷權限最遲在 token 到期時生效
- 撤銷必須立即生效的場景（如停權、安全事件）：
  - 用 `valhalla.WithRemoteAuthz()` 強制全部走遠端，或
  - 對關鍵權限直接呼叫遠端：搭配短 `WithCacheTTL` + webhook 失效

## Webhook 快取失效（預留）

`authz.Authorizer` 提供失效 hook，供 IAM Server 事件系統（Valhalla #165）
驅動 —— 收到權限變更事件時主動清快取，撤銷立即生效：

```go
// webhook handler 內
func onPermissionChanged(evt PermissionChangedEvent) {
    cachedAuthorizer.Invalidate(evt.UserID, evt.TenantID) // 單一租戶
    // 或 cachedAuthorizer.InvalidateUser(evt.UserID)      // 跨租戶
}
```

## 配置範例

```go
// 預設：本地優先 + 遠端 fallback（建議）
client, _ := valhalla.New("iam.example.com:50051")

// 全部走遠端（撤銷敏感場景）
client, _ := valhalla.New("iam.example.com:50051",
    valhalla.WithRemoteAuthz(),
    valhalla.WithCacheTTL(30*time.Second), // 短 TTL 縮小一致性窗口
)

// 手動組裝（非 Valhalla 後端）
checker := authz.NewClaimsChecker(
    authz.WithFallback(myRemoteAuthorizer),       // 可省略 — 無 fallback 時直接報錯
    authz.WithDegradedFlag("perms_incomplete"),   // 自訂降級 claim 名稱
)
client, _ := iam.NewClient(cfg, iam.WithAuthorizer(checker))
```
