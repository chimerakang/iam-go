# iam-go — Master Tasks

> **iam-go** — Backend-agnostic Go SDK for Identity and Access Management
> **Last updated:** 2026-02-26
> **Auto-generated** from GitHub Issues
> Run `/task-sync` to regenerate

## Status Legend

| Status | Meaning |
|--------|---------|
| ✅ | 已完成 |
| 🔄 | 開發中 |
| 🧪 | 測試中 |
| 📋 | 規劃中 |
| ⏸️ | 暫停 |
| 🚫 | 已取消 |

---

## Phase Overview

| Phase | Description | Progress | Status |
|-------|-------------|----------|--------|
| **P0: IAM Server Requirements** | Standard capabilities for any IAM server — RS256 JWT, API Keys, External API | 0% (0/3) | 📋 |
| **P1: Core SDK** | JWKS client, gRPC connection, authorization, secrets | 20% (1/5) | 🔄 |
| **P2: Middleware** | Kratos & gRPC middleware, auth/tenant/permission | 0% (0/2) | 🔄 |
| **P3: Extended Features** | Tenant, user, session clients | 0% (0/3) | 📋 |
| **P4: Testing & Quality** | Fake client, integration tests, CI/CD | 0% (0/3) | 📋 |
| **P5: Audit & Observability** | Audit logging, Prometheus metrics | 0% (0/2) | 📋 |

---


## P0: IAM Server Requirements

| # | Task | Issue | Status |
|---|------|-------|--------|
| P0.1 | **P0.1: IAM Server Requirements — RS256 JWT + JWKS Endpoint** | [#1](https://github.com/chimerakang/iam-go/issues/1) | 📋 |
| P0.2 | **P0.2: IAM Server Requirements — API Key/Secret Management Service** | [#2](https://github.com/chimerakang/iam-go/issues/2) | 📋 |
| P0.3 | **P0.3: IAM Server Requirements — IAM Service API for External Consumers** | [#3](https://github.com/chimerakang/iam-go/issues/3) | 📋 |

## P1: Core SDK

| # | Task | Issue | Status |
|---|------|-------|--------|
| P1.0 | **P1.0 Core Interfaces & Domain Types** | [#19](https://github.com/chimerakang/iam-go/issues/19) | ✅ |
| P1.1 | **P1.1 JWKS Client — Public Key Fetching and JWT Verification** | [#4](https://github.com/chimerakang/iam-go/issues/4) | 🔄 |
| P1.2 | **P1.2 Client Core — gRPC Connection and Config** | [#5](https://github.com/chimerakang/iam-go/issues/5) | 🔄 |
| P1.3 | **P1.3 Authorizer — Permission Checking with Cache** | [#6](https://github.com/chimerakang/iam-go/issues/6) | 🔄 |
| P1.4 | **P1.4 SecretService — API Key Management** | [#7](https://github.com/chimerakang/iam-go/issues/7) | 🔄 |

## P2: Middleware

| # | Task | Issue | Status |
|---|------|-------|--------|
| P2.1 | **P2.1 Kratos Middleware — Auth, Tenant, Permission (Primary)** | [#9](https://github.com/chimerakang/iam-go/issues/9) | 🔄 |
| P2.2 | **P2.2 gRPC Interceptors — Auth, Tenant, Permission** | [#10](https://github.com/chimerakang/iam-go/issues/10) | 🔄 |
| ~~P2.1~~ | ~~P2.1 Gin Middleware — Auth, Tenant, Permission~~ | [#8](https://github.com/chimerakang/iam-go/issues/8) | 🚫 |

> **Note:** #8 (Gin Middleware) was closed — architecture changed to Kratos + Proto-first.

## P3: Extended Features

| # | Task | Issue | Status |
|---|------|-------|--------|
| P3.1 | **P3.1 TenantService — Resolution and Context** | [#11](https://github.com/chimerakang/iam-go/issues/11) | 📋 |
| P3.2 | **P3.2 UserService — User Query** | [#12](https://github.com/chimerakang/iam-go/issues/12) | 📋 |
| P3.3 | **P3.3 SessionService — Session Management** | [#13](https://github.com/chimerakang/iam-go/issues/13) | 📋 |

## P4: Testing & Quality

| # | Task | Issue | Status |
|---|------|-------|--------|
| P4.1 | **P4.1 Fake Client — In-Memory Test Doubles** | [#14](https://github.com/chimerakang/iam-go/issues/14) | 📋 |
| P4.2 | **P4.2 Integration Tests — End-to-End Verification** | [#15](https://github.com/chimerakang/iam-go/issues/15) | 📋 |
| P4.3 | **P4.3 CI/CD — GitHub Actions Pipeline** | [#16](https://github.com/chimerakang/iam-go/issues/16) | 📋 |

## P5: Audit & Observability

| # | Task | Issue | Status |
|---|------|-------|--------|
| P5.1 | **P5.1 Audit Log Integration** | [#17](https://github.com/chimerakang/iam-go/issues/17) | 📋 |
| P5.2 | **P5.2 Prometheus Metrics** | [#18](https://github.com/chimerakang/iam-go/issues/18) | 📋 |

---

## Issue Tracker

| Issue | Title | Phase | Status |
|-------|-------|-------|--------|
| [#19](https://github.com/chimerakang/iam-go/issues/19) | P1.0 Core Interfaces & Domain Types | P1: Core SDK | ✅ |
| [#18](https://github.com/chimerakang/iam-go/issues/18) | P5.2 Prometheus Metrics | P5: Audit & Observability | 📋 |
| [#17](https://github.com/chimerakang/iam-go/issues/17) | P5.1 Audit Log Integration | P5: Audit & Observability | 📋 |
| [#16](https://github.com/chimerakang/iam-go/issues/16) | P4.3 CI/CD — GitHub Actions Pipeline | P4: Testing & Quality | 📋 |
| [#15](https://github.com/chimerakang/iam-go/issues/15) | P4.2 Integration Tests — End-to-End Verification | P4: Testing & Quality | 📋 |
| [#14](https://github.com/chimerakang/iam-go/issues/14) | P4.1 Fake Client — In-Memory Test Doubles | P4: Testing & Quality | 📋 |
| [#13](https://github.com/chimerakang/iam-go/issues/13) | P3.3 SessionService — Session Management | P3: Extended Features | 📋 |
| [#12](https://github.com/chimerakang/iam-go/issues/12) | P3.2 UserService — User Query | P3: Extended Features | 📋 |
| [#11](https://github.com/chimerakang/iam-go/issues/11) | P3.1 TenantService — Resolution and Context | P3: Extended Features | 📋 |
| [#10](https://github.com/chimerakang/iam-go/issues/10) | P2.2 gRPC Interceptors — Auth, Tenant, Permission | P2: Middleware | 🔄 |
| [#9](https://github.com/chimerakang/iam-go/issues/9) | P2.1 Kratos Middleware — Auth, Tenant, Permission (Primary) | P2: Middleware | 🔄 |
| [#8](https://github.com/chimerakang/iam-go/issues/8) | ~~P2.1 Gin Middleware~~ | P2: Middleware | 🚫 |
| [#7](https://github.com/chimerakang/iam-go/issues/7) | P1.4 SecretService — API Key Management | P1: Core SDK | 🔄 |
| [#6](https://github.com/chimerakang/iam-go/issues/6) | P1.3 Authorizer — Permission Checking with Cache | P1: Core SDK | 🔄 |
| [#5](https://github.com/chimerakang/iam-go/issues/5) | P1.2 Client Core — gRPC Connection and Config | P1: Core SDK | 🔄 |
| [#4](https://github.com/chimerakang/iam-go/issues/4) | P1.1 JWKS Client — Public Key Fetching and JWT Verification | P1: Core SDK | 🔄 |
| [#3](https://github.com/chimerakang/iam-go/issues/3) | P0.3: IAM Server Requirements — IAM Service API for External Consumers | P0: IAM Server Requirements | 📋 |
| [#2](https://github.com/chimerakang/iam-go/issues/2) | P0.2: IAM Server Requirements — API Key/Secret Management Service | P0: IAM Server Requirements | 📋 |
| [#1](https://github.com/chimerakang/iam-go/issues/1) | P0.1: IAM Server Requirements — RS256 JWT + JWKS Endpoint | P0: IAM Server Requirements | 📋 |

---

**Last sync:** 2026-02-26 19:53 UTC
