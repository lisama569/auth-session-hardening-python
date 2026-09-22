# 登录会话、多因素验证与访问控制强化（本地可复现）

在现有 FastAPI 骨架之上，补齐一套**不依赖任何真实外部服务**的登录会话强化能力：

- 短期访问凭据（access token）+ 可轮换、一次性的刷新凭据（refresh token）
- TOTP 二次验证 + 按「账号 × 来源」维度的失败计数、限流与锁定
- 角色/权限范围（scope）的统一授权判定，所有入口结论一致
- 并发、异常与配置变更下状态一致、失败原因可区分、判定可解释（结构化日志）

## 目录结构

```
auth/
  errors.py         # 稳定、可区分的错误码（ErrorCode）
  clock.py          # 可注入时钟（FixedClock/SystemClock），时间逻辑全部可测
  tokens.py         # HMAC-SHA256 自签名凭据 + KeyRing（支持即时密钥轮换）
  store.py          # 线程安全内存存储 + 刷新凭据原子 claim/轮换
  mfa.py            # RFC 6238 TOTP + 失败计数/限流窗口/锁定窗口
  authz.py          # 统一授权判定（Authorizer.decide 是唯一判定入口）
  sessions.py       # 会话生命周期编排（登录/刷新/登出/密钥轮换）
  app.py            # FastAPI 装配（所有 HTTP 入口共享同一个 service）
main.py             # uvicorn 入口
tests/              # 单测/并发测试/HTTP 端到端测试（pytest，无外部依赖）
conftest.py         # 测试引导：开启结构化判定日志
```

## 本地运行

```bash
uv sync
uv run uvicorn main:app --reload          # http://127.0.0.1:8000/docs
uv run pytest -q                          # 全部测试（41 个）
uv run pytest -s                          # 同时打印关键输入与判定依据日志
uv run python scripts/local_demo.py       # 一条脚本走完整条安全链路
```

预置演示账号（仅本地演示，非真实 IdP）：

| 用户 | 密码 | 持久化 scopes |
|------|------|---------------|
| alice | `password-123` | `docs:read`, `profile:read` |
| bob   | `password-123` | `docs:read`, `docs:write`, `profile:read` |

资源：`docs`（需 `docs:read`）、`docs-admin`（需 `docs:write`）、`profile`（需 `profile:read`）。
TOTP 密钥在进程启动时随机生成；脚本 `scripts/local_demo.py` 会直接使用同一进程内的密钥生成口令。

## HTTP 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/auth/login/start` | 校验密码，返回 MFA challenge |
| POST | `/auth/login/complete` | 校验 TOTP，签发 access + refresh |
| POST | `/auth/refresh` | 刷新凭据轮换（一次性、并发安全） |
| POST | `/auth/logout` | 登出（吊销会话与整个 refresh 家族） |
| GET  | `/resources/{name}` | 受保护资源（统一授权判定） |
| POST | `/admin/rotate-keys` | 轮换凭据签名密钥（旧凭据立即失效） |

详见 [`docs/security.md`](docs/security.md)。

## 可区分的失败结果

| 场景 | 错误码 | HTTP |
|------|--------|------|
| 密码错误/用户不存在（统一响应，防枚举） | `invalid_credentials` | 400 |
| MFA challenge 不存在 / 已过期 | `challenge_not_found` / `challenge_expired` | 400 |
| TOTP 错误 / 仅时钟偏差 | `totp_invalid` / `totp_clock_skew` | 400 |
| 触发限流（口令正确也不放行） | `mfa_rate_limited` | 429 |
| 触发锁定（锁定期内口令正确也不放行） | `mfa_locked` | 409 |
| access 过期 / refresh 过期 | `*_token_expired` | 401 |
| access 因版本陈旧/登出/重用被吊销 | `access_token_revoked` | 409 |
| refresh 并发重复提交 | `refresh_token_concurrent` | 409 |
| refresh 轮换后再次使用（重用） | `refresh_token_reuse` | 409 |
| refresh 家族被吊销 | `refresh_token_revoked` | 409 |
| 签名密钥已轮换（旧 kid） | `key_version_stale` | 401 |
| 未认证 | `unauthenticated` | 401 |
| 越权（对外表现同资源不存在） | `forbidden`（body 内可见） | 404 |
| 资源不存在 | `not_found` | 404 |

## 测试覆盖

- `tests/test_concurrent_refresh.py`：确定性并发（无 sleep，基于线程钩子栅栏），N 个并发同一 refresh 恰好 1 个成功，其余全部 `refresh_token_concurrent`；提交后的重放为 `refresh_token_reuse`
- `tests/test_sessions.py`：轮换后旧凭据失效、过期凭据、登出、密钥轮换、重用吊销家族与会话
- `tests/test_mfa.py`：失败累计、限流阈值、**锁定窗口边界**（恰在 `locked_until` 才放行）、成功复位、按用户/来源隔离、时钟偏差可区分
- `tests/test_authz.py`：越权与资源不存在对外同为 404、**服务端持久化权限优先于凭据携带权限**、权限变更立即影响已签发凭据
- `tests/test_http_api.py`：跨入口授权一致性与全部错误码的 HTTP 形态
- `tests/test_store.py` / `tests/test_tokens.py`：原子 claim/轮换、签名/篡改/过期/密钥轮换
