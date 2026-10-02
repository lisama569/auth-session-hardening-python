# 登录会话、多因素验证与访问控制强化（本地可复现）

在现有 FastAPI 骨架之上，补齐一套**不依赖任何真实外部服务**的登录会话强化能力：

- 短期访问凭据（access token）+ 可轮换、一次性的刷新凭据（refresh token）
- TOTP 二次验证 + 按「账号 × 来源」维度的失败计数、限流与锁定
- 角色/权限范围（scope）的统一授权判定，所有入口结论一致
- **多设备会话管理**：列举有效会话（稳定标识、来源、建立时间、当前会话标记）、
  按标识立即下线单个会话、「退出其他所有设备」
- **敏感操作再认证**：高风险操作必须落在最近一次成功二次验证之后的可配置
  新鲜度窗口内；再认证一次性口令不可重放，窗口边界明确（排他上界）
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
uv run pytest -q                          # 全部测试（62 个）
uv run pytest -s                          # 同时打印关键输入与判定依据日志
uv run python scripts/local_demo.py       # 一条脚本走完整条安全链路（含多设备管理）
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
| GET  | `/auth/sessions` | 列举本人当前有效的登录会话 |
| POST | `/auth/sessions/revoke` | 按稳定标识下线本人的某个会话 |
| POST | `/auth/reauthenticate` | 对当前会话做一次二次验证（刷新敏感操作新鲜度） |
| POST | `/auth/sessions/revoke-others` | 退出其他所有设备（敏感操作，需要新鲜再认证） |
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
| 会话管理：越权 / 会话不存在 / 已下线（对外同形） | `not_found` | 404 |
| 会话不存在（凭举证指的会话从未存在） | `session_not_found` | 400 |
| 会话已被其所有者下线（或并发下线） | `session_revoked`（access）/`refresh_token_revoked`（refresh） | 409 |
| 敏感操作缺少新鲜再认证 | `reauth_required` | 403 |
| 再认证口令重放（同一 TOTP 步号第二次使用） | `reauth_code_reused` | 409 |
| 资源不存在 | `not_found` | 404 |

## 测试覆盖

- `tests/test_concurrent_refresh.py`：确定性并发（无 sleep，基于线程钩子栅栏），N 个并发同一 refresh 恰好 1 个成功，其余全部 `refresh_token_concurrent`；提交后的重放为 `refresh_token_reuse`
- `tests/test_sessions.py`：轮换后旧凭据失效、过期凭据、登出、密钥轮换、重用吊销家族与会话
- `tests/test_mfa.py`：失败累计、限流阈值、**锁定窗口边界**（恰在 `locked_until` 才放行）、成功复位、按用户/来源隔离、时钟偏差可区分
- `tests/test_authz.py`：越权与资源不存在对外同为 404、**服务端持久化权限优先于凭据携带权限**、权限变更立即影响已签发凭据
- `tests/test_device_management.py`（新增 18 个）：会话列举字段与「当前会话」标记、单会话下线（access/refresh 立即失效、未点名会话不受影响）、越权/不存在/已下线对外同形、再认证新鲜度**排他边界**（窗口内、恰在到期点、刚过）、窗口顺延、口令不可重放（含并发）、下线与 in-flight 刷新交错并发、HTTP 端到端形态
- `tests/test_http_api.py`：跨入口授权一致性与全部错误码的 HTTP 形态
- `tests/test_store.py` / `tests/test_tokens.py`：原子 claim/轮换、签名/篡改/过期/密钥轮换

## 多设备会话管理与再认证（新增能力）

- 会话带有稳定标识 `sess_*`、登录来源 `source`、建立时间 `created_at`；
  `GET /auth/sessions` 只返回**当前仍有效**的会话，并把本次请求所用会话
  标记为 `current: true`（从不同设备看，标记随视角切换，标识保持稳定）。
- `POST /auth/sessions/revoke` 按标识下线**本人的**会话：会话立即吊销、
  令牌版本 +1、该会话所有 refresh 家族记录置为 revoked——旧 access 报
  `access_token_revoked`、refresh 报 `refresh_token_revoked`，无需等待过期。
- `POST /auth/sessions/revoke-others` 原子终止本人除当前会话外的全部会话；
  当前会话的 access/refresh 完全不受影响（版本号不变）。
- 会话归属判定与既有授权口径一致：对**他人的**会话标识和**不存在**的标识，
  对外一律是 `404 not_found`（含响应体与状态码完全同形），真实归属
  （`foreign_session` / `session_missing` / `already_revoked`）只进服务端日志。
- 敏感操作的再认证新鲜度窗口默认 300 秒（构造参数 `reauth_window` 可调）：
  最后一次成功再认证时间记在**会话**上（`last_reauth_at`），窗口为
  `[t0, t0 + window)`——恰在 `t0 + window` 即视为过期，结果稳定可预期。
- 用于再认证的 TOTP 口令按「用户 × 绝对步号」**原子消费**：同一口令不能
  完成第二次敏感操作（`reauth_code_reused`，409），跨会话也不行；
  窗口内再次验证成功按「自最新一次成功起重新开窗」顺延（sliding）。
- 登录时完成的 MFA 不等于敏感操作再认证；再认证走独立入口，其失败仍计入
  既有 `(user, source)` 限流/锁定，错误原因（错误码/时钟偏差/限流/锁定/
  窗口过期/口令重放）全部可区分。

### 对既有行为的兼容范围

- 既有 `/auth/login/*`、`/auth/refresh`、`/auth/logout`、`/resources/*`、
  `/admin/rotate-keys` 的路径、请求/响应结构与错误码**保持不变**；
  新增能力全部挂在新路径上。
- `SessionRecord` 仅新增带默认值的字段（`source`、`last_reauth_at`），
  `create_session(user_id, source="web")` 对旧调用方向后兼容。
- 唯一的行为加固：refresh 在「已 claim、未提交」窗口内被并发吊销时，
  原先会冒出未分类异常，现在明确返回 `session_revoked` /
  `refresh_token_revoked`（可区分、可预期），正常刷新路径无任何变化。
