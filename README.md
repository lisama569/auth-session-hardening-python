# 登录会话、多因素验证与访问控制强化（本地可复现）

在现有 FastAPI 骨架之上，补齐一套**不依赖任何真实外部服务**的登录会话强化能力：

- 短期访问凭据（access token）+ 可轮换、一次性的刷新凭据（refresh token）
- TOTP 二次验证 + 按「账号 × 来源」维度的失败计数、限流与锁定
- 角色/权限范围（scope）的统一授权判定，所有入口结论一致
- **多设备会话管理**：列举自己的有效会话、点名下线单个会话、一步退出其他所有设备
- **敏感操作再认证**：高风险操作要求最近一次二次验证落在可配置新鲜度窗口内，一次性口令不可重放
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
uv run pytest -q                          # 全部测试（75 个）
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
| GET  | `/auth/sessions` | 列举自己当前有效的登录会话 |
| POST | `/auth/sessions/reauthenticate` | 当前会话二次验证（建立/顺延新鲜度） |
| POST | `/auth/sessions/terminate` | 点名下线自己的某一个会话 |
| POST | `/auth/sessions/logout-others` | 退出其他所有设备（需新鲜二次验证） |
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
| 点名的会话不存在 / 属于他人 / 已吊销（三者同形） | `session_not_found` | 404 |
| 敏感操作缺少新鲜二次验证 | `reauth_required` | 403 |
| 一次性口令被重复使用 | `totp_replay` | 409 |
| 越权（对外表现同资源不存在） | `forbidden`（body 内可见） | 404 |
| 资源不存在 | `not_found` | 404 |

## 多设备会话管理

- **列举**：`GET /auth/sessions`（携带当前会话 access token）返回该用户全部
  未吊销会话的稳定标识 `session_id`、登入来源 `source`、建立时间
  `created_at`，并用 `current: true` 标出**当前这次请求**所用的会话。
- **点名下线**：`POST /auth/sessions/terminate`，body 为
  `{"session_id": ...}`。下线是**同一把锁内的原子三连**：会话置吊销、
  令牌版本 +1（旧 access 立即报 `access_token_revoked`）、该会话家族内
  全部 refresh 置吊销（再刷新报 `refresh_token_revoked`）。允许下线当前
  会话自己；同账号未点名的会话完全不受影响。
- **退出其他所有设备**：`POST /auth/sessions/logout-others` 吊销调用者除
  当前会话外的全部会话，当前 access/refresh 始终保持可用，操作幂等。
- **归属与存在性隐藏**：所有会话入口只认经过认证的主体；对「不属于
  自己的 id」「根本不存在的 id」「已吊销的 id」统一返回同一个
  `session_not_found`（404，body 完全一致），判定依据（foreign_owner /
  missing / revoked）只写入服务端日志，不暴露会话是否存在。

## 敏感操作再认证（step-up）

「退出其他所有设备」属于高风险操作，**不能只靠未过期的 access token**：

- 新鲜度 = 该会话「最近一次成功二次验证」时刻 + 窗口
  （`reauth_freshness`，默认 300 秒，构造器可配）。
- 登录时完成的二次验证就是第一个新鲜度锚点；窗口内调用
  `POST /auth/sessions/reauthenticate` 并通过 TOTP 后，窗口从**本次验证
  时刻**重新起算（顺延规则固定为「滑窗」）。
- 边界确定可预期：`now == fresh_until` 仍然放行（**包含边界**），
  `now > fresh_until`（哪怕只多一微秒）拒绝为 `reauth_required`（403），
  调用方据此知道需要重新做一次二次验证——它与 `totp_invalid`（400）、
  `mfa_rate_limited`（429）、`mfa_locked`（409）都不同。
- **一次性口令不可重放（含并发与跨会话）**：已消费的 TOTP 绝对时间步
  记录在**按用户**的台账里（登录那一步也算），会话上保留镜像。同一口令
  无论在同一会话再交、在该用户的另一个登录会话里交，还是同时被多路请求
  提交，都只有一路成功，其余直接报 `totp_replay`（409）——即使它在密码学
  上仍有效、即使窗口开着；被拒重放**不顺延窗口**，与 `totp_invalid`（口令
  错误）、限流/锁定均为不同错误码。
- 再认证 / 登录的「查重 + 消费 + 顺延锚点」是存储层锁内的**单个原子动作**，
  并发下同一口令只有一个赢家、窗口只顺延一次、台账计数不重不漏，不依赖线程
  调度或延迟；下线与刷新交错时，刷新若在提交阶段发现家族已被
  终止，得到可区分的 `refresh_token_revoked`。

## 测试覆盖

- `tests/test_concurrent_refresh.py`：确定性并发（无 sleep，基于线程钩子栅栏），N 个并发同一 refresh 恰好 1 个成功，其余全部 `refresh_token_concurrent`；提交后的重放为 `refresh_token_reuse`
- `tests/test_sessions.py`：轮换后旧凭据失效、过期凭据、登出、密钥轮换、重用吊销家族与会话
- `tests/test_mfa.py`：失败累计、限流阈值、**锁定窗口边界**（恰在 `locked_until` 才放行）、成功复位、按用户/来源隔离、时钟偏差可区分
- `tests/test_authz.py`：越权与资源不存在对外同为 404、**服务端持久化权限优先于凭据携带权限**、权限变更立即影响已签发凭据
- `tests/test_http_api.py`：跨入口授权一致性与全部错误码的 HTTP 形态
- `tests/test_device_sessions.py`：会话列举（稳定 id / 来源 / 时间 / 当前标记）、单个与批量下线后 access+refresh 立即作废、越权与不存在同形、未点名会话不受影响
- `tests/test_reauth.py`：新鲜度窗口**包含/超出边界**、再认证顺延、失败原因可区分（错误口令/限流）、**一次性口令不可重放**、登录口令已消费
- `tests/test_concurrent_sessions.py`：同一口令并发再认证单赢家且窗口只顺延一次、下线与刷新在 claim 窗口内交错、refresh 已提交后下线株连后继凭据、并发批量下线计数稳定
- `tests/test_totp_replay.py`：**确定性**（线程栅栏，非自然竞争）复现「同时提交同一口令」（同会话 2/8 路、跨会话）与「跨会话重复使用同一口令」（再认证 / 二次登录），断言恰好一个赢家、窗口只顺延一次、重放与口令错误/限流可区分，并回归新鲜度包含边界
- `tests/test_http_sessions.py`：新端点的 HTTP 形态（404 同形、403 引导再认证、409 重放、401 未认证）
- `tests/test_store.py` / `tests/test_tokens.py`：原子 claim/轮换、**一次性口令原子消费原语**（并发单赢家、用户级跨会话台账、跨用户隔离）、签名/篡改/过期/密钥轮换
