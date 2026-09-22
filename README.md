# 登录会话、多因素验证与访问控制强化（本地可复现）

在原有 FastAPI 骨架之上，补齐一套**不依赖任何外部服务/真实凭据**的认证会话强化能力：

* 短期**访问凭据** + 可轮换**刷新凭据**的完整生命周期；
* 基于时间的一次性口令（TOTP）二次验证与失败防护（限流 / 锁定 / 防重放）；
* 角色与权限范围（scope）的统一授权判定，所有入口结论一致；
* 并发、异常、配置变更下状态一致、失败原因可区分、日志可解释。

仅依赖 Python 标准库实现密码哈希（PBKDF2）、HMAC 签名、TOTP（RFC 6238 子集），
持久化为进程内、加锁的内存存储；时间源可注入，测试可精确推进。

---

## 1. 快速开始

```bash
uv sync                                  # 安装依赖（含 pytest）
uv run pytest -q                         # 运行全部测试（48 个）
uv run uvicorn main:app --port 8000      # 启动本地服务
# 或：uv run python main.py
```

启动时会播种三个仅用于本地的演示账号（口令固定、TOTP 密钥随机生成）：

| 用户名 | 密码 | 角色 | 启用 MFA |
|---|---|---|---|
| `admin`  | `admin-pass`  | admin（读写 + 管理） | 是 |
| `editor` | `editor-pass` | editor（docs 读写） | 否 |
| `viewer` | `viewer-pass` | viewer（docs 只读） | 是 |

> 演示账号的 TOTP 密钥可通过容器读取：
> `container._demo_totp_secrets["admin"]`，当前口令由
> `container.totp.generate_code(secret)` 生成（测试即如此使用）。

### 1.1 最小调用示例

```bash
# 登录（无 MFA 的 editor 直接返回凭据对）
curl -s -X POST localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"editor","password":"editor-pass","source":"web"}'

# 携带访问凭据访问资源
curl -s localhost:8000/api/docs/doc-1/read \
  -H "Authorization: Bearer <access_token>"

# 轮换刷新凭据
curl -s -X POST localhost:8000/auth/refresh \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<refresh_token>"}'
```

需要 MFA 的账号，`/auth/login` 返回 `{"mfa_required": true, "mfa_token": ...}`，
再调用 `/auth/mfa` 提交 6 位口令。

---

## 2. 会话与凭据生命周期

### 2.1 凭据形态

两类凭据均为自包含的紧凑字符串：

```
base64url(header).base64url(payload).base64url(HMAC_SHA256)
```

* `header = {"alg":"HS256","kid":"<密钥id>"}`；
* 访问凭据 payload：`jti, sub, scopes, iat, exp, family, typ=access`；
* 刷新凭据 payload：`jti, sub, iat, exp, family, typ=refresh`。

刷新凭据的**权威状态**（是否已使用 / 已撤销）保存在服务端，而不是只靠签名。

| 凭据 | 寿命 | 撤销可见性 |
|---|---|---|
| 访问凭据 access token | 15 分钟（`ACCESS_TOKEN_TTL`） | 登出/显式撤销立即失效（撤销表，按其 `exp` 惰性清理） |
| 刷新凭据 refresh token | 7 天（`REFRESH_TOKEN_TTL`） | 家族级撤销，立即失效 |

### 2.2 刷新轮换（rotation）规则

调用 `/auth/refresh` 用旧刷新凭据换取**新的访问凭据 + 新的刷新凭据**：

1. 校验签名 / `kid` / 类型；
2. 在存储层**同一把锁**内完成「查状态 → 判定 → 置 `used=true` → 签发」，
   先占位再签发；
3. 成功后：
   * **旧刷新凭据立即失效**（标记 `used`）；
   * 新凭据属于同一 `family`，新访问凭据的权限由**服务端用户记录实时重算**。

**重复 / 并发提交同一刷新凭据**：恰好一个成功，其余全部失败，且原因可区分：

| 场景 | HTTP | 稳定错误码 `error.code` |
|---|---|---|
| 旧凭据再次提交（落败的并发者/串行重放） | 401 | `refresh_token_reused` |
| 家族已被连带撤销（登出、检测到重用、密钥轮换） | 401 | `refresh_token_revoked` |
| 凭据过期 | 401 | `refresh_token_expired` |
| 坏签名 / 旧 `kid`（密钥轮换后）/ 类型错误 | 401 | `refresh_token_invalid` |

**重用即牵连撤销**：一旦发现某个已使用的刷新凭据被再次提交，立即撤销整个
`family`（包括刚轮换出的新凭据），以阻断令牌窃取后的继续轮换。

### 2.3 登出与密钥轮换

* `POST /auth/logout`（携带 `refresh_token`，可选 `access_token`）：
  撤销整个刷新家族；若上报访问凭据，则该访问凭据**立即**失效
  （`access_token_revoked`），无需等待 15 分钟自然过期。
* `TokenAuthority.rotate_signing_key()`：生成新 HMAC 密钥并**删除旧密钥**。
  旧凭据验签时找不到 `kid`，访问凭据报 `access_token_invalid`、
  刷新凭据报 `refresh_token_invalid`，同时所有现存刷新家族被标记撤销。
  密钥轮换后，此前签发的 MFA 挑战令牌也立即失效（`invalid_mfa_token`）。

---

## 3. TOTP 二次验证与失败防护

### 3.1 验证算法

标准 TOTP（HMAC-SHA1，6 位，30 秒时间步），默认允许前后各 1 个时间步
（±30s 时钟漂移，`TOTPConfig.skew=1`），使用常数时间比较。

### 3.2 判定顺序与可区分结果

对 `verify(user_id, source, secret, code, timestamp?)`，在锁内按序判定：

1. 来源时间戳与服务端时钟相差超过 `max_timestamp_skew_seconds`
   （默认 86400s，测试配置 120s）→ **`totp_time_skew`**（时钟偏差，独立原因，
   **不**计入失败次数）；
2. 账号在该 `source` 处于锁定窗口 → **`account_locked`（HTTP 423）**，
   **即使口令正确也拒绝**；
3. 处于限流冷却窗口 → **`mfa_throttled`（HTTP 429）**；
4. 时间步已被该账号成功使用过 → **`totp_replayed`**（防重放，计为一次失败）；
5. 口令在允许窗口内不匹配 → **`totp_incorrect`**（计为一次失败）；
6. 成功：记录最近使用的时间步（防重放），并**复位**失败计数与所有窗口。

### 3.3 计数、限流与锁定规则（阈值可配）

默认 `TOTPConfig`：

* 每次错误口令（incorrect / replayed）使 `failures += 1`；
  **被限流/锁定拦截的请求不增加计数**；
* 失败达到 `throttle_after=3`：每次失败都会刷新 60s 冷却窗口
  （`throttle_seconds`），窗口内请求被减速拒绝（429）；
* 失败达到 `max_attempts=5`：进入 300s 锁定窗口（`lock_seconds`），
  窗口内**一切**验证请求都被拒绝（423），口令正确也不例外；
* **计数持续累计，冷却窗口过期不清零**（否则锁定阈值永远不可达）；
  计数仅在两种情况下复位：**成功验证**，或**锁定窗口过期（全新开始）**。
* 计数维度是 `user_id:source`（账号 + 来源），不同来源互不影响。

> 边界语义：越过失利阈值的**那一次**请求仍返回原始失败原因
> （incorrect/replayed），阈值窗口只对**后续**请求生效——
> “第 N 次错就是错，第 N+1 次才告知被限流/锁定”，更易解释。

锁定窗口边界示例（固定时钟，见 `tests/test_totp_mfa.py`）：
连续 5 次错误后锁定 300s；`t=299` 仍是 `account_locked`，`t=300`
窗口过期、计数清零，当前正确口令立即放行。

---

## 4. 授权判定模型

### 4.1 唯一权威是服务端持久化数据

主体最终权限：

```
effective_scopes = 持久化显式 scopes  ∪  ⋃ role∈roles 的 ROLE_SCOPE_MAP[role]
```

* `ROLE_SCOPE_MAP` 是服务端安全配置：
  `admin → {admin:read, admin:write, docs:read, docs:write}`，
  `editor → {docs:read, docs:write}`，`viewer → {docs:read}`；
* **访问凭据中携带的 `scopes` 仅被视为客户端声明，判定时一律忽略**。
  凭据被多写权限不会提权（且 HMAC 使篡改即失效）；凭据少写权限也不会降权。
  声明与权威不一致时，服务端记录一条 `scope divergence ... -> decision_uses=server_store`
  日志，结论始终以服务端为准并保持稳定。
* 配置变更（如把某用户角色从 admin 收敛为 viewer）后，其尚未过期的访问凭据
  下次请求即按新权限判定，无需等凭据过期。

### 4.2 跨入口一致 + 不暴露资源存在性

* 所有受保护资源入口（`/api/docs/{id}/read`、`/api/docs/{id}/write`）都调用
  **同一个** `AuthService.require_scope → authz.authorize_or_404`，
  因此对同一请求结论必然一致；
* **越权访问与资源不存在对外完全相同**：HTTP 404 +
  `{"error":{"code":"not_found",...}}`，响应体逐字节一致，
  无法据此判断资源是否存在；差异（forbidden vs missing）只记录在服务端日志；
* 未认证问题（缺少/损坏/过期/撤销凭据）仍是 401，便于客户端区分“先去登录”；
* 显式管理入口 `/api/admin/whoami` 不是资源存在性入口，权限不足返回明确的
  403 `forbidden`。

---

## 5. 错误码总览（稳定、可断言）

所有业务错误返回统一形态：

```json
{"error": {"code": "<稳定错误码>", "message": "<人类可读说明>"}}
```

| code | HTTP | 含义 |
|---|---|---|
| `invalid_credentials` | 401 | 用户名/密码错误（用户不存在与密码错误同因） |
| `mfa_required` | 401 | 需二次验证（响应同时返回 `mfa_token`） |
| `invalid_mfa_token` | 401 | MFA 挑战令牌无效/被密钥轮换失效 |
| `totp_incorrect` / `totp_replayed` | 401 | 口令错误 / 时间步重放 |
| `totp_time_skew` | 401 | 时间戳偏差超窗（可区分，不计失败） |
| `mfa_throttled` | 429 | 限流冷却中 |
| `account_locked` | 423 | 锁定窗口内 |
| `access_token_invalid` / `_expired` / `_revoked` | 401 | 访问凭据 坏/过期/撤销 |
| `refresh_token_invalid` / `_expired` / `_reused` / `_revoked` | 401 | 刷新凭据 坏/过期/重用/撤销 |
| `forbidden` | 403 | 已认证但权限不足（显式管理入口） |
| `not_found` | 404 | 资源不存在 **或** 越权（对外不可区分） |

---

## 6. HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 用户名/密码登录；需要则返回 `mfa_token` |
| POST | `/auth/mfa` | 提交 TOTP 口令完成二次验证 |
| POST | `/auth/refresh` | 刷新凭据轮换（旧凭据失效） |
| POST | `/auth/logout` | 登出，撤销刷新家族（及可选访问凭据） |
| GET  | `/api/docs/{id}/read` | 资源入口，需 `docs:read`；越权与不存在同为 404 |
| GET  | `/api/docs/{id}/write` | 资源入口，需 `docs:write`；越权与不存在同为 404 |
| GET  | `/api/admin/whoami` | 管理入口，需 `admin:read`；不足返回 403 |
| GET  | `/health` | 健康检查 |

---

## 7. 代码结构

```
auth/
  errors.py      # 统一错误类型与稳定 code / HTTP 状态
  timeutil.py    # Clock / FixedClock（可注入、可推进的时间源）
  security.py    # PBKDF2 密码哈希、base64url、HMAC-SHA256（纯标准库）
  store.py       # 线程安全内存存储：用户、刷新凭据、撤销表、MFA 计数、TOTP 时间步
  tokens.py      # 访问/刷新凭据签发、原子轮换、登出撤销、签名密钥管理
  totp.py        # TOTP 生成/校验 + 限流/锁定/防重放/时钟偏差
  authz.py       # 角色→scope、服务端权威解析、统一授权、404 掩盖
  service.py     # 登录/MFA/刷新/登出/入口鉴权编排
  api.py         # FastAPI 入口、统一错误响应
  bootstrap.py   # 装配 + 演示账号播种
main.py          # uvicorn 启动入口
tests/           # pytest：并发刷新、重用、锁定边界、过期/撤销、跨入口一致性等
```

### 7.1 本地验证（测试）

```bash
uv run pytest -q                 # 全部
uv run pytest -k concurrent -q   # 仅并发相关
uv run pytest -k lockout -q      # 仅锁定边界
```

测试特点：

* **不依赖真实外部服务或凭据**：内存存储 + `FixedClock` + 本地生成的 TOTP 密钥；
* 覆盖并发刷新（32 线程/64 并发 ×多轮，断言**恰好一个成功**）、
  凭据重复使用、锁定窗口边界（t=299 / t=300）、过期与已撤销凭据、
  密钥轮换立即失效、跨入口授权一致性、越权/不存在响应同形、
  服务端权限覆盖凭据声明等；
* 失败路径一律断言**稳定错误码**，失败原因可区分；
* 单测/运行日志打印关键输入（user、source、时间戳、code 长度）与
  **判定依据**（effective scopes、required、decision、failures、
  窗口剩余秒数、scope divergence 等），便于审计解释。
