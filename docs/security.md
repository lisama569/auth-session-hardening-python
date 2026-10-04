# 会话 / 凭据 / 二次验证 / 授权 设计说明

所有时间判断都走可注入时钟（`auth/clock.py`），默认参数集中在
`auth/sessions.py` 与 `auth/mfa.py`，本地用 `FixedClock` 即可复现任意
边界条件，不依赖任何真实外部服务。

## 1. 会话与凭据生命周期

### 1.1 凭据形态

- 格式：`base64url(payload).base64url(HMAC-SHA256(payload, 当前密钥))`，
  载荷为 JSON，自包含、无状态可验签；实现见 `auth/tokens.py`。
- `typ=access`：TTL 300 秒，携带 `scopes` 快照与会话令牌版本 `ver`。
- `typ=refresh`：TTL 7 天，只携带会话/主体标识，不携带业务权限。
- 每个凭据带 `jti`（唯一标识）、`kid`（签名密钥版本）、`iat/exp`。

### 1.2 登录与签发

1. `POST /auth/login/start`：恒定时间比对密码哈希；用户不存在与密码错误
   返回**同一个** `invalid_credentials`（防账号枚举）。通过后创建
   MFA challenge（TTL 120 秒，一次性、过期报 `challenge_expired`，
   重放报 `challenge_not_found`）。
2. `POST /auth/login/complete`：TOTP 校验通过后：
   - 创建 `SessionRecord`（`token_version = 0`）；
   - 签发 access（`ver=0`）与 refresh；
   - 服务端登记 refresh 记录：`jti -> {family_id, state=ACTIVE}`。

### 1.3 刷新轮换（refresh rotation）

刷新是**一次性原子操作**（`Store.mark_inflight` +
`Store.replace_refresh` 均在同一把锁内完成状态迁移）：

1. 验签、校验类型与过期；
2. 原子 claim：只有 `ACTIVE 且未被 claim` 的凭据能成功，claim 后
   `inflight=True`；
3. bump 会话 `token_version`，以新版本号签发新 access + 新 refresh
   （同 `family_id`），旧记录置 `ROTATED` 并记录 `successor_jti`。

由此得到可区分的三类失败：

| 时序 | 旧凭据状态 | 结果 |
|------|-----------|------|
| 与获胜请求**同时**提交（获胜者已 claim 未提交） | `inflight=True` | `refresh_token_concurrent`（409） |
| 获胜者提交后再次使用 | `ROTATED` | `refresh_token_reuse`（409） |
| 家族已被吊销（登出/检测到重用） | `REVOKED` | `refresh_token_revoked`（409） |

**刷新成功后：**

- 旧 refresh 立即失效（状态变为 `ROTATED`）；
- 会话 `token_version` +1，**旧 access 立即失效**：`authenticate`
  会比对 `claims.ver == session.token_version`，不一致报
  `access_token_revoked`（不用等 access 自然过期）。

**检测到重用（旧凭据被再次使用）时的保守响应：**

- 吊销整个 refresh 家族（`revoke_family`）；
- 吊销会话并 bump 版本，已签发的全部 access 立即失效。
  理由：旧凭据重现意味着可能失窃，必须让失窃窗口内的整条链路同时失效。

### 1.4 登出

`POST /auth/logout` 吊销会话与整个 refresh 家族并 bump 令牌版本，
因此：refresh 报 `refresh_token_revoked`，access 报
`access_token_revoked`。登出对签名验证失败（如刚轮换过密钥）的凭据
采用「只读载荷定位会话」的尽力策略，保证密钥轮换后登出仍然生效；
该降级路径只做状态吊销，不做任何认证结论。

### 1.5 签名密钥轮换

`POST /admin/rotate-keys` / `KeyRing.rotate()` 生成全新随机密钥与
`kid`，**不保留旧密钥**。此后：

- 旧密钥签名的任何凭据验签即失败；当载荷中 `kid` 与当前不同，
  给出可区分的 `key_version_stale`（401），与普通伪造
  （`*_token_invalid`）区分；
- access 与 refresh 一视同仁，立即失效。

### 1.6 并发正确性如何保证与验证

- 正确性：claim 与轮换提交是存储层同一把 `RLock` 内的检查-更新，
  多线程下状态迁移只有一个线程能赢（`tests/test_store.py` 直接压测）。
- 可复现：并发测试不使用 `sleep`，而是在
  `SessionService._refresh_claimed` 钩子上放置线程栅栏
  （`tests/test_concurrent_refresh.py`），让获胜请求确定性地停在
  「已 claim、未提交」窗口，再同时发起 N 个重复请求。断言：恰好
  1 个成功、N 个全部 `refresh_token_concurrent`、家族内仅余 1 个活跃凭据。

## 2. 二次验证（TOTP）与限流规则

实现为 RFC 6238（HMAC-SHA1，30 秒周期，6 位数字），见 `auth/mfa.py`。

- 容忍窗口：当前步 ±1 步内的口令视为正确（`matched_step` 会记录命中偏移）。
- 时钟偏差可区分：口令在 ±(2..3) 步内有效但超出容忍窗口，返回
  `totp_clock_skew`（仍是一次计入的失败）；更远或根本错误为
  `totp_invalid`。
- 失败维度：`(user_id, source)`，例如同一用户的 `web` 与 `mobile`
  计数互不影响（测试覆盖）。

默认阈值（构造器可调）：

| 规则 | 默认值 |
|------|--------|
| 失败计数达到 3 | 进入 60 秒限流窗口，期间**口令正确也返回 `mfa_rate_limited`** |
| 失败计数达到 5 | 进入 300 秒锁定窗口，期间**任何尝试都返回 `mfa_locked`，不再校验口令** |
| 锁定窗口边界 | 排他边界：`t < locked_until` 锁定；恰在 `locked_until` 放行云图重计 |
| 成功验证 | 计数与所有窗口立即清零复位 |
| 锁定期满 | 计数显式复位为 0（下一次失败从 1 开始） |

计数语义说明：限流窗口内仍会继续评估口令，错误口令继续累加计数，
因此持续攻击会从「限流」升级为「锁定」；但正确口令在限流窗口内
不放行（防爆破），锁定窗口内则完全短路。MFA 判定不抛异常，而以
`MfaStatus(result, failures, locked_until, retry_after)` 返回可解释
结果，由会话层映射成错误码。

## 3. 授权判定模型

`auth/authz.py` 中的 `Authorizer.decide(resource, user_id,
credential_scopes)` 是**唯一**判定函数，HTTP 入口与会话服务
（`authorize_request`）全部经过它，因此同一请求在任何入口结论一致。

判定顺序（稳定、可解释，每步都有结构化日志）：

1. 无主体 → `DENY_UNAUTHENTICATED`（`unauthenticated`，401）；
2. 资源未注册 → `DENY_NOT_FOUND`（内部原因 `not_found`）；
3. **以服务端持久化数据为准**：有效权限 = 存储中该用户的
   `scopes`；凭据中携带的 `scopes` 仅作参考，差异会被记录
   （`authz.scope_reconcile -> persistence_wins`，含 dropped/added）：
   - 凭据夸口有但服务端没授予的 scope → 丢弃（提权伪造无效）；
   - 凭据里缺但服务端已授予的 scope → 仍放行；
4. 持久化 scope 不满足资源要求 → `DENY_NOT_FOUND`（内部原因
   `forbidden`，日志含 missing 集合）。

**存在性隐藏**：越权与资源不存在对外**完全同形**（都是 404 +
`DENY_NOT_FOUND`），区别只保留在 `AuthDecision.reason` 与服务端日志中，
不向调用者暴露目标资源是否存在。

**配置变更即时生效**：由于每次判定都实时读取持久化用户记录，
管理员收窄某用户 scope 后，其手上尚未过期的 access token 立刻失去
对应能力（测试 `test_permission_change_takes_effect_for_outstanding_tokens`），
无需吊销凭据即可止血；凭据吊销（版本/密钥/登出）则作为独立机制存在。

## 4. 多设备会话管理

### 4.1 会话标识与列举

每次登录完成后创建一个 `SessionRecord`，携带：

- `session_id`：`sess_` 前缀的稳定随机标识，可被用户引用、跨请求不变；
- `source`：登入来源（登录 start 传入，如 `web` / `mobile` / `cli`）；
- `created_at`：建立时间（来自可注入时钟）；
- `token_version`：令牌版本，刷新/下线递增，旧 access 即刻失效。

`GET /auth/sessions` 只列举**当前认证主体自己的、未吊销**的会话，
并用 `current` 布尔标出本次 access token 所属的那个会话；列举结果
不会出现任何人的其他会话。

### 4.2 单个下线与「退出其他所有设备」

二者都复用存储层的**原子终止原语**（`Store.terminate_session` /
`terminate_other_sessions`），在同一把 `RLock` 内一次完成：

1. 会话置 `revoked` 并记录原因（`user_terminated` / `logout_others`）；
2. `token_version += 1`——此后该会话已签发的全部 access 在
   `authenticate` 处得到 `access_token_revoked`；
3. 该会话绑定的**全部** refresh 记录（含旧家族链路与「已 claim、
   未提交」的在途记录）置 `REVOKED`，刷新入口随即得到
   `refresh_token_revoked`。

因此下线是**立即**且**访问/刷新双凭据同时**作废；原因可与
「会话不存在」（`session_not_found`）、「会话已吊销但凭据先撞到家族
状态」等区分。批量下线时当前会话不在目标集合内，其状态、版本、
refresh 家族都不被触碰，当前请求与后续刷新照常。

### 4.3 归属判定与存在性隐藏（与统一授权口径一致）

会话管理入口不经过资源 `Authorizer`（它们不是具名资源），但严格
沿用同一条存在性隐藏原则：`_own_active_session_or_404` 仅当目标
「存在 **且** 属于当前用户 **且** 未吊销」时才放行，其余三种情况
（missing / foreign_owner / revoked）抛出**同一个**
`session_not_found`，HTTP 均为 404、body 完全一致；真实依据只进
日志。列举接口按主体过滤，越权方连 id 都看不到。这样新增入口不会
泄露「某个 session_id 是否存在 / 属于谁」。

### 4.4 下线与刷新交错

- 刷新在 claim 之后、提交之前若会话被终止：提交时
  `replace_refresh` 发现旧记录已非 `ACTIVE/inflight` 而失败，服务层
  重读记录并归类为 `refresh_token_revoked`（`basis=terminated_in_flight`），
  不会误发新凭据。
- 刷新先提交、下线后到：终止原语按 `session_id` 株连全部 refresh，
  刚轮换出的后继凭据同样立即 `REVOKED`。
- 同账号其它会话的刷新与凭据在两种交错下都不受影响（并发测试
  `test_terminate_while_refresh_in_flight_revokes_the_refresh` 等覆盖）。

## 5. 敏感操作再认证（step-up reauthentication）

### 5.1 新鲜度模型

每个会话持久化 `mfa_last_verified_at` 与自己视角的 `mfa_consumed_steps`；
此外存储层为**每个用户**维护一份跨会话的已消费时间步总账
`_user_mfa_steps`（一次性限制的权威记录）：

- **锚点**：登录完成时那次成功的 TOTP 即首个锚点（其时间步同时入账，
  对该用户的所有会话生效）；之后每次成功的 `reauthenticate` 把锚点
  刷新为当前时刻。
- **窗口**：敏感操作要求 `now <= mfa_last_verified_at +
  reauth_freshness`。默认 300 秒，`SessionService(reauth_freshness=...)`
  可配。
- **边界**：采用包含边界——恰在 `fresh_until` 放行；严格大于
  （哪怕一个 epsilon）拒绝为 `reauth_required`，测试在两个边界点
  各断言一次。本次改动**不触碰该口径**：边界点的判定逻辑保持不变。
- **顺延规则**：只有「成功」的再认证会滑动窗口，且起点是本次验证
  时刻；失败的口令验证、被拒绝的重放都不改锚点。

### 5.2 失败原因三分

敏感操作被拒与再认证本身的失败使用互不重叠的稳定码：

| 情形 | 错误码 | HTTP |
|------|--------|------|
| 窗口已过 / 从未验证，需要重做二次验证 | `reauth_required` | 403 |
| 口令错误 | `totp_invalid` | 400 |
| 口令仅时钟偏差 | `totp_clock_skew` | 400 |
| 触发限流 | `mfa_rate_limited` | 429 |
| 触发锁定 | `mfa_locked` | 409 |
| 一次性口令重放 | `totp_replay` | 409 |

调用方凭 403 + `reauth_required` 即知「去走一次 reauth 再重试」，
不会把它与口令错误或限流/锁定混淆。

### 5.3 一次性口令不可重放（按用户，含并发与跨会话）

TOTP 的口令按 30 秒时间步重复。成功消费一个口令（登录或 step-up）时，
把命中的**绝对时间步**（`now // period + matched_step`）写入**该用户**
的跨会话已消费总账（同时在会话视角留一份）。之后任何请求再次提交同一
时间步的口令时：

- 先过 TOTP 校验（保证错误口令仍计失败、限流/锁定照常生效），
- 再由存储层在**同一把锁内**完成「查总账 → 消费 → 记锚点」：
  命中已消费集合即返回 `STEP_REPLAYED`，服务层抛 `totp_replay`，
  **不**更新锚点、**不**滑动窗口、**不**新增任何消费记录。

因此同一步口令在**同一用户**下最多授权一次敏感操作，覆盖三种来路：

1. **同一会话顺序重放**——同一设备把刚用过的口令再交一次；
2. **跨会话 / 跨设备重放**——口令在 A 会话用掉后，换到该用户的
   B 会话（另一台设备）再用，照样被挡；登录时消费的那一步也不能
   拿到另一个会话里做 step-up；
3. **同时并发提交**——N 个请求在极短时间内携带同一口令，恰好 1 个
   成功，其余 N-1 个全部 `totp_replay`。

总账按用户隔离：不同用户（密钥不同）同处一个时间步互不影响。总账
深度有界（`MFA_STEPS_RETAINED = 8` 个最近时间步），仍远大于 TOTP
校验器 ±3 步的最大可命中窗口，因此一个密码学上还可能命中的旧口令
永远不会被遗忘；正常的下一时间步新口令随时可用。

> 说明：多次**登录**本身保持多设备可用——两台设备在同一时间步内各做
> 一次登录都成功，登录对重复时间步是幂等入账（只记一次）；一次性限制
> 作用在「用口令授权敏感操作（step-up）」以及「登录后把该口令挪作他用」
> 上。

### 5.4 并发一致性

- 再认证的「查重 + 消费 + 记锚点」是 `Store.consume_mfa_step` 在
  **一次锁获取**内完成的单一原子迁移：要么三处状态（用户总账、会话
  历史、会话锚点）一起更新且每处只更新一次，要么一处都不动。N 个
  并发、携带同一口令的再认证（无论是否同会话）恰好一个成功，其余
  全部 `totp_replay`，锚点只更新一次、总账只多一个时间步。
- 该保证不依赖线程调度，也不依赖「先缓一缓再判断」：消费判定与窗口
  顺延在同一个临界区内，不可能出现两个请求都通过查重、窗口被写两次
  或次数对不上的情况。新鲜度窗口的边界口径（包含边界）保持不变。
- 多个并发「退出其他设备」在窗口内结论一致：恰有一个看到全部待
  下线会话、其余看到 0，当前会话永不被终止，计数不错乱。

## 6. 与既有行为的兼容范围

本次为**叠加式**改动，不改变既有登录 / 刷新 / 授权语义：

- 登录、刷新轮换、重用检测、登出、密钥轮换的错误码与状态迁移不变；
  既有用例全部继续通过（当前共 75 个）。
- `SessionRecord` 仅新增带默认值的字段（`source`、
  `mfa_last_verified_at`、`mfa_consumed_steps`）；`create_session`
  新增带默认值的 `source` 形参，既有调用点无需改动。
- 一次性口令的消费记录从「仅 per-session」增强为「per-user 跨会话总账
  + per-session 视图」：登录改用幂等的 `record_mfa_login`，再认证改用
  单一原子原语 `consume_mfa_step`；旧的 `mark_mfa_verified` 保留。
  语义变化仅在于「跨会话/并发的同一口令」从可重复放行变为明确拒绝
  （`totp_replay`），其余判定不变。
- 新增的两个错误码只出现在新入口（以及空凭据的防御性
  `unauthenticated`）；既有错误码的 HTTP 映射未改。
- 既有 `/auth/logout` 与新的会话下线共用吊销原语，但互不替代：
  logout 仍按 refresh 家族吊销，新下线按「会话 + 其全部家族」吊销。
- 统一授权 `Authorizer.decide` 未改；新会话入口在其之外实现了等价
  的存在性隐藏，多个入口（列举 / 单个下线 / 批量下线 / 再认证）对
  同一归属问题结论一致。

## 7. 本地验证方法

```bash
uv sync
uv run pytest -q          # 75 个测试全部通过，结尾按业务领域汇总用例与结果
uv run pytest -v          # 逐条列出每个业务下的用例与 PASSED/FAILED
uv run pytest -s          # 打印每个关键判定的结构化 JSON 日志
uv run python scripts/local_demo.py   # 完整链路冒烟脚本
uv run uvicorn main:app --reload      # 交互式试玩：/docs
```

并发/跨会话重放专项（确定性、可反复运行，不依赖自然竞争）：

```bash
uv run pytest tests/test_concurrent_reauth_replay.py -v
uv run pytest tests/test_concurrent_sessions.py::test_concurrent_reauth_same_code_single_winner_window_once -v
```

实现方式：`tests/test_concurrent_reauth_replay.py` 中的
`ReauthBarrierService` 在 `SessionService._mfa_code_verified` 钩子
（TOTP 已校验通过、尚未进入消费判定）放置一个**两段式门闩**——先等 N
个请求全部到达（`wait_all_validated()`），再一次性放行
（`release()`），使所有携带同一口令的请求在同一瞬间进入
`consume_mfa_step`。由此在任何机器上稳定断言「恰好 1 个成功、其余
`totp_replay`、窗口只顺延一次」，而不是靠多线程自然竞争碰运气。

手工复现新能力（时间用 `FixedClock`，脚本里即 `clock.advance(...)`）：

1. 用不同 `source` 登录两次，`GET /auth/sessions` 可见两条会话及
   `current` 标记；
2. `POST /auth/sessions/terminate` 点名下线其中一条，随后用它的
   access 得 409 `access_token_revoked`、refresh 得 409
   `refresh_token_revoked`，另一条照常；
3. 用别人的 `session_id` 或一个不存在的 id 调用下线，两次都是
   404 `session_not_found` 且响应体一致；
4. `clock.advance(120.001)` 越过新鲜度窗口后调用
   `logout-others` 得 403 `reauth_required`；恰在边界（advance
   120.0）仍 200；
5. 调 `reauthenticate` 提交正确口令后窗口顺延；把同一口令在**同一会话**
   再交一次得 409 `totp_replay`，窗口不滑动；
6. 用不同 `source` 再登录一台设备，在第一台设备上 step-up 成功后，立刻
   拿**同一个口令**到第二台设备调 `reauthenticate`：同样得 409
   `totp_replay`（跨会话重放），第二台会话的新鲜度锚点不移动；错误口令
   则仍是 400 `totp_invalid`，限流/锁定为 429/409，三者互不混淆。

日志示例（`pytest -s` 可见），展示关键输入与判定依据：

```json
{"stage":"refresh","decision":"ok","user":"alice","old_jti":"rt_...","new_jti":"rt_...","token_version":1}
{"stage":"refresh","decision":"refresh_token_reuse","family":"fam_...","jti":"rt_...","used_at":1000000.0}
{"stage":"authz.decide","decision":"not_found","resource":"docs-admin","subject":"alice","missing":["docs:write"],"basis":"scope_insufficient"}
{"stage":"authz.scope_reconcile","decision":"persistence_wins","subject":"alice","dropped":["docs:write"],"persisted_scopes":["docs:read","profile:read"]}
{"stage":"mfa.verify","decision":"mfa_locked","user":"alice","source":"web","failures":5,"retry_after":300.0,"code_evaluated":false}
```

测试不访问网络、不使用真实 TOTP 服务或 IdP：TOTP 由同模块的
`code_at` 在已知密钥下生成；时间由 `FixedClock` 驱动；HTTP 测试使用
FastAPI `TestClient`。
