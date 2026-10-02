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

## 3.5 多设备会话管理

会话创建时记录稳定标识 `sess_<random>`、登录来源 `source` 与建立时间
`created_at`；会话结构另带 `last_reauth_at`（再认证新鲜度，见 3.6）。

### 3.5.1 列举（`GET /auth/sessions`）

- 必须持有效 access token；只返回该账号**未被吊销**的会话，按建立时间升序。
- 每条包含 `session_id / source / created_at / last_reauth_at / current`；
  `current` 标记**本次请求所用**的会话。标识是可被后续请求点名引用的稳定
  字符串，换一台设备查看时同一标识不变、只是 `current` 视角切换。

### 3.5.2 按标识下线单个会话（`POST /auth/sessions/revoke`）

`Store.terminate_session(session_id, user_id, reason, now)` 在存储层同一把
锁内一次完成：

1. 会话存在、归属调用者且尚未吊销，否则返回 `False`（无副作用）；
2. 置 `revoked=True`、记录 `revoked_reason=session_revoked_by_owner`；
3. `token_version += 1`——该会话此前签发的 access 在下一次
   `authenticate` 时因版本不一致立刻报 `access_token_revoked`；
4. 该会话名下全部 refresh 记录置 `REVOKED`（含当前家族与历史家族），
   再拿 refresh 来请求报 `refresh_token_revoked`。

未被点名的会话（同账号的其它设备、其它账号）记录一概不触碰。

### 3.5.3 退出其他所有设备（`POST /auth/sessions/revoke-others`）

`Store.terminate_other_sessions(keep_session_id, user_id, ...)` 原子地批量
终止调用者除当前会话外的所有有效会话：当前会话的 `token_version`
**不变**，其 access/refresh 之后照常可用；被终止会话的 refresh 记录
全部置 `REVOKED`。批量过程对每个会话的效果与 3.5.2 完全相同。

### 3.5.4 归属与存在性隐藏（与统一授权口径一致）

单个下线入口对三类输入——会话标识不存在、属于他人、已被吊销——对外
返回**同一个** `404 {"error":"not_found"}`，无法据此外推会话是否存在；
区分依据 `session_missing / foreign_session / already_revoked` 只写进
服务端结构化日志。列举入口天然只暴露本人会话；「退出其他设备」只按
存储中的归属关系批量选取，不接受外部传入的会话标识。

### 3.5.5 下线与刷新交错并发

刷新在 claim 之后、提交之前存在一个窗口；若会话恰在该窗口内被下线：

- `terminate_session` / `terminate_other_sessions` 已把相关 refresh 记录
  置 `REVOKED`，获胜中的 `replace_refresh` 提交会因状态不再可交换而失败；
- 会话层把该 `LookupError` 收敛为可区分结果：会话已吊销 →
  `session_revoked`，否则 `refresh_token_revoked`，claim 一定被释放，
  绝不会签发「孤儿新凭据」。

测试用既有的 `BarrierService` 钩子确定性地把刷新钉在该窗口，再从另一台
设备执行单个/批量下线，断言刷新被拒、目标凭据全死、当前会话继续可用、
存储中没有残留活跃凭据（`test_terminate_*_during_inflight_refresh`）。

## 3.6 敏感操作再认证（step-up）

「退出其他所有设备」属于高风险操作，仅凭一张尚未过期的 access 凭据
不放行。规则由 `SessionService(reauth_window=...)` 配置，默认 300 秒。

### 3.6.1 新鲜度模型

- 新鲜度按**会话**记录：`SessionRecord.last_reauth_at`。登录时完成的
  MFA **不**写入该字段（登录验证与敏感操作再认证是两件事）。
- 窗口为半开区间 **`[t0, t0 + window)`**：`now < t0 + window` 视为新鲜；
  **恰在 `t0 + window` 即过期**，必须重新再认证。边界由注入时钟驱动，
  测试精确断言「差 1ms 放行 / 恰在边界拒绝 / 过 1ms 拒绝」。
- 顺延（sliding）：窗口内再次验证成功，以**最新一次成功时间**重开窗口；
  仅执行敏感操作（不带新口令）不顺延。
- 超窗结果为独立错误码 `reauth_required`（HTTP 403），与「口令错误」
  `totp_invalid`(400)、「时钟偏差」`totp_clock_skew`(400)、
  「限流」`mfa_rate_limited`(429)、「锁定」`mfa_locked`(409) 全部不同。

### 3.6.2 一次性口令不可重放

- 再认证仍走 `TotpVerifier.verify`，失败照常计入 `(user, source)` 的
  限流/锁定；通过后取命中的**绝对 TOTP 步号**
  （`step_at(now) + matched_step`）。
- `Store.consume_reauth_step(user, step, min_retained_step)` 在存储锁内
  原子地「检查-记录」：同一用户的同一步号第二次出现即拒绝
  `reauth_code_reused`（409），无论来自同一会话还是另一台设备。
- 记录按用户维度（一个账号共享一个 TOTP 密钥），并按
  `now - max_skew_steps` 修剪陈旧步号，集合不会无限增长。
- 重放被拒时**不**写 `last_reauth_at`、不改变计数窗口，状态不被污染：
  下一周期的新口令仍可正常完成再认证。

### 3.6.3 并发一致性

两个请求并发使用同一口令做再认证时，步号消费是存储锁内的一次原子
检查-更新：恰好一个成功并盖新鲜度时间戳，另一个得到
`reauth_code_reused`。并发的多次敏感操作不会出现「本该拦住却放行」或
窗口/计数错乱；测试 `_StepUpBarrierService` 把首个请求确定性地停在
「口令已验证、步号尚未消费」处再放入第二个请求。

### 3.6.4 入口

- `POST /auth/reauthenticate`：只做一次再认证并延长本会话新鲜度，
  不执行任何敏感动作（便于调用方先刷新再操作）；
- `POST /auth/sessions/revoke-others`：请求体可带 `code`——带码则先
  完成再认证（成功即顺延窗口）再批量下线；不带码则要求窗口内已有
  新鲜再认证，否则 `reauth_required`。

## 4. 本地验证方法

```bash
uv sync
uv run pytest -q          # 62 个测试全部通过（44 个既有 + 18 个新增）
uv run pytest -s          # 打印每个关键判定的结构化 JSON 日志
uv run python scripts/local_demo.py   # 完整链路冒烟脚本（结尾含多设备管理）
uv run uvicorn main:app --reload      # 交互式试玩：/docs
```

日志示例（`pytest -s` 可见），展示关键输入与判定依据：

```json
{"stage":"refresh","decision":"ok","user":"alice","old_jti":"rt_...","new_jti":"rt_...","token_version":1}
{"stage":"refresh","decision":"refresh_token_reuse","family":"fam_...","jti":"rt_...","used_at":1000000.0}
{"stage":"authz.decide","decision":"not_found","resource":"docs-admin","subject":"alice","missing":["docs:write"],"basis":"scope_insufficient"}
{"stage":"authz.scope_reconcile","decision":"persistence_wins","subject":"alice","dropped":["docs:write"],"persisted_scopes":["docs:read","profile:read"]}
{"stage":"mfa.verify","decision":"mfa_locked","user":"alice","source":"web","failures":5,"retry_after":300.0,"code_evaluated":false}
{"stage":"sessions.list","decision":"ok","user":"alice","current":"sess_...","count":3,"sessions":["sess_...","sess_..."]}
{"stage":"sessions.revoke","decision":"not_found","actor":"alice","target":"sess_other","basis":"foreign_session"}
{"stage":"reauth.verify","decision":"ok","user":"alice","source":"web","step":33333,"fresh_until":1000300.0}
{"stage":"reauth.verify","decision":"reauth_code_reused","user":"alice","step":33333}
{"stage":"sessions.revoke_others","decision":"ok","current":"sess_...","terminated":["sess_..."],"reauthenticated":true}
```

测试不访问网络、不使用真实 TOTP 服务或 IdP：TOTP 由同模块的
`code_at` 在已知密钥下生成；时间由 `FixedClock` 驱动；HTTP 测试使用
FastAPI `TestClient`。
