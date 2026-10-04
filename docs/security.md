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

每个会话持久化自己的 `mfa_last_verified_at`（新鲜度锚点**仍按会话**
独立），而一次性口令的已消费记录保存在**按用户**的台账
`_mfa_consumed[user_id]` 中、会话上保留一份镜像（`mfa_consumed_steps`）：

- **锚点**：登录完成时那次成功的 TOTP 即首个锚点（其时间步同时被
  标记为已消费）；之后每次成功的 `reauthenticate` 把锚点刷新为当前
  时刻。
- **窗口**：敏感操作要求 `now <= mfa_last_verified_at +
  reauth_freshness`。默认 300 秒，`SessionService(reauth_freshness=...)`
  可配。
- **边界**：采用包含边界——恰在 `fresh_until` 放行；严格大于
  （哪怕一个 epsilon）拒绝为 `reauth_required`，测试在两个边界点
  各断言一次。
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

### 5.3 一次性口令不可重放（含并发与跨会话）

TOTP 的口令按 30 秒时间步重复。再认证 / 登录成功时把命中的**绝对时间步**
（`now // period + matched_step`）写入**按用户**的已消费台账
（`Store._mfa_consumed[user_id]`），并在所属会话上保留同一步的镜像。
登录那一步同样进用户台账。再次提交同一步口令时：

- 先过 TOTP 校验（保证错误口令仍计失败、限流/锁定照常生效），
- 再由**原子**原语 `Store.consume_mfa_step(user_id, session_id, at, step)`
  在存储层同一把 `RLock` 内一次完成「查重 → 追加用户台账 → 追加会话镜像
  → 写新鲜度锚点」：命中已消费步即 `totp_replay`，**不**更新锚点、
  **不**滑动窗口、台账也不增加任何记录。

因此同一步口令在**同一用户下、跨所有会话**最多只能授权一次：

| 重放形态 | 结果 |
|----------|------|
| 同一步在同一会话里再次提交 | `totp_replay`（409） |
| 同一时刻 N 个请求提交同一口令（同会话或跨会话） | 恰好 1 个成功，其余全部 `totp_replay`（409） |
| 一个会话用掉后，换到该用户的另一个会话再用 | `totp_replay`（409） |
| 另一个会话登录时直接复用已用过的口令完成登录 | `totp_replay`（409），新建会话随即撤回，不留任何已登录会话 |

不同用户的相同绝对时间步互不影响（台账按 `user_id` 隔离）。`totp_replay`
与 `totp_invalid`（口令本身错误）、`mfa_rate_limited` / `mfa_locked`
（限流或锁定）使用互不重叠的错误码，调用方可明确区分。

### 5.4 并发一致性

- 再认证的「查重 + 记锚点 + 消费步」是存储层锁内的**单个**原子动作：
  N 个并发、携带同一口令的再认证恰好一个成功，其余全部 `totp_replay`，
  锚点只更新一次、用户台账中该步只出现一次（不是靠线程调度碰运气，也不
  靠 sleep）。被拒绝的路径不写任何状态，因此不会出现窗口顺延两次、次数
  对不上或本该拦截的请求被放行。
- 登录完成与再认证共用同一个原子消费原语；若登录在查重环节落败
  （并发重复登录或口令已在其它会话消费），刚创建的会话会被
  `delete_session` 撤回，拒绝不会留下一条已认证会话。
- 多个并发「退出其他设备」在窗口内结论一致：恰有一个看到全部待
  下线会话、其余看到 0，当前会话永不被终止，计数不错乱。
- 新鲜度窗口的边界口径不变：恰在 `fresh_until` 放行，严格大于（哪怕
  一个 epsilon）拒绝为 `reauth_required`；再认证的窗口从本次验证时刻
  起算，失败的口令验证与被拒绝的重放都不改锚点。

## 6. 与既有行为的兼容范围

本次为**叠加式**改动，不改变既有登录 / 刷新 / 授权语义：

- 登录、刷新轮换、重用检测、登出、密钥轮换的错误码与状态迁移不变；
  原有登录 / 刷新 / 授权 / 多设备 / 再认证用例全部继续通过。
- 唯一收紧的语义是一次性口令的消费范围由「按会话」改为「按用户」：
  同一用户的第二个设备完成登录时必须使用**新一步**口令（真实环境下
  30 秒后自然换步）；此前测试夹具在 `FixedClock` 同一时刻为多设备
  登录复用同一口令的写法，改为每次登录前 `clock.advance(31.0)`，
  与生产使用方式一致。
- `SessionRecord` 字段保持不变（`mfa_consumed_steps` 现为用户台账
  的会话镜像）；`Store` 新增 `consume_mfa_step`（原子查重+消费+
  顺延）、`get_consumed_mfa_steps`、`delete_session` 与
  `MfaConsumeResult`，既有 `get_mfa_state` / `mark_mfa_verified`
  保留，`create_session` 签名不变。
- 错误码与 HTTP 映射未改：重放继续是 409 `totp_replay`，窗口过期
  继续是 403 `reauth_required`，错误口令继续是 400 `totp_invalid`。
- 既有 `/auth/logout` 与新的会话下线共用吊销原语，但互不替代：
  logout 仍按 refresh 家族吊销，新下线按「会话 + 其全部家族」吊销。
- 统一授权 `Authorizer.decide` 未改；新会话入口在其之外实现了等价
  的存在性隐藏，多个入口（列举 / 单个下线 / 批量下线 / 再认证）对
  同一归属问题结论一致。

## 7. 本地验证方法

```bash
uv sync
uv run pytest -q          # 全部测试通过（含一次性口令并发/跨会话回归）
uv run pytest -s          # 打印每个关键判定的结构化 JSON 日志
uv run pytest tests/test_totp_replay.py -v   # 只跑两类回归，逐条看用例名与结果
uv run python scripts/local_demo.py   # 完整链路冒烟脚本
uv run uvicorn main:app --reload      # 交互式试玩：/docs
```

### 7.1 一次性口令并发 / 跨会话回归如何稳定复现

回归用例在 `tests/test_totp_replay.py`，**不靠多线程自然竞争**：

- **同时提交同一个口令**：`ReauthBarrierService` 通过服务钩子
  `_mfa_step_consuming` 放置 `threading.Barrier`，让 N 路请求确定性地
  同时停在「TOTP 已校验通过、原子消费尚未执行」的点上，再一起放行。
  - `test_simultaneous_same_code_same_session_single_winner[2|8]`：
    同一会话 2 路 / 8 路同时提交同一口令，断言恰好 1 个成功、其余
    全部 `totp_replay`，且窗口只顺延一次、台账中该步只出现一次；
  - `test_simultaneous_same_code_across_two_sessions_single_winner`：
    两个登录会话同时提交同一口令，同样恰好 1 个成功。
- **跨会话重复使用**：
  - `test_cross_session_replay_is_rejected`：口令在会话 A 用掉后，
    换到同用户会话 B（口令仍在 ±1 步容忍窗口内，密码学上有效）必须
    得到 `totp_replay`，且会话 B 的锚点没有被滑动；
  - `test_second_login_replaying_a_spent_code_is_rejected_and_leaves_no_session`：
    另一个设备直接拿已用过的口令完成登录，得到 `totp_replay`，且不
    残留新会话；
  - `test_login_replay_is_distinct_from_wrong_code`：同一界面下错误
    口令仍是 `totp_invalid`，与重放原因可区分。
- **边界口径回归**：`test_freshness_bound_unchanged_after_ledger_change`
  断言恰在 `fresh_until` 放行、过一个 epsilon 拒绝为 `reauth_required`，
  改造前后口径一致。
- 存储层原子性另有 `tests/test_store.py` 中的
  `test_consume_mfa_step_is_single_winner_under_contention`（8 线程
  同起点压测原语）与
  `test_consume_mfa_step_is_user_scoped_across_sessions`（跨会话/跨
  用户/已吊销会话的台账语义）直接压测。

这些用例在修复前的实现上可稳定复现失败（同会话并发两路都成功、
跨会话重复使用被放行）；用历史代码建 worktree 拷贝该测试文件即可
对照。并发用例不使用 `sleep`，整套 75 个测试可反复稳定通过。

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
5. 调 `reauthenticate` 提交正确口令后窗口顺延；把同一口令再交一次
   得 409 `totp_replay`，窗口不滑动；用同一用户的另一个登录会话
   （登录前先 `clock.advance(31.0)` 取新口令登录）再交这个旧口令，
   同样是 409 `totp_replay`。

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
