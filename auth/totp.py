"""基于时间的一次性口令（RFC 6238 子集）与失败防护。

判定顺序（在存储层锁内完成，保证并发下计数一致）：

1. 来源时间戳若与服务端时钟相差超过 ``max_timestamp_skew_seconds``
   -> :class:`TOTPTimeSkew`（时钟偏差，独立原因，不计入失败）；
2. 账号在该来源处于锁定窗口 -> :class:`AccountLocked`（即使口令正确也拒绝）；
3. 处于限流冷却窗口 -> :class:`MFAThrottled`；
4. 时间步已被该账号成功使用过 -> :class:`TOTPCodeReplayed`（计失败）；
5. 口令在允许的 ±skew 时间步内不匹配 -> :class:`TOTPCodeIncorrect`（计失败）；
6. 成功：记录最近使用时间步（防重放），失败计数整体复位。

计数/窗口规则（阈值与时长见 :class:`TOTPConfig`）：

* 每次错误口令使 ``failures += 1``（限流拦截的请求不增计数）；
* 达到 ``throttle_after``：每次失败都会刷新短时冷却窗口，请求被减速；
* 达到 ``max_attempts``：进入锁定窗口，窗口内一律拒绝；
* 计数持续累计，限流窗口过期不清零（否则锁定阈值永远不可达）；
  仅在以下两种情况复位：成功验证，或锁定窗口过期（全新开始）；
* 一旦成功验证，计数与所有窗口立即复位。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import struct

from . import errors
from .store import InMemoryStore, MFAFailureState
from .timeutil import Clock

logger = logging.getLogger("auth.totp")


class TOTPConfig:
    def __init__(
        self,
        digits: int = 6,
        period: int = 30,
        skew: int = 1,
        max_attempts: int = 5,
        throttle_after: int = 3,
        throttle_seconds: float = 60.0,
        lock_seconds: float = 300.0,
        max_timestamp_skew_seconds: float = 86400.0,
    ) -> None:
        self.digits = digits
        self.period = period
        self.skew = skew
        self.max_attempts = max_attempts
        self.throttle_after = throttle_after
        self.throttle_seconds = throttle_seconds
        self.lock_seconds = lock_seconds
        self.max_timestamp_skew_seconds = max_timestamp_skew_seconds


def _new_state(key: str) -> MFAFailureState:
    return MFAFailureState(key=key)


class TOTPVerifier:
    def __init__(self, store: InMemoryStore, clock: Clock,
                 config: TOTPConfig | None = None) -> None:
        self._store = store
        self._clock = clock
        self.cfg = config or TOTPConfig()

    # 口令生成（标准库 HOTP/TOTP） ------------------------------------------
    @staticmethod
    def generate_secret(length: int = 20) -> str:
        """生成 base32 编码随机密钥（RFC 4648，无填充）。"""
        return base64.b32encode(os.urandom(length)).decode("ascii").rstrip("=")

    def _code_for_counter(self, key: bytes, counter: int) -> str:
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFF_FFFF
        otp = binary % (10 ** self.cfg.digits)
        return str(otp).zfill(self.cfg.digits)

    def generate_code(self, secret: str, at: float | None = None) -> str:
        ts = self._clock.now() if at is None else at
        return self._code_for_counter(self._decode_secret(secret),
                                      int(ts) // self.cfg.period)

    @staticmethod
    def _decode_secret(secret: str) -> bytes:
        padding = "=" * (-len(secret) % 8)
        return base64.b32decode(secret + padding, casefold=True)

    # 校验主流程 -------------------------------------------------------------
    def verify(self, user_id: str, source: str, secret: str, code: str,
               timestamp: float | None = None) -> None:
        now = self._clock.now()
        ts = now if timestamp is None else float(timestamp)
        key = f"{user_id}:{source}"
        logger.info(
            "totp.verify start user=%s source=%s ts_provided=%s clock=%s code_len=%d",
            user_id, source, timestamp, now, len(code),
        )

        # 1) 时钟偏差（独立原因，不累计失败）
        if abs(now - ts) > self.cfg.max_timestamp_skew_seconds:
            logger.warning("totp time skew user=%s delta=%.1f", user_id, ts - now)
            raise errors.TOTPTimeSkew(
                f"时间戳偏差过大: {ts - now:.0f}s")

        current_counter = int(ts) // self.cfg.period
        key_bytes = self._decode_secret(secret)

        with self._store.lock():
            state = self._store.get_mfa_state(key) or _new_state(key)

            # 2) 锁定窗口优先：窗口内即使口令正确也拒绝
            if state.locked_until and now < state.locked_until:
                logger.warning(
                    "totp locked user=%s failures=%d unlock_in=%.1f",
                    user_id, state.failures, state.locked_until - now)
                raise errors.AccountLocked(
                    f"账号已锁定，{state.locked_until - now:.0f}s 后重试")
            if state.locked_until and now >= state.locked_until:
                # 窗口过期：计数与窗口清零，重新开始
                state = _new_state(key)

            # 3) 限流冷却窗口（仅减速；过期不清零，计数继续累计）
            if state.throttled_until and now < state.throttled_until:
                logger.info(
                    "totp throttled user=%s retry_in=%.1f",
                    user_id, state.throttled_until - now)
                raise errors.MFAThrottled(
                    f"验证过于频繁，{state.throttled_until - now:.0f}s 后重试")

            # 4) 候选时间步窗口内是否有匹配（常数时间比较）
            accepted_counter: int | None = None
            accepted_code = ""
            for step in range(-self.cfg.skew, self.cfg.skew + 1):
                counter = current_counter + step
                candidate = self._code_for_counter(key_bytes, counter)
                if hmac.compare_digest(candidate, code.strip()):
                    accepted_counter = counter
                    accepted_code = candidate
                    break

            # 5) 防重放：该时间步已被成功使用过
            last_used = self._store.get_totp_last_counter(user_id)
            replayed = (
                accepted_counter is not None
                and last_used is not None
                and accepted_counter <= last_used
            )

            if accepted_counter is None or replayed:
                reason = "replayed" if replayed else "incorrect"
                exc_cls = errors.TOTPCodeReplayed if replayed else errors.TOTPCodeIncorrect
                state = self._register_failure(state, now)
                self._store.save_mfa_state(state)
                logger.warning(
                    "totp reject user=%s reason=%s failures=%d locked_until=%s throttled_until=%s",
                    user_id, reason, state.failures,
                    state.locked_until > now, state.throttled_until > now)
                raise exc_cls()

            # 6) 成功：记录时间步，失败计数整体复位
            self._store.set_totp_last_counter(user_id, accepted_counter)
            self._store.reset_mfa_state(key)
            logger.info(
                "totp accept user=%s counter=%d scope=%s previous_failures_reset",
                user_id, accepted_counter, key)

    def _register_failure(self, state: MFAFailureState, now: float) -> MFAFailureState:
        state.failures += 1
        state.last_failure_at = now
        if state.failures >= self.cfg.max_attempts:
            state.locked_until = now + self.cfg.lock_seconds
            state.throttled_until = 0.0
        elif state.failures >= self.cfg.throttle_after:
            state.throttled_until = now + self.cfg.throttle_seconds
        return state
