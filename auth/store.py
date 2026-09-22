"""内存持久化层：账号、刷新凭据家族、撤销列表、TOTP 失败计数。

线程安全（:class:`RLock` 可重入），刷新轮换等"读-判-写"序列在
:meth:`InMemoryStore.lock` 内原子完成，保证并发下只有一次成功。
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class StoredUser:
    """服务端持久化的用户记录（权限以这里的数据为唯一权威）。"""

    user_id: str
    username: str
    password_hash: str
    roles: list[str] = field(default_factory=list)
    scopes: list[str] = field(default_factory=list)
    totp_secret: str | None = None


@dataclass
class RefreshTokenRecord:
    """刷新凭据的服务端持久化形态。"""

    jti: str
    family_id: str
    user_id: str
    issued_at: float
    expires_at: float
    used: bool = False
    revoked: bool = False
    revoke_reason: str = ""

    @property
    def active(self) -> bool:
        return not self.used and not self.revoked


@dataclass
class MFAFailureState:
    """按 账号 + 来源 维度累计的失败状态。"""

    key: str
    failures: int = 0
    locked_until: float = 0.0
    throttled_until: float = 0.0
    last_failure_at: float = 0.0


class InMemoryStore:
    def __init__(self) -> None:
        self._lock = RLock()
        self._users_by_id: dict[str, StoredUser] = {}
        self._users_by_username: dict[str, StoredUser] = {}
        self._refresh_tokens: dict[str, RefreshTokenRecord] = {}
        # jti -> 过期时间；访问凭据即使短期，撤销也要在其寿命内可查
        self._revoked_access: dict[str, float] = {}
        self._mfa_states: dict[str, MFAFailureState] = {}
        # user_id -> 上一次成功使用的 TOTP 时间步（防重放）
        self._totp_last_counter: dict[str, int] = {}

    @contextmanager
    def lock(self) -> Iterator[None]:
        """持锁执行临界区（可重入）。"""
        with self._lock:
            yield

    # 用户 ----------------------------------------------------------------
    def upsert_user(self, user: StoredUser) -> None:
        with self._lock:
            self._users_by_id[user.user_id] = user
            self._users_by_username[user.username] = user

    def get_user_by_username(self, username: str) -> StoredUser | None:
        with self._lock:
            return self._users_by_username.get(username)

    def get_user_by_id(self, user_id: str) -> StoredUser | None:
        with self._lock:
            return self._users_by_id.get(user_id)

    # 刷新凭据 -------------------------------------------------------------
    def save_refresh_token(self, record: RefreshTokenRecord) -> None:
        with self._lock:
            self._refresh_tokens[record.jti] = record

    def get_refresh_token(self, jti: str) -> RefreshTokenRecord | None:
        with self._lock:
            return self._refresh_tokens.get(jti)

    def revoke_family(self, family_id: str, reason: str) -> None:
        """撤销整个刷新家族（登出/重用检测触发）。"""
        with self._lock:
            for rec in self._refresh_tokens.values():
                if rec.family_id == family_id and not rec.revoked:
                    rec.revoked = True
                    rec.revoke_reason = reason

    def revoke_all_refresh_tokens(self, reason: str) -> None:
        """撤销全部刷新家族（签名密钥轮换时调用）。"""
        with self._lock:
            for rec in self._refresh_tokens.values():
                if not rec.revoked:
                    rec.revoked = True
                    rec.revoke_reason = reason

    # 访问凭据撤销 ----------------------------------------------------------
    def revoke_access_token(self, jti: str, expires_at: float) -> None:
        with self._lock:
            self._revoked_access[jti] = expires_at

    def sweep_expired_access_revocations(self, now: float) -> None:
        """按调用方给定的时间（注入时钟）清理已自然过期的撤销记录。"""
        with self._lock:
            dead = [j for j, exp in self._revoked_access.items() if exp <= now]
            for j in dead:
                del self._revoked_access[j]

    def is_access_token_revoked(self, jti: str) -> bool:
        with self._lock:
            return jti in self._revoked_access

    # MFA 限流/锁定 --------------------------------------------------------
    def get_mfa_state(self, key: str) -> MFAFailureState | None:
        with self._lock:
            return self._mfa_states.get(key)

    def get_or_create_mfa_state(self, key: str) -> MFAFailureState:
        with self._lock:
            state = self._mfa_states.get(key)
            if state is None:
                state = MFAFailureState(key=key)
                self._mfa_states[key] = state
            return state

    def save_mfa_state(self, state: MFAFailureState) -> None:
        with self._lock:
            self._mfa_states[state.key] = state

    def reset_mfa_state(self, key: str) -> None:
        """成功验证后按明确规则复位：计数与所有窗口清零。"""
        with self._lock:
            self._mfa_states.pop(key, None)

    # TOTP 防重放 -----------------------------------------------------------
    def get_totp_last_counter(self, user_id: str) -> int | None:
        with self._lock:
            return self._totp_last_counter.get(user_id)

    def set_totp_last_counter(self, user_id: str, counter: int) -> None:
        with self._lock:
            self._totp_last_counter[user_id] = counter

