"""访问凭据与可轮换刷新凭据的签发/校验/轮换。

凭据形态（均为自包含、HMAC-SHA256 签名的紧凑字符串，无外部服务依赖）::

    <header>.<payload>.<signature>

header/payload 均为 b64url 编码 JSON。header 含 ``kid``（密钥 id），
payload 含 jti/sub/scopes/iat/exp/family 等。刷新凭据额外在服务端
持久化其状态（是否已用/已撤销），因此即使签名合法，状态不合法也会被拒。
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from . import errors, security
from .store import InMemoryStore, RefreshTokenRecord
from .timeutil import Clock

ACCESS_TOKEN_TTL = 15 * 60          # 访问凭据：15 分钟短期
REFRESH_TOKEN_TTL = 7 * 24 * 3600   # 刷新凭据：7 天


@dataclass
class AccessToken:
    token: str
    jti: str
    kid: str
    user_id: str
    scopes: list[str]
    expires_at: float
    family_id: str = ""


@dataclass
class IssuedRefreshToken:
    token: str
    record: RefreshTokenRecord


@dataclass
class TokenPair:
    """一次签发/轮换得到的新凭据对。"""

    access: AccessToken
    refresh: IssuedRefreshToken


class TokenAuthority:
    """凭据签发/校验/轮换 + 签名密钥管理。"""

    def __init__(self, store: InMemoryStore, clock: Clock) -> None:
        self._store = store
        self._clock = clock
        self._lock = __import__("threading").RLock()
        # kid -> secret；只保留当前密钥，密钥轮换后旧 kid 立即无法验签
        self._keys: dict[str, str] = {}
        self._active_kid = self._load_new_key()

    # 密钥管理 --------------------------------------------------------------
    def _load_new_key(self) -> str:
        kid = secrets.token_hex(8)
        self._keys = {kid: secrets.token_hex(32)}
        return kid

    @property
    def active_kid(self) -> str:
        return self._active_kid

    def rotate_signing_key(self) -> str:
        """轮换签名密钥并使此前签发的所有凭据立即失效。

        旧密钥被删除：旧凭据验签时找不到 kid，一律视为无效；
        同时撤销现存全部刷新家族（防御性状态失效）。
        返回新 kid。
        """
        with self._lock:
            new_kid = self._load_new_key()
            self._active_kid = new_kid
            for rec in list(self._store._refresh_tokens.values()):  # noqa: SLF001
                if not rec.revoked:
                    rec.revoked = True
                    rec.revoke_reason = "signing_key_rotated"
            return new_kid

    # 编解码 ----------------------------------------------------------------
    def _encode(self, payload: dict) -> tuple[str, str, str]:
        kid = self._active_kid
        header = {"alg": "HS256", "kid": kid}
        h = security.b64url_encode(json.dumps(header, separators=(",", ":")).encode())
        p = security.b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        sig = security.hmac_sign(self._keys[kid].encode(), f"{h}.{p}")
        return h, p, sig

    def _decode(self, token: str) -> tuple[dict, dict]:
        parts = token.split(".")
        if len(parts) != 3:
            raise errors.AccessTokenInvalid("凭据格式错误")
        h, p, sig = parts
        try:
            header = json.loads(security.b64url_decode(h))
            payload = json.loads(security.b64url_decode(p))
        except (ValueError, TypeError) as exc:
            raise errors.AccessTokenInvalid("凭据编码错误") from exc
        kid = header.get("kid")
        secret = self._keys.get(kid) if kid else None
        if secret is None:
            # kid 不存在：密钥已轮换或凭据伪造
            raise errors.AccessTokenInvalid("签名密钥未知（可能已轮换）")
        expected = security.hmac_sign(secret.encode(), f"{h}.{p}")
        if not security.constant_time_equals(expected, sig):
            raise errors.AccessTokenInvalid("签名不匹配")
        return header, payload

    # 签发 ------------------------------------------------------------------
    def issue(self, user_id: str, scopes: list[str],
              family_id: str | None = None) -> TokenPair:
        """签发全新凭据对（新家族）；family_id 仅供轮换内部复用。"""
        now = self._clock.now()
        family = family_id or secrets.token_hex(16)
        # 访问凭据
        at_jti = secrets.token_hex(16)
        at_payload = {
            "jti": at_jti,
            "sub": user_id,
            "scopes": list(scopes),
            "iat": now,
            "exp": now + ACCESS_TOKEN_TTL,
            "family": family,
            "typ": "access",
        }
        h, p, sig = self._encode(at_payload)
        access = AccessToken(
            token=f"{h}.{p}.{sig}",
            jti=at_jti,
            kid=self._active_kid,
            user_id=user_id,
            scopes=list(scopes),
            expires_at=at_payload["exp"],
            family_id=family,
        )
        # 刷新凭据
        rt_jti = secrets.token_hex(16)
        rt_payload = {
            "jti": rt_jti,
            "sub": user_id,
            "iat": now,
            "exp": now + REFRESH_TOKEN_TTL,
            "family": family,
            "typ": "refresh",
        }
        rh, rp, rsig = self._encode(rt_payload)
        record = RefreshTokenRecord(
            jti=rt_jti,
            family_id=family,
            user_id=user_id,
            issued_at=now,
            expires_at=rt_payload["exp"],
        )
        self._store.save_refresh_token(record)
        refresh = IssuedRefreshToken(token=f"{rh}.{rp}.{rsig}", record=record)
        return TokenPair(access=access, refresh=refresh)

    # 访问凭据校验 -----------------------------------------------------------
    def verify_access_token(self, token: str) -> AccessToken:
        _, payload = self._decode(token)  # 无效/坏签名/旧 kid -> *_invalid
        if payload.get("typ") != "access":
            raise errors.AccessTokenInvalid("凭据类型错误")
        now = self._clock.now()
        if now >= float(payload["exp"]):
            raise errors.AccessTokenExpired()
        if self._store.is_access_token_revoked(payload["jti"]):
            raise errors.AccessTokenRevoked()
        return AccessToken(
            token=token,
            jti=payload["jti"],
            kid="",
            user_id=payload["sub"],
            scopes=list(payload.get("scopes", [])),
            expires_at=float(payload["exp"]),
            family_id=payload.get("family", ""),
        )

    # 刷新凭据：原子轮换 -----------------------------------------------------
    def rotate(self, refresh_token: str, scopes: list[str] | None = None) -> TokenPair:
        """用旧刷新凭据换新凭据对。

        并发安全："解析→状态判定→置 used→签发" 在存储层同一把锁内完成，
        因此同一刷新凭据并发/重复提交时恰好一个成功，其余抛
        :class:`RefreshTokenReused`。任何重用/撤销异常都会连带撤销整个家族。
        """
        # 签名/编码层校验（无需持锁）
        _, payload = self._decode_refresh(refresh_token)
        jti = payload["jti"]
        now = self._clock.now()
        with self._store.lock():
            record = self._store.get_refresh_token(jti)
            if record is None:
                raise errors.RefreshTokenInvalid("刷新凭据未登记")
            if record.revoked:
                # 已撤销家族中的凭据：登出、重用连带撤销或密钥轮换
                raise errors.RefreshTokenRevoked(record.revoke_reason or "revoked")
            if record.used:
                # 重放检测：撤销整个家族（含已签发的新凭据）
                self._store.revoke_family(record.family_id, "refresh_token_reuse")
                raise errors.RefreshTokenReused()
            if now >= record.expires_at:
                # 过期本身也使家族其余凭据作废，避免过期后继续轮换
                self._store.revoke_family(record.family_id, "refresh_token_expired")
                raise errors.RefreshTokenExpired()
            if payload["sub"] != record.user_id:
                self._store.revoke_family(record.family_id, "refresh_token_subject_mismatch")
                raise errors.RefreshTokenInvalid("主体不匹配")
            # 原子占位：先置 used 再签发，落败并发者只能看到 used=True
            record.used = True
            pair = self.issue(record.user_id, list(scopes or []),
                              family_id=record.family_id)
            # 新访问凭据在轮换瞬间仍有效；旧访问凭据由家族撤销在登出时处理
            return pair

    def _decode_refresh(self, token: str) -> tuple[dict, dict]:
        try:
            header, payload = self._decode(token)
        except errors.AccessTokenInvalid as exc:
            # 旧 kid（密钥轮换后）与坏签名字面统一为 invalid，
            # 但持久化状态可能给出更精确的 revoked 原因，这里先抛 invalid
            raise errors.RefreshTokenInvalid(str(exc)) from exc
        if payload.get("typ") != "refresh":
            raise errors.RefreshTokenInvalid("凭据类型错误")
        return header, payload

    # 登出 ------------------------------------------------------------------
    def revoke_session(self, refresh_token: str) -> str:
        """登出：撤销整个刷新家族。返回 family_id。

        旧刷新凭据立即失效；访问凭据因寿命短（15 分钟）自然失效，
        若客户端同时上报访问凭据 jti 可走 :meth:`revoke_access_token`。
        """
        _, payload = self._decode_refresh(refresh_token)
        family_id = payload["family"]
        self._store.revoke_family(family_id, "logout")
        return family_id

    def revoke_access_token(self, token: str) -> None:
        """显式撤销某个访问凭据（登出时调用，立即失效）。"""
        try:
            _, payload = self._decode(token)
        except errors.AccessTokenInvalid:
            return
        self._store.revoke_access_token(payload["jti"], float(payload["exp"]))
        self._store.sweep_expired_access_revocations(self._clock.now())


    # 内部短令牌（如登录后的 MFA 挑战令牌） -----------------------------------
    def issue_inner_token(self, typ: str, subject: str, ttl: float,
                          extra: dict | None = None) -> str:
        now = self._clock.now()
        payload = {"typ": typ, "sub": subject, "iat": now, "exp": now + ttl}
        if extra:
            payload.update(extra)
        jti = secrets.token_hex(16)
        payload["jti"] = jti
        h, p, sig = self._encode(payload)
        return f"{h}.{p}.{sig}"

    def verify_inner_token(self, token: str, expected_typ: str) -> dict:
        """校验内部令牌。密钥轮换后旧 kid 立即失效，过期抛 AccessTokenExpired。"""
        try:
            _, payload = self._decode(token)
        except errors.AccessTokenInvalid as exc:
            raise errors.InvalidMFAToken(str(exc)) from exc
        if payload.get("typ") != expected_typ:
            raise errors.InvalidMFAToken("令牌类型错误")
        if self._clock.now() >= float(payload["exp"]):
            raise errors.AccessTokenExpired("mfa_token 已过期")
        return payload
