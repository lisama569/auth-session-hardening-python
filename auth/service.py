"""认证服务编排：登录、MFA 校验、刷新、登出、入口鉴权。

关键不变量：

* 登录/刷新签发的访问凭据，其权限一律由**服务端持久化用户记录**重算
  （``resolve_scopes``），不信任刷新凭据或请求中的任何权限声明；
* MFA 挑战令牌（mfa_token）是绑定 user_id 与 source 的短期签名令牌，
  签名密钥轮换后立即失效；
* 登出同时撤销刷新家族与（可选上报的）访问凭据。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from . import authz, errors, security
from .store import InMemoryStore, StoredUser
from .timeutil import Clock
from .tokens import ACCESS_TOKEN_TTL, TokenAuthority, TokenPair
from .totp import TOTPVerifier

logger = logging.getLogger("auth.service")

MFA_TOKEN_TTL = 5 * 60


@dataclass
class LoginResult:
    """登录结果：要么直接得到凭据对，要么需要 MFA。"""

    mfa_required: bool
    mfa_token: str | None = None
    user_id: str | None = None
    pair: TokenPair | None = None


@dataclass
class SessionView:
    """对外的凭据视图（字符串）。"""

    access_token: str
    refresh_token: str
    expires_in: int
    token_type: str = "Bearer"
    scopes: list[str] = field(default_factory=list)


def _pair_to_view(pair: TokenPair, ttl: int) -> SessionView:
    return SessionView(
        access_token=pair.access.token,
        refresh_token=pair.refresh.token,
        expires_in=ttl,
        scopes=list(pair.access.scopes),
    )


class AuthService:
    def __init__(self, store: InMemoryStore, tokens: TokenAuthority,
                 totp: TOTPVerifier, clock: Clock) -> None:
        self._store = store
        self._tokens = tokens
        self._totp = totp
        self._clock = clock

    # 用户管理（种子数据/测试用） -------------------------------------------
    def register(self, user_id: str, username: str, password: str,
                 roles: list[str] | None = None,
                 scopes: list[str] | None = None,
                 totp_secret: str | None = None) -> StoredUser:
        user = StoredUser(
            user_id=user_id,
            username=username,
            password_hash=security.hash_password(password),
            roles=list(roles or []),
            scopes=list(scopes or []),
            totp_secret=totp_secret,
        )
        self._store.upsert_user(user)
        return user

    # 登录 ------------------------------------------------------------------
    def login(self, username: str, password: str, source: str) -> LoginResult:
        logger.info("login username=%s source=%s", username, source)
        user = self._store.get_user_by_username(username)
        # 用户不存在与密码错误不可区分，统一 invalid_credentials
        if user is None or not security.verify_password(password, user.password_hash):
            logger.warning("login rejected username=%s reason=invalid_credentials", username)
            raise errors.InvalidCredentials()
        if user.totp_secret:
            mfa_token = self._tokens.issue_inner_token(
                "mfa_challenge", user.user_id, MFA_TOKEN_TTL,
                extra={"source": source})
            logger.info("login mfa_required user=%s source=%s", user.user_id, source)
            return LoginResult(mfa_required=True, mfa_token=mfa_token, user_id=user.user_id)
        pair = self._issue_for_user(user)
        logger.info("login issued user=%s scopes=%s", user.user_id, pair.access.scopes)
        return LoginResult(mfa_required=False, user_id=user.user_id, pair=pair)

    def verify_mfa(self, mfa_token: str, code: str,
                   timestamp: float | None = None) -> LoginResult:
        payload = self._tokens.verify_inner_token(mfa_token, "mfa_challenge")
        user = self._store.get_user_by_id(payload["sub"])
        if user is None or not user.totp_secret:
            raise errors.InvalidMFAToken()
        source = str(payload.get("source", "unknown"))
        logger.info("verify_mfa user=%s source=%s", user.user_id, source)
        # 失败/锁定/重放/时钟偏差均由此处抛出可区分异常
        self._totp.verify(user.user_id, source, user.totp_secret, code, timestamp)
        pair = self._issue_for_user(user)
        logger.info("verify_mfa issued user=%s scopes=%s", user.user_id, pair.access.scopes)
        return LoginResult(mfa_required=False, user_id=user.user_id, pair=pair)

    # 刷新 ------------------------------------------------------------------
    def refresh(self, refresh_token: str) -> SessionView:
        """轮换刷新凭据。新访问凭据权限由服务端当前用户记录重算。"""
        # 先解析拿 user_id（失败抛 refresh_* 可区分异常），再以服务端权限重算
        # 这里 rotate 需要 scopes；为保持"解析-置位"原子性，由 authority 判定，
        # 但 scopes 在持锁外先查用户（用户记录不参与竞态安全）。
        user_id = self._peek_refresh_subject(refresh_token)
        user = self._store.get_user_by_id(user_id)
        if user is None:
            raise errors.RefreshTokenInvalid("主体不存在")
        effective = authz.resolve_scopes(user.roles, user.scopes)
        pair = self._tokens.rotate(refresh_token, scopes=sorted(effective))
        logger.info("refresh rotated user=%s new_jti=%s scopes=%s",
                    user_id, pair.access.jti, pair.access.scopes)
        return _pair_to_view(pair, ACCESS_TOKEN_TTL)

    def _peek_refresh_subject(self, refresh_token: str) -> str:
        # 复用 authority 的解码（含旧 kid/坏签名 -> refresh_token_invalid）
        _, payload = self._tokens._decode_refresh(refresh_token)  # noqa: SLF001
        return str(payload["sub"])

    # 登出 ------------------------------------------------------------------
    def logout(self, refresh_token: str, access_token: str | None = None) -> None:
        family_id = self._tokens.revoke_session(refresh_token)
        if access_token:
            self._tokens.revoke_access_token(access_token)
        logger.info("logout family=%s access_revoked=%s", family_id, access_token is not None)

    # 资源存在性（演示用：doc- 前缀视为存在；可替换为真实资源存储） --------------
    def resource_exists(self, doc_id: str) -> bool:
        return isinstance(doc_id, str) and doc_id.startswith("doc-") and len(doc_id) > 4

    # 入口鉴权（所有 HTTP 入口共用） -----------------------------------------
    def authenticate(self, access_token: str) -> authz.Principal:
        """校验访问凭据并以服务端权限构建主体。"""
        at = self._tokens.verify_access_token(access_token)
        user = self._store.get_user_by_id(at.user_id)
        if user is None:
            raise errors.AccessTokenInvalid("主体不存在")
        return authz.build_principal(
            user.user_id, user.roles, user.scopes,
            token_scopes=at.scopes, source="access_token")

    def require_scope(self, access_token: str, required_scope: str,
                      resource: str = "", *, mask: bool = True) -> authz.Principal:
        principal = self.authenticate(access_token)
        if mask:
            authz.authorize_or_404(principal, required_scope, resource=resource)
        else:
            authz.authorize(principal, required_scope, resource=resource)
        return principal

    def _issue_for_user(self, user: StoredUser):
        effective = sorted(authz.resolve_scopes(user.roles, user.scopes))
        return self._tokens.issue(user.user_id, effective)
