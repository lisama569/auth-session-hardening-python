"""统一错误类型。

每个业务错误都带稳定的 ``code``，调用方（含测试）可据此区分失败原因，
而不需要解析错误文案。
"""

from __future__ import annotations


class AuthError(Exception):
    """所有认证域错误的基类。"""

    code: str = "auth_error"
    http_status: int = 400

    def __init__(self, message: str | None = None) -> None:
        super().__init__(message or self.code)
        self.message = message or self.code


class InvalidCredentials(AuthError):
    """用户名/密码校验失败。"""

    code = "invalid_credentials"
    http_status = 401


class MFARequired(AuthError):
    """登录需要二次验证（携带 mfa_token 继续）。"""

    code = "mfa_required"
    http_status = 401


class InvalidMFAToken(AuthError):
    """mfa_token 无效或已过期。"""

    code = "invalid_mfa_token"
    http_status = 401


class TOTPCodeIncorrect(AuthError):
    """TOTP 口令不正确。"""

    code = "totp_incorrect"
    http_status = 401


class TOTPCodeReplayed(AuthError):
    """TOTP 口令在有效期内被重复使用。"""

    code = "totp_replayed"
    http_status = 401


class TOTPTimeSkew(AuthError):
    """TOTP 时间戳超出允许偏差窗口（可区分的时钟偏差结果）。"""

    code = "totp_time_skew"
    http_status = 401


class MFAThrottled(AuthError):
    """二次验证失败次数过多，触发限流冷却。"""

    code = "mfa_throttled"
    http_status = 429


class AccountLocked(AuthError):
    """账号在来源维度已被临时锁定。"""

    code = "account_locked"
    http_status = 423


class AccessTokenInvalid(AuthError):
    """访问凭据格式错误或签名无效。"""

    code = "access_token_invalid"
    http_status = 401


class AccessTokenExpired(AuthError):
    """访问凭据已过期。"""

    code = "access_token_expired"
    http_status = 401


class AccessTokenRevoked(AuthError):
    """访问凭据已被主动撤销（登出/密钥轮换）。"""

    code = "access_token_revoked"
    http_status = 401


class RefreshTokenInvalid(AuthError):
    """刷新凭据格式错误/不属于本系统。"""

    code = "refresh_token_invalid"
    http_status = 401


class RefreshTokenExpired(AuthError):
    """刷新凭据已过期。"""

    code = "refresh_token_expired"
    http_status = 401


class RefreshTokenReused(AuthError):
    """刷新凭据已被使用过（旧凭据再次提交，含并发竞态中的落败者）。"""

    code = "refresh_token_reused"
    http_status = 401


class RefreshTokenRevoked(AuthError):
    """刷新凭据已被撤销（登出/家族撤销/密钥轮换）。"""

    code = "refresh_token_revoked"
    http_status = 401


class Forbidden(AuthError):
    """已认证但权限不足。对外与资源不存在统一为 404（见 api 层）。"""

    code = "forbidden"
    http_status = 403


class NotFound(AuthError):
    """目标资源不存在。"""

    code = "not_found"
    http_status = 404
