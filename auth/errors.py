"""Domain error types.

Every security-relevant rejection carries a stable, distinguishable
``code`` so callers (and tests) can tell *why* a request was rejected.
"""
from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    # credentials / session
    INVALID_CREDENTIALS = "invalid_credentials"
    CHALLENGE_NOT_FOUND = "challenge_not_found"
    CHALLENGE_EXPIRED = "challenge_expired"
    ACCESS_TOKEN_INVALID = "access_token_invalid"
    ACCESS_TOKEN_EXPIRED = "access_token_expired"
    ACCESS_TOKEN_REVOKED = "access_token_revoked"
    REFRESH_TOKEN_INVALID = "refresh_token_invalid"
    REFRESH_TOKEN_EXPIRED = "refresh_token_expired"
    REFRESH_TOKEN_REVOKED = "refresh_token_revoked"
    REFRESH_TOKEN_REUSE = "refresh_token_reuse"
    REFRESH_TOKEN_CONCURRENT = "refresh_token_concurrent"
    SESSION_NOT_FOUND = "session_not_found"
    SESSION_REVOKED = "session_revoked"
    KEY_VERSION_STALE = "key_version_stale"

    # mfa
    MFA_NOT_ENROLLED = "mfa_not_enrolled"
    TOTP_INVALID = "totp_invalid"
    TOTP_CLOCK_SKEW = "totp_clock_skew"
    MFA_RATE_LIMITED = "mfa_rate_limited"
    MFA_LOCKED = "mfa_locked"

    # authorization
    FORBIDDEN = "forbidden"
    NOT_FOUND = "not_found"
    UNAUTHENTICATED = "unauthenticated"


class AuthError(Exception):
    """Base class for all authentication / authorization errors."""

    code: ErrorCode = ErrorCode.INVALID_CREDENTIALS

    def __init__(self, message: str | None = None, *, code: ErrorCode | None = None):
        if code is not None:
            self.code = code
        super().__init__(message or self.code.value)
