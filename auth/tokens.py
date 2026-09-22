"""Self-contained signed credentials (access / refresh tokens).

No external IdP or crypto service is involved: tokens are
``base64url(payload).base64url(hmac_sha256)`` values signed with the
current :class:`KeyRing` key. Each token carries a ``kid``; once the key
is rotated, tokens signed by an older key fail verification with a
distinguishable :class:`~auth.errors.AuthError` immediately.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from typing import Any

from auth.clock import Clock, SystemClock
from auth.errors import AuthError, ErrorCode


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


@dataclass(frozen=True)
class TokenClaims:
    jti: str
    typ: str  # "access" | "refresh"
    sub: str  # user id
    sid: str  # session id
    kid: str
    iat: float
    exp: float
    ver: int = 0
    scopes: frozenset[str] = field(default_factory=frozenset)

    def to_dict(self) -> dict[str, Any]:
        return {
            "jti": self.jti,
            "typ": self.typ,
            "sub": self.sub,
            "sid": self.sid,
            "kid": self.kid,
            "iat": self.iat,
            "exp": self.exp,
            "ver": self.ver,
            "scp": sorted(self.scopes),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TokenClaims":
        return cls(
            jti=str(data["jti"]),
            typ=str(data["typ"]),
            sub=str(data["sub"]),
            sid=str(data["sid"]),
            kid=str(data["kid"]),
            iat=float(data["iat"]),
            exp=float(data["exp"]),
            ver=int(data.get("ver", 0)),
            scopes=frozenset(data.get("scp", ())),
        )


class KeyRing:
    """Holds the *single* active signing key.

    Rotation discards the previous key entirely, so every credential
    signed with it stops validating.
    """

    def __init__(self, clock: Clock | None = None, key_size: int = 32) -> None:
        self._clock = clock or SystemClock()
        self._key_size = key_size
        self._key = secrets.token_bytes(key_size)
        self._kid = b64url_encode(secrets.token_bytes(8))

    @property
    def kid(self) -> str:
        return self._kid

    def rotate(self) -> str:
        """Generate a brand-new key; old tokens become invalid."""
        self._key = secrets.token_bytes(self._key_size)
        self._kid = b64url_encode(secrets.token_bytes(8))
        return self._kid

    def sign(self, claims: dict[str, Any]) -> str:
        # The active kid is always stamped by the signer itself.
        claims = dict(claims)
        claims["kid"] = self._kid
        payload = b64url_encode(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
        sig = hmac.new(self._key, payload.encode(), hashlib.sha256).digest()
        return f"{payload}.{b64url_encode(sig)}"

    def _invalid_code(self, typ: str | None) -> ErrorCode:
        return (
            ErrorCode.REFRESH_TOKEN_INVALID
            if typ == "refresh"
            else ErrorCode.ACCESS_TOKEN_INVALID
        )

    def _expired_code(self, typ: str | None) -> ErrorCode:
        return (
            ErrorCode.REFRESH_TOKEN_EXPIRED
            if typ == "refresh"
            else ErrorCode.ACCESS_TOKEN_EXPIRED
        )

    def verify(self, token: str) -> TokenClaims:
        """Validate signature, kid and exp; raise AuthError otherwise."""
        parts = token.split(".")
        if len(parts) != 2:
            raise AuthError(code=self._invalid_code(None))
        payload_b64, sig_b64 = parts
        try:
            signature = b64url_decode(sig_b64)
            body = json.loads(b64url_decode(payload_b64))
        except (ValueError, json.JSONDecodeError):
            raise AuthError(code=self._invalid_code(None))
        if not isinstance(body, dict):
            raise AuthError(code=self._invalid_code(None))

        expected_sig = hmac.new(self._key, payload_b64.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected_sig):
            # A payload that names a different kid is a retired-key token;
            # everything else is an outright invalid signature.
            if isinstance(body.get("kid"), str) and body["kid"] != self._kid:
                raise AuthError(
                    f"token signed by retired key {body['kid']!r}",
                    code=ErrorCode.KEY_VERSION_STALE,
                )
            raise AuthError(code=self._invalid_code(body.get("typ")))

        try:
            claims = TokenClaims.from_dict(body)
        except (KeyError, TypeError, ValueError):
            raise AuthError(code=self._invalid_code(body.get("typ")))

        if claims.kid != self._kid:
            raise AuthError(
                f"token signed by retired key {claims.kid!r}",
                code=ErrorCode.KEY_VERSION_STALE,
            )
        if claims.exp <= self._clock.now():
            raise AuthError(code=self._expired_code(claims.typ))
        return claims
