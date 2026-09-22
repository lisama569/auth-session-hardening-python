"""密码哈希与凭据签名原语（纯标准库实现，无外部依赖）。"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

_PBKDF2_ALGO = "pbkdf2_sha256"
_PBKDF2_ITERATIONS = 200_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 加盐哈希。

    存储格式：``pbkdf2_sha256$<迭代次数>$<salt_b64url>$<dk_b64url>``
    """
    salt = os.urandom(_SALT_BYTES)
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, _PBKDF2_ITERATIONS
    )
    return "$".join(
        (_PBKDF2_ALGO, str(_PBKDF2_ITERATIONS), b64url_encode(salt), b64url_encode(dk))
    )


def verify_password(password: str, stored_hash: str) -> bool:
    """常数时间校验密码，格式不匹配时安全返回 False。"""
    try:
        algo, iterations_s, salt_s, dk_s = stored_hash.split("$", 3)
        if algo != _PBKDF2_ALGO:
            return False
        iterations = int(iterations_s)
        salt = b64url_decode(salt_s)
        expected = b64url_decode(dk_s)
    except (ValueError, TypeError):
        return False
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate, expected)


def b64url_encode(data: bytes) -> str:
    """无填充 base64url 编码。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    """解码无填充 base64url。"""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def hmac_sign(key: bytes, message: str) -> str:
    """对字符串消息做 HMAC-SHA256，返回 b64url 签名。"""
    digest = hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()
    return b64url_encode(digest)


def sign(payload: str, secret: str) -> str:
    """HMAC-SHA256 签名（兼容旧签名位置）。"""
    return hmac_sign(secret.encode("utf-8"), payload)


def constant_time_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a, b)
