"""时钟与密码/签名原语测试。"""

import pytest

from auth.security import (
    b64url_decode,
    b64url_encode,
    constant_time_equals,
    hash_password,
    sign,
    verify_password,
)
from auth.timeutil import Clock, FixedClock


def test_fixed_clock_advances():
    c = FixedClock()
    t0 = c.now()
    c.advance(30)
    assert c.now() == t0 + 30


def test_system_clock_cannot_advance():
    c = Clock()
    assert isinstance(c.now(), float)
    with pytest.raises(TypeError):
        c.advance(10)


def test_password_hash_roundtrip_and_salts():
    h1 = hash_password("hunter2")
    h2 = hash_password("hunter2")
    assert h1 != h2  # 随机盐
    assert verify_password("hunter2", h1)
    assert not verify_password("wrong", h1)
    assert not verify_password("hunter2", "garbage$1$a$b")


def test_b64url_roundtrip():
    for raw in (b"", b"\x00", b"\xff" * 5, b"hello"):
        assert b64url_decode(b64url_encode(raw)) == raw


def test_hmac_deterministic_and_key_sensitive():
    assert sign("payload", "key") == sign("payload", "key")
    assert sign("payload", "key") != sign("payload", "other")
    assert constant_time_equals("abc", "abc")
    assert not constant_time_equals("abc", "abd")
