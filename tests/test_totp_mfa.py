"""TOTP 二次验证与失败防护测试。"""

from __future__ import annotations

import logging

import pytest

from auth import errors
from auth.store import InMemoryStore
from auth.totp import TOTPVerifier


@pytest.fixture
def env(clock, config):
    store = InMemoryStore()
    verifier = TOTPVerifier(store, clock, config)
    secret = TOTPVerifier.generate_secret()
    return store, verifier, secret


def _fail(verifier, secret, user="u1", source="web", code="000000"):
    with pytest.raises(errors.TOTPCodeIncorrect):
        verifier.verify(user, source, secret, code)


def test_correct_code_accepted_and_logged(env, caplog):
    _, verifier, secret = env
    code = verifier.generate_code(secret)
    with caplog.at_level(logging.INFO, logger="auth.totp"):
        verifier.verify("u1", "web", secret, code)
    assert any("totp accept" in r.message and "u1" in r.message for r in caplog.records)


def test_replay_same_window_rejected_and_counts(env):
    _, verifier, secret = env
    code = verifier.generate_code(secret)
    verifier.verify("u1", "web", secret, code)
    with pytest.raises(errors.TOTPCodeReplayed):
        verifier.verify("u1", "web", secret, code)


def test_skew_window_accepts_adjacent_step(env, clock):
    _, verifier, secret = env
    # 上一个时间步的口令（skew=1 允许）
    code = verifier.generate_code(secret, at=clock.now() - 30)
    verifier.verify("u1", "web", secret, code)


def test_clock_skew_distinguishable_and_not_counted(env, clock):
    _, verifier, secret = env
    far_future = clock.now() + 10_000
    with pytest.raises(errors.TOTPTimeSkew):
        verifier.verify("u1", "web", secret, "123456", timestamp=far_future)
    # 时钟偏差不计失败：紧接着一次错误应是 incorrect 而非 throttle
    with pytest.raises(errors.TOTPCodeIncorrect):
        verifier.verify("u1", "web", secret, "000000")


def test_throttle_after_threshold(env):
    _, verifier, secret = env
    # 3 次错误越阈（每次返回 incorrect），第 4 次请求被限流
    for _ in range(3):
        _fail(verifier, secret)
    with pytest.raises(errors.MFAThrottled):
        verifier.verify("u1", "web", secret, "000000")
    # 冷却窗口内即使口令正确也不放行
    code = verifier.generate_code(secret)
    with pytest.raises(errors.MFAThrottled):
        verifier.verify("u1", "web", secret, code)


def test_throttle_expiry_keeps_counter(env, clock):
    _, verifier, secret = env
    for _ in range(3):
        _fail(verifier, secret)
    clock.advance(61)
    # 冷却过期不复位计数：再错 2 次即达到锁定阈值 5
    _fail(verifier, secret)  # f=4
    with pytest.raises(errors.MFAThrottled):  # 失败刷新冷却 -> 紧接请求被限流
        verifier.verify("u1", "web", secret, "000000")
    clock.advance(61)
    _fail(verifier, secret)  # f=5，越锁定阈值（本次仍是 incorrect）
    # 此后任何请求（即使口令正确）都被锁定拒绝
    with pytest.raises(errors.AccountLocked):
        verifier.verify("u1", "web", secret, verifier.generate_code(secret))


def test_lockout_boundary_edges(env, clock, caplog):
    _, verifier, secret = env
    _drive_to_locked(verifier, secret, clock)
    # t = 299 仍锁定
    clock.advance(299)
    with pytest.raises(errors.AccountLocked):
        verifier.verify("u1", "web", secret, verifier.generate_code(secret))
    # t = 300 窗口过期：计数复位，当前正确口令放行
    clock.advance(1)
    with caplog.at_level(logging.INFO, logger="auth.totp"):
        verifier.verify("u1", "web", secret, verifier.generate_code(secret))
    assert any("totp accept" in r.message for r in caplog.records)
    # 复位后重新计数，不会立刻锁定
    _fail(verifier, secret)


def _drive_to_locked(verifier, secret, clock, failures=5):
    n = 0
    while n < failures:
        try:
            verifier.verify("u1", "web", secret, "000000")
        except errors.TOTPCodeIncorrect:
            n += 1
        except errors.MFAThrottled:
            clock.advance(61)  # 等冷却过去再继续累计


def test_success_resets_failure_counter(env, clock):
    _, verifier, secret = env
    _fail(verifier, secret)
    _fail(verifier, secret)
    # 成功一次，计数清零
    verifier.verify("u1", "web", secret, verifier.generate_code(secret))
    # 再来 3 次错误才到限流阈值（而非 1 次）
    _fail(verifier, secret)
    _fail(verifier, secret)
    _fail(verifier, secret)
    with pytest.raises(errors.MFAThrottled):
        verifier.verify("u1", "web", secret, "000000")


def test_failures_isolated_by_source(env):
    _, verifier, secret = env
    # web 连续错误，api 不受影响
    for _ in range(3):
        _fail(verifier, secret, source="web")
    with pytest.raises(errors.MFAThrottled):
        verifier.verify("u1", "web", secret, "000000")
    # 另一来源独立计数，正确口令放行
    verifier.verify("u1", "api", secret, verifier.generate_code(secret))
