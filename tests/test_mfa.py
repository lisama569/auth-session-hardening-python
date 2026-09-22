"""TOTP verification, failure accounting, rate limiting and locking."""
import pytest

from auth.clock import FixedClock
from auth.mfa import TotpResult, TotpVerifier


@pytest.fixture()
def rig():
    clock = FixedClock(1_000_000.0)
    verifier = TotpVerifier(
        clock=clock,
        rate_limit_threshold=3,
        rate_limit_window_seconds=60.0,
        lock_threshold=5,
        lock_window_seconds=300.0,
    )
    secret = verifier.generate_secret()
    return clock, verifier, secret


def test_correct_code_succeeds(rig):
    clock, verifier, secret = rig
    code = verifier.code_at(secret, clock.now())
    status = verifier.verify("u1", "web", secret, code)
    assert status.result is TotpResult.OK
    assert status.failures == 0


def test_wrong_code_accumulates_failures(rig):
    clock, verifier, secret = rig
    s1 = verifier.verify("u1", "web", secret, "000000")
    s2 = verifier.verify("u1", "web", secret, "111111")
    assert s1.result is TotpResult.INVALID and s1.failures == 1
    assert s2.result is TotpResult.INVALID and s2.failures == 2


def test_rate_limit_triggered_at_threshold(rig):
    clock, verifier, secret = rig
    for _ in range(2):
        verifier.verify("u1", "web", secret, "000000")
    third = verifier.verify("u1", "web", secret, "000000")
    assert third.result is TotpResult.RATE_LIMITED
    assert third.retry_after == pytest.approx(60.0)

    # Even the correct code is refused during the rate-limit window.
    good = verifier.code_at(secret, clock.now())
    blocked = verifier.verify("u1", "web", secret, good)
    assert blocked.result is TotpResult.RATE_LIMITED


def test_lock_window_rejects_correct_code_until_boundary(rig):
    clock, verifier, secret = rig
    for _ in range(4):
        verifier.verify("u1", "web", secret, "000000")
    fifth = verifier.verify("u1", "web", secret, "000000")
    assert fifth.result is TotpResult.LOCKED
    assert fifth.locked_until == clock.now() + 300.0

    # Correct code inside the window is still rejected.
    clock.advance(299.0)
    good = verifier.code_at(secret, clock.now())
    inside = verifier.verify("u1", "web", secret, good)
    assert inside.result is TotpResult.LOCKED

    # Boundary is exclusive: at exactly locked_until the lock is gone.
    clock.advance(1.0)
    good = verifier.code_at(secret, clock.now())
    at_boundary = verifier.verify("u1", "web", secret, good)
    assert at_boundary.result is TotpResult.OK
    assert at_boundary.failures == 0


def test_success_resets_counter(rig):
    clock, verifier, secret = rig
    verifier.verify("u1", "web", secret, "000000")
    verifier.verify("u1", "web", secret, "000000")
    good = verifier.code_at(secret, clock.now())
    ok = verifier.verify("u1", "web", secret, good)
    assert ok.result is TotpResult.OK
    again = verifier.verify("u1", "web", secret, "000000")
    assert again.failures == 1  # counter restarted from zero


def test_failures_are_isolated_by_user_and_source(rig):
    clock, verifier, secret = rig
    verifier.verify("u1", "web", secret, "000000")
    verifier.verify("u1", "web", secret, "000000")
    other_source = verifier.verify("u1", "mobile", secret, "000000")
    other_user = verifier.verify("u2", "web", secret, "000000")
    assert other_source.failures == 1
    assert other_user.failures == 1


def test_clock_skew_is_distinguishable_from_invalid(rig):
    clock, verifier, secret = rig
    # 2 steps away: beyond tolerance (1) but within max skew (3).
    far_time = clock.now() + 2 * 30
    skew_code = verifier.code_at(secret, far_time)
    status = verifier.verify("u1", "web", secret, skew_code)
    assert status.result is TotpResult.CLOCK_SKEW
    assert status.failures == 1  # still a counted failure

    # Code at 4 steps away is a plain invalid code.
    too_far = clock.now() + 4 * 30
    far_code = verifier.code_at(secret, too_far)
    invalid = verifier.verify("u2", "web", secret, far_code)
    assert invalid.result is TotpResult.INVALID


def test_tolerance_window_accepts_neighboring_step(rig):
    clock, verifier, secret = rig
    # A code one period old is within tolerance.
    old_code = verifier.code_at(secret, clock.now() - 30)
    status = verifier.verify("u1", "web", secret, old_code)
    assert status.result is TotpResult.OK
    assert status.matched_step == -1
