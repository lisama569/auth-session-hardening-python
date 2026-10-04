"""Store-level atomicity: refresh claim/rotation and MFA consume."""
import threading

import pytest

from auth.clock import FixedClock
from auth.store import MfaConsumeResult, RefreshRecord, RefreshState, Store


def _make_record(now=1000.0):
    return RefreshRecord(
        jti="rt-1", family_id="fam-1", session_id="sess-1", user_id="u1",
        issued_at=now, expires_at=now + 999,
    )


def test_claim_is_exclusive_under_contention():
    store = Store(clock=FixedClock(1000.0))
    store.add_refresh(_make_record())
    winners = []
    barrier = threading.Barrier(8)

    def claim():
        barrier.wait()
        try:
            store.mark_inflight("rt-1")
            winners.append(1)
        except LookupError:
            pass

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(winners) == 1


def test_replace_requires_prior_claim():
    store = Store(clock=FixedClock(1000.0))
    store.add_refresh(_make_record())
    successor = RefreshRecord(
        jti="rt-2", family_id="fam-1", session_id="sess-1", user_id="u1",
        issued_at=1000.0, expires_at=2000.0,
    )
    # Not claimed yet -> commit must fail.
    with pytest.raises(LookupError):
        store.replace_refresh("rt-1", successor)
    # After claim, commit succeeds exactly once.
    store.mark_inflight("rt-1")
    store.replace_refresh("rt-1", successor)
    with pytest.raises(LookupError):
        store.replace_refresh("rt-1", successor)
    old = store.get_refresh("rt-1")
    assert old.state is RefreshState.ROTATED
    assert old.successor_jti == "rt-2"


def test_revoke_family_covers_all_members():
    store = Store(clock=FixedClock(1000.0))
    store.add_refresh(_make_record())
    store.add_refresh(RefreshRecord(
        jti="rt-2", family_id="fam-1", session_id="sess-1", user_id="u1",
        issued_at=1001.0, expires_at=2000.0,
    ))
    store.add_refresh(RefreshRecord(
        jti="rt-other", family_id="fam-2", session_id="sess-1", user_id="u1",
        issued_at=1001.0, expires_at=2000.0,
    ))
    store.revoke_family("fam-1", "test", now=1002.0)
    assert store.get_refresh("rt-1").state is RefreshState.REVOKED
    assert store.get_refresh("rt-2").state is RefreshState.REVOKED
    assert store.get_refresh("rt-other").state is RefreshState.ACTIVE


# ----------------------------------------------------------------- MFA ledger
def test_consume_mfa_step_is_single_winner_under_contention():
    store = Store(clock=FixedClock(1000.0))
    s = store.create_session("u1")
    outcomes = []
    barrier = threading.Barrier(8)

    def consume():
        barrier.wait()
        outcomes.append(store.consume_mfa_step("u1", s.session_id, 1000.0, 42))

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(MfaConsumeResult.OK) == 1
    assert outcomes.count(MfaConsumeResult.REPLAY) == 7
    # the ledger and the session mirror agree: the step is present once
    assert store.get_consumed_mfa_steps("u1") == frozenset({42})
    anchor, consumed = store.get_mfa_state(s.session_id)
    assert anchor == 1000.0
    assert consumed == frozenset({42})


def test_consume_mfa_step_is_user_scoped_across_sessions():
    store = Store(clock=FixedClock(1000.0))
    a = store.create_session("u1", "web")
    b = store.create_session("u1", "mobile")
    other = store.create_session("u2", "cli")

    assert store.consume_mfa_step("u1", a.session_id, 1000.0, 7) is MfaConsumeResult.OK
    # same step in a sibling session of the same user -> replay, no anchor move
    assert store.consume_mfa_step("u1", b.session_id, 1001.0, 7) is MfaConsumeResult.REPLAY
    assert store.get_mfa_state(b.session_id)[0] is None
    # a different user may consume the same absolute step independently
    assert store.consume_mfa_step("u2", other.session_id, 1000.0, 7) is MfaConsumeResult.OK
    # a replay against a missing/revoked session burns nothing
    assert store.consume_mfa_step("u1", "nope", 1002.0, 8) is MfaConsumeResult.SESSION_GONE
    assert 8 not in store.get_consumed_mfa_steps("u1")
    store.revoke_session(a.session_id, "x")
    assert store.consume_mfa_step("u1", a.session_id, 1003.0, 9) is MfaConsumeResult.SESSION_GONE
    assert 9 not in store.get_consumed_mfa_steps("u1")
