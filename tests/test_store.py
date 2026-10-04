"""Store-level atomicity: refresh claim/rotation under threads."""
import threading

import pytest

from auth.clock import FixedClock
from auth.store import RefreshRecord, RefreshState, Store


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


# ---- MFA one-time step consumption: per-user, cross-session, atomic ----

def _store_with_two_sessions():
    store = Store(clock=FixedClock(1000.0))
    from auth.store import UserRecord
    store.upsert_user(UserRecord("alice", "h"))
    a = store.create_session("alice", "web")
    b = store.create_session("alice", "mobile")
    return store, a, b


def test_consume_mfa_step_is_one_time_across_sessions():
    from auth.store import MfaConsumeResult
    store, a, b = _store_with_two_sessions()

    assert store.consume_mfa_step(a.session_id, "alice", 1000.0, 10) is MfaConsumeResult.OK
    # same absolute step, different session of the same user -> replay,
    # and B's freshness anchor is never written
    assert store.consume_mfa_step(b.session_id, "alice", 1001.0, 10) \
        is MfaConsumeResult.STEP_REPLAYED
    assert store.get_mfa_state(b.session_id)[0] is None
    # a distinct step still succeeds on B
    assert store.consume_mfa_step(b.session_id, "alice", 1002.0, 11) is MfaConsumeResult.OK
    assert store.get_mfa_state(b.session_id)[0] == 1002.0
    # ledger is isolated per user
    c = store.create_session("carol", "web")
    assert store.consume_mfa_step(c.session_id, "carol", 1003.0, 10) is MfaConsumeResult.OK


def test_consume_mfa_step_rejected_for_missing_or_revoked_session():
    from auth.store import MfaConsumeResult
    store, a, _b = _store_with_two_sessions()
    assert store.consume_mfa_step("nope", "alice", 1000.0, 10) \
        is MfaConsumeResult.SESSION_GONE
    store.revoke_session(a.session_id, "test")
    assert store.consume_mfa_step(a.session_id, "alice", 1000.0, 12) \
        is MfaConsumeResult.SESSION_GONE
    assert 12 not in store.get_consumed_steps("alice")


def test_concurrent_consume_of_same_step_has_single_winner():
    from auth.store import MfaConsumeResult
    store, a, _b = _store_with_two_sessions()
    winners = []
    barrier = threading.Barrier(8)

    def consume():
        barrier.wait()
        result = store.consume_mfa_step(a.session_id, "alice", 1000.0, 20)
        if result is MfaConsumeResult.OK:
            winners.append(1)

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(winners) == 1
    # ledger and per-session history both contain the step exactly once
    assert store.get_consumed_steps("alice") == frozenset({20})
    assert store.get_mfa_state(a.session_id)[1] == frozenset({20})


def test_record_mfa_login_is_idempotent_for_repeated_step():
    store, a, b = _store_with_two_sessions()
    # two logins presenting the same step both succeed (multi-device) but
    # the step lands in the user ledger exactly once
    assert store.record_mfa_login(a.session_id, "alice", 1000.0, 5) is True
    assert store.record_mfa_login(b.session_id, "alice", 1000.0, 5) is True
    assert store.get_consumed_steps("alice") == frozenset({5})
    assert store.get_mfa_state(a.session_id)[0] == 1000.0
    assert store.get_mfa_state(b.session_id)[0] == 1000.0
