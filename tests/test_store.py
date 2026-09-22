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
