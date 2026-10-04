"""Concurrency: step-up one-time code and revoke/refresh interleaving.

Two guarantees:

* N concurrent reauthentications presenting the *same* one-time code have
  exactly one winner; every loser sees ``totp_replay`` and the freshness
  window slides exactly once;
* a session terminated while a refresh rotation is in flight loses — the
  refresh comes back ``refresh_token_revoked``; a refresh committed just
  before termination succeeds and its successor is nevertheless killed
  (whole-family termination). A sibling session is never affected.
"""
import threading

import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service
from tests.test_concurrent_refresh import BarrierService
from tests.test_concurrent_reauth_replay import ReauthBarrierService
from tests.test_sessions import login


def _barrier_service():
    base, clock = build_service(reauth_freshness=40.0)
    svc = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=300.0, refresh_ttl=3600.0, reauth_freshness=40.0,
    )
    return svc, clock


def _reauth_gate_service(parties: int):
    base, clock = build_service(reauth_freshness=40.0)
    svc = ReauthBarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=300.0, refresh_ttl=3600.0,
        reauth_freshness=40.0, parties=parties,
    )
    return svc, clock


def test_concurrent_reauth_same_code_single_winner_window_once():
    n = 8
    service, clock = _reauth_gate_service(n)
    tokens = login(service)                     # consumes TOTP step 0
    ctx = service.authenticate(tokens.access_token)
    clock.advance(31.0)                         # next TOTP step
    code = service.totp_provisioning_code("alice", clock.now())

    results: list[object] = []
    lock = threading.Lock()

    def attempt():
        try:
            out = service.reauthenticate(ctx, code)
            with lock:
                results.append(("ok", out.fresh_until))
        except AuthError as exc:
            with lock:
                results.append(("err", exc.code))

    threads = [threading.Thread(target=attempt) for _ in range(n)]
    for t in threads:
        t.start()
    # Deterministic: wait until every request has validated its code, then
    # release them all into the consume decision at the same instant.
    service.wait_all_validated()
    service.release()
    for t in threads:
        t.join(timeout=5.0)
        assert not t.is_alive(), "reauth thread hung"

    oks = [r for r in results if r[0] == "ok"]
    errs = [r[1] for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert errs == [ErrorCode.TOTP_REPLAY] * (n - 1), results
    # single slide: exactly one freshness anchor recorded
    assert oks[0][1] == clock.now() + 40.0
    state = service.store.get_mfa_state(ctx.session_id)
    assert state[0] == clock.now()
    assert len(state[1]) == 2  # login step + one reauth step


def test_refresh_committed_then_terminated_kills_successor_too():
    service, _ = build_service()
    victim = login(service, source="web")
    sibling = login(service, source="mobile")
    victim_ctx = service.authenticate(victim.access_token)

    rotated = service.refresh(victim.refresh_token)
    service.terminate_session(victim_ctx, victim_ctx.session_id)

    # the freshly minted successor pair is dead as well (family revoke)
    with pytest.raises(AuthError) as exc:
        service.refresh(rotated.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED
    with pytest.raises(AuthError) as exc:
        service.authenticate(rotated.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    # sibling untouched
    assert service.authenticate(sibling.access_token).session_id == \
        service.keyring.verify(sibling.access_token).sid


def test_terminate_while_refresh_in_flight_revokes_the_refresh():
    service, clock = _barrier_service()
    victim = login(service, source="web")
    sibling = login(service, source="mobile")
    victim_ctx = service.authenticate(victim.access_token)
    sibling_ctx = service.authenticate(sibling.access_token)
    jti = service.keyring.verify(victim.refresh_token).jti

    holder: dict[str, object] = {}

    def winner():
        try:
            holder["result"] = service.refresh(victim.refresh_token)
        except AuthError as exc:
            holder["result"] = exc.code

    t = threading.Thread(target=winner)
    t.start()
    service.wait_until_claimed(jti)         # refresh claimed, not committed

    # Termination lands entirely inside the claim window and returns.
    service.terminate_session(victim_ctx, victim_ctx.session_id)

    service.open_gate()
    t.join(timeout=2.0)
    assert holder["result"] is ErrorCode.REFRESH_TOKEN_REVOKED, holder

    # no live refresh credential survived for the victim
    with pytest.raises(AuthError) as exc:
        service.refresh(victim.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED
    # sibling session is completely unaffected
    assert service.authenticate(sibling.access_token).session_id == sibling_ctx.session_id
    rotated = service.refresh(sibling.refresh_token)
    assert service.authenticate(rotated.access_token).session_id == sibling_ctx.session_id


def test_concurrent_logout_others_is_stable():
    # Repeated sensitive ops while fresh must all agree and never corrupt
    # counters or terminate the acting session.
    service, _ = build_service()
    current = login(service, source="web")
    others = [login(service, source=f"dev{i}") for i in range(4)]
    ctx = service.authenticate(current.access_token)

    counts: list[int] = []
    lock = threading.Lock()

    def sweep():
        try:
            n = service.logout_other_sessions(ctx)
            with lock:
                counts.append(n)
        except AuthError as exc:
            with lock:
                counts.append(-1)

    threads = [threading.Thread(target=sweep) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=2.0)

    # exactly one sweep sees the 4 sessions; all later sweeps see zero,
    # and no call is rejected (MFA is fresh)
    assert sorted(counts) == [0, 0, 0, 0, 0, 4], counts
    # acting session survives every sweep
    assert service.authenticate(current.access_token).session_id == ctx.session_id
    for tokens in others:
        with pytest.raises(AuthError) as exc:
            service.authenticate(tokens.access_token)
        assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
