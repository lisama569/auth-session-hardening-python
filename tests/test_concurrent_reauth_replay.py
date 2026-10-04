"""One-time TOTP code reuse: simultaneous and cross-session replay.

These tests reproduce two regressions *deterministically* — no sleeps and
no reliance on natural thread races:

* N requests presenting the same one-time code rendezvous on a
  ``threading.Barrier`` after the code validated but before the consume
  decision, then hit the decision together. Exactly one may win; the
  rest must get ``totp_replay`` and the freshness window slides once.
* The same code consumed in one login session (login or a prior step-up)
  can never authorize a sensitive operation from another session of the
  same user — cross-session replay is rejected with ``totp_replay``,
  distinguishable from ``totp_invalid`` and ``mfa_rate_limited`` /
  ``mfa_locked``.
"""
import threading

import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service
from tests.test_sessions import login

WINDOW = 40.0


class ReauthBarrierService(type(build_service()[0])):
    """Hold every validated reauth at a gate, then release them together."""

    def __init__(self, *args, parties: int, **kwargs):
        super().__init__(*args, **kwargs)
        self._parties = parties
        self._arrived = 0
        self._cond = threading.Condition()
        self._release = threading.Event()

    def _mfa_code_verified(self, user_id, session_id, matched_step):
        # Phase 1: count arrivals after the code cryptographically
        # validated; phase 2: the test releases the gate and every party
        # enters the consume decision together. No sleeps, no scheduling
        # luck — the rendezvous is explicit.
        with self._cond:
            self._arrived += 1
            self._cond.notify_all()
        self._release.wait(timeout=10)

    def wait_all_validated(self, timeout: float = 10.0):
        deadline_arrival = True
        with self._cond:
            ok = self._cond.wait_for(
                lambda: self._arrived >= self._parties, timeout=timeout)
        assert ok, "not all requests validated their code in time"

    def release(self):
        self._release.set()


def _barrier_service(parties: int):
    base, clock = build_service(reauth_freshness=WINDOW)
    svc = ReauthBarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=300.0, refresh_ttl=3600.0,
        reauth_freshness=WINDOW, parties=parties,
    )
    return svc, clock


def _run(service, fn, n: int) -> list:
    outcomes: list = []
    lock = threading.Lock()

    def worker():
        try:
            result = fn()
            with lock:
                outcomes.append(("ok", result))
        except AuthError as exc:
            with lock:
                outcomes.append(("err", exc.code))

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    # Deterministic rendezvous: wait until every request holds a validated
    # code, then release all of them into the consume decision together.
    service.wait_all_validated()
    service.release()
    for t in threads:
        t.join(timeout=10.0)
        assert not t.is_alive(), "reauth thread hung"
    return outcomes


def test_simultaneous_same_code_same_session_single_winner():
    n = 8
    service, clock = _barrier_service(parties=n)
    tokens = login(service)                     # consumes TOTP step 0
    ctx = service.authenticate(tokens.access_token)
    clock.advance(31.0)                         # step 1 now valid
    code = service.totp_provisioning_code("alice", clock.now())

    outcomes = _run(service, lambda: service.reauthenticate(ctx, code), n)

    oks = [o for o in outcomes if o[0] == "ok"]
    errs = [o[1] for o in outcomes if o[0] == "err"]
    assert len(oks) == 1, outcomes
    assert errs == [ErrorCode.TOTP_REPLAY] * (n - 1), outcomes
    # window slid exactly once, from exactly this verification instant
    assert oks[0][1].fresh_until == clock.now() + WINDOW
    state = service.store.get_mfa_state(ctx.session_id)
    assert state[0] == clock.now()
    # login step + exactly one reauth step
    assert sorted(state[1]) == [service.verifier.step_at(1_000_000.0),
                                service.verifier.step_at(clock.now())]
    # per-user ledger gained exactly one step as well (no double write)
    assert service.store.get_consumed_steps("alice") == frozenset(state[1])


def test_cross_session_reuse_sequential_is_replay_not_success():
    service, clock = build_service(reauth_freshness=WINDOW)
    tokens_a = login(service, source="web")
    tokens_b = login(service, source="mobile")
    ctx_a = service.authenticate(tokens_a.access_token)
    ctx_b = service.authenticate(tokens_b.access_token)

    clock.advance(31.0)                         # next TOTP step
    code = service.totp_provisioning_code("alice", clock.now())
    assert service.reauthenticate(ctx_a, code).fresh_until == clock.now() + WINDOW

    # same one-time code, different session of the same user -> replay,
    # with a code distinct from a wrong/rate-limited/locked code
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx_b, code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY

    # B's anchor was NOT slid and B consumed nothing new: it is still the
    # login instant (clock start 1_000_000.0, login step only)
    b_state = service.store.get_mfa_state(ctx_b.session_id)
    assert b_state[0] == 1_000_000.0
    assert sorted(b_state[1]) == [service.verifier.step_at(1_000_000.0)]
    # A's window did slide to t31+WINDOW
    assert service.store.get_mfa_state(ctx_a.session_id)[0] == clock.now()

    # B's freshness boundary remains anchored at login (inclusive edge at
    # login + WINDOW, epsilon past it requires reauth) — checked without
    # mutating either session.
    assert service._require_fresh_mfa  # service API is in place
    clock.advance(WINDOW - 31.0)                # t = WINDOW exactly
    service._require_fresh_mfa(
        service.store.get_session(ctx_b.session_id))   # no raise: admitted
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service._require_fresh_mfa(
            service.store.get_session(ctx_b.session_id))
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED
    # A (slid at t31) is still fresh at t=WINDOW+0.001 < 31+WINDOW
    service._require_fresh_mfa(
        service.store.get_session(ctx_a.session_id))


def test_cross_session_simultaneous_same_code_single_winner():
    n = 2
    service, clock = _barrier_service(parties=n)
    tokens_a = login(service, source="web")
    tokens_b = login(service, source="mobile")
    ctx_a = service.authenticate(tokens_a.access_token)
    ctx_b = service.authenticate(tokens_b.access_token)
    clock.advance(31.0)
    code = service.totp_provisioning_code("alice", clock.now())

    results: list = []
    lock = threading.Lock()

    def worker(ctx):
        try:
            out = service.reauthenticate(ctx, code)
            with lock:
                results.append(("ok", ctx.session_id, out.fresh_until))
        except AuthError as exc:
            with lock:
                results.append(("err", ctx.session_id, exc.code))

    threads = [
        threading.Thread(target=worker, args=(ctx_a,)),
        threading.Thread(target=worker, args=(ctx_b,)),
    ]
    for t in threads:
        t.start()
    service.wait_all_validated()
    service.release()
    for t in threads:
        t.join(timeout=10.0)
        assert not t.is_alive(), "reauth thread hung"

    oks = [r for r in results if r[0] == "ok"]
    errs = [r[2] for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert errs == [ErrorCode.TOTP_REPLAY], results

    winner_session = oks[0][1]
    loser_session = next(
        s for s in (ctx_a.session_id, ctx_b.session_id) if s != winner_session
    )
    # the loser session's freshness anchor never moved: it is still the
    # login instant (clock start 1_000_000.0), so no spurious window slide
    loser_state = service.store.get_mfa_state(loser_session)
    assert loser_state[0] == 1_000_000.0
    # only the winner slid its own session
    winner_state = service.store.get_mfa_state(winner_session)
    assert winner_state[0] == clock.now()


def test_login_code_cannot_authorize_step_up_in_another_session():
    # The very code that completed login on device A is immediately
    # presented as a step-up on device B: it was consumed per-user at
    # login, so B must see totp_replay (not success, not totp_invalid).
    service, _ = build_service(reauth_freshness=WINDOW)
    challenge_a = service.begin_login("alice", "pw", "web")
    code = service.totp_provisioning_code("alice")
    tokens_a = service.complete_login(challenge_a.challenge_id, code)
    tokens_b = login(service, source="mobile", code=code)
    ctx_b = service.authenticate(tokens_b.access_token)

    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx_b, code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY
    # A is a normal, fully usable session regardless
    assert service.authenticate(tokens_a.access_token).user_id == "alice"


def test_replay_is_independent_of_other_users_and_fresh_steps():
    # Per-user ledger: the same absolute TOTP step used by a different
    # user (different secret) is unrelated; and a genuinely new step code
    # still works after a replay was rejected.
    service, clock = build_service(reauth_freshness=WINDOW)
    alice = service.authenticate(login(service, user="alice", source="web").access_token)
    bob = service.authenticate(login(service, user="bob", source="web").access_token)
    clock.advance(31.0)

    alice_code = service.totp_provisioning_code("alice", clock.now())
    bob_code = service.totp_provisioning_code("bob", clock.now())
    assert service.reauthenticate(alice, alice_code).fresh_until == clock.now() + WINDOW
    # bob's same-step code is unaffected by alice's consumption
    assert service.reauthenticate(bob, bob_code).fresh_until == clock.now() + WINDOW

    # alice replaying her old code fails; the next step's code then works
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(alice, alice_code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY
    clock.advance(30.0)
    new_code = service.totp_provisioning_code("alice", clock.now())
    assert service.reauthenticate(alice, new_code).fresh_until == clock.now() + WINDOW
