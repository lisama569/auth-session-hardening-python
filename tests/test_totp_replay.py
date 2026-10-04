"""One-time-code replay: deterministic concurrency + cross-session cases.

These tests do NOT rely on natural thread races: a ``threading.Barrier``
installed at a service hook parks every participant at the exact point
between "code cryptographically verified" and "atomic consume + window
slide", then releases them simultaneously. The atomicity of
``Store.consume_mfa_step`` must then produce exactly one winner
regardless of lock scheduling.
"""
import threading

import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service
from tests.test_sessions import login


class ReauthBarrierService(type(build_service()[0])):
    """Rendezvous all parties right before the atomic code-consume move.

    The primary sync point is the ``_mfa_step_consuming`` service hook:
    every request has passed TOTP verification but none has consumed the
    step yet.

    On the pre-fix implementation (whose service has no such hook) a
    wrapper around ``Store.get_mfa_state`` reconstructs the exact reported
    window instead: each thread first obtains its own *pre-write* replay
    snapshot, then the whole party rendezvous before any thread is allowed
    to run the replay decision / consume write. Both threads therefore
    observe the unconsumed ledger and write.

    A lone caller skips the rendezvous (nothing is waiting), so the same
    service stays usable for follow-up sequential assertions.
    """

    def __init__(self, *args, parties: int = 2, **kwargs):
        super().__init__(*args, **kwargs)
        self._parties = parties
        self._barrier = threading.Barrier(parties)

    def _rendezvous(self) -> None:
        # The first arrival parks (it waits for the rest of the party);
        # every further arrival joins. Callers that are NOT part of a
        # full party (sequential follow-up traffic) use ``_maybe_wait``.
        self._barrier.wait(timeout=5.0)

    def _maybe_wait(self) -> None:
        # Skip the rendezvous when no peer is already parked, so lone
        # sequential callers never block on the N-party barrier.
        if self._barrier.n_waiting > 0:
            self._barrier.wait(timeout=5.0)

    def _mfa_step_consuming(self, user_id, session_id, step):
        # Fixed implementation: verified, not yet consumed.
        self._maybe_wait()

    def install_legacy_sync_point(self) -> None:
        """Pre-fix service only: sync after the pre-write ledger read."""
        if hasattr(self.store, "consume_mfa_step"):
            return  # fixed service rendezvous through the hook
        original_get = self.store.get_mfa_state

        def synced_get(session_id):
            state = original_get(session_id)  # snapshot taken, no write yet
            self._rendezvous()                # all parties hold the same view
            return state

        self.store.get_mfa_state = synced_get


def _barrier_service(parties: int, reauth_freshness: float = 40.0):
    base, clock = build_service(reauth_freshness=reauth_freshness)
    service = ReauthBarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=300.0, refresh_ttl=3600.0,
        reauth_freshness=reauth_freshness, parties=parties,
    )
    service.install_legacy_sync_point()
    return service, clock


def _gather(fn, args_list):
    """Run fn(*args) for each args set on its own thread; collect outcomes."""
    results: list[object] = []
    lock = threading.Lock()

    def worker(args):
        try:
            value = fn(*args)
            with lock:
                results.append(("ok", value))
        except AuthError as exc:
            with lock:
                results.append(("err", exc.code))

    threads = [threading.Thread(target=worker, args=(args,)) for args in args_list]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5.0)
    assert not any(t.is_alive() for t in threads), "a worker thread hung at the barrier"
    return results


# ---------------------------------------------------------------- same-code
# 1. simultaneous submissions of the SAME code in the SAME session
# ----------------------------------------------------------------
@pytest.mark.parametrize("parties", [2, 8])
def test_simultaneous_same_code_same_session_single_winner(parties):
    service, clock = _barrier_service(parties)
    tokens = login(service)                 # consumes the login step
    ctx = service.authenticate(tokens.access_token)
    clock.advance(31.0)                     # a fresh, unconsumed TOTP step
    code = service.totp_provisioning_code("alice", clock.now())

    results = _gather(service.reauthenticate, [(ctx, code)] * parties)

    oks = [r for r in results if r[0] == "ok"]
    errs = [r[1] for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert errs == [ErrorCode.TOTP_REPLAY] * (parties - 1), results

    # the window slid exactly once, from exactly one anchor instant...
    assert oks[0][1].fresh_until == clock.now() + 40.0
    anchor, consumed = service.store.get_mfa_state(ctx.session_id)
    assert anchor == clock.now()
    # ...and the step appears exactly once (login step + one reauth step)
    assert len(consumed) == 2
    assert service.verifier.step_at(clock.now()) in consumed

    # the rejected attempts must not authorize a second sensitive op:
    # a replay loser presenting the same code again is still refused
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY


def test_replay_reason_is_distinct_from_wrong_code_and_throttling():
    service, clock = _barrier_service(2)
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)
    clock.advance(31.0)
    code = service.totp_provisioning_code("alice", clock.now())

    results = _gather(service.reauthenticate, [(ctx, code)] * 2)
    codes = {r[1] for r in results if r[0] == "err"}
    assert codes == {ErrorCode.TOTP_REPLAY}

    # replay must not masquerade as any other MFA failure reason
    assert ErrorCode.TOTP_REPLAY not in (
        ErrorCode.TOTP_INVALID, ErrorCode.MFA_RATE_LIMITED, ErrorCode.MFA_LOCKED,
    )
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, "000000")
    assert exc.value.code is ErrorCode.TOTP_INVALID


# ------------------------------------------------------------- cross-session
# 2. a code spent in one session can never be reused in another
# ----------------------------------------------------------------
def test_cross_session_replay_is_rejected():
    service, clock = build_service(reauth_freshness=400.0)
    first = login(service, source="web")          # step A consumed at login
    clock.advance(31.0)                            # step B is current
    code_b = service.totp_provisioning_code("alice", clock.now())
    ctx_a = service.authenticate(first.access_token)
    assert service.reauthenticate(ctx_a, code_b).fresh_until == clock.now() + 400.0

    # the second device finishes login with its own fresh code (step C)
    clock.advance(30.0)
    second_login_at = clock.now()
    second = login(service, source="mobile")
    ctx_b = service.authenticate(second.access_token)

    # step B still cryptographically validates here (tolerance ±1 step),
    # yet it must be refused as a replay — not as invalid/locked/etc.
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx_b, code_b)
    assert exc.value.code is ErrorCode.TOTP_REPLAY

    # neither session's ledger allows the spent step a second time
    assert service.verifier.step_at(clock.now()) - 1 in \
        service.store.get_consumed_mfa_steps("alice")
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx_a, code_b)
    assert exc.value.code is ErrorCode.TOTP_REPLAY

    # the refused cross-session replay did not slide session B's anchor:
    # it still equals its own login instant (not the rejected call instant)
    anchor_b, _ = service.store.get_mfa_state(ctx_b.session_id)
    assert anchor_b == second_login_at


def test_simultaneous_same_code_across_two_sessions_single_winner():
    service, clock = _barrier_service(2)
    first = login(service, source="web")
    clock.advance(31.0)
    second = login(service, source="mobile")
    clock.advance(31.0)                             # fresh unconsumed step
    code = service.totp_provisioning_code("alice", clock.now())
    ctx_a = service.authenticate(first.access_token)
    ctx_b = service.authenticate(second.access_token)

    results = _gather(
        service.reauthenticate, [(ctx_a, code), (ctx_b, code)],
    )
    oks = [r for r in results if r[0] == "ok"]
    errs = [r[1] for r in results if r[0] == "err"]
    assert len(oks) == 1, results
    assert errs == [ErrorCode.TOTP_REPLAY], results

    # only one session's freshness anchor moved: exactly one anchor lands
    # at the rendezvous instant, the loser keeps its own login instant
    anchor_a, _ = service.store.get_mfa_state(ctx_a.session_id)
    anchor_b, _ = service.store.get_mfa_state(ctx_b.session_id)
    assert [a for a in (anchor_a, anchor_b) if a == clock.now()] == [clock.now()]
    loser_anchor = anchor_b if anchor_a == clock.now() else anchor_a
    assert loser_anchor != clock.now()
    # the user-wide ledger holds the step exactly once
    ledger = service.store.get_consumed_mfa_steps("alice")
    assert sorted(ledger).count(service.verifier.step_at(clock.now())) == 1


def test_second_login_replaying_a_spent_code_is_rejected_and_leaves_no_session():
    service, clock = build_service()
    first = login(service, source="web")
    assert len(service.store.list_active_sessions("alice")) == 1
    spent = service.totp_provisioning_code("alice", clock.now())

    # another device completes its challenge with the already-spent code;
    # within tolerance it is still the same TOTP, so only replay can fire
    challenge = service.begin_login("alice", "pw", "mobile")
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge.challenge_id, spent)
    assert exc.value.code is ErrorCode.TOTP_REPLAY

    # no extra session lingers and the challenge was consumed
    assert len(service.store.list_active_sessions("alice")) == 1
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge.challenge_id, spent)
    assert exc.value.code is ErrorCode.CHALLENGE_NOT_FOUND
    # the original session is untouched and still usable
    ctx = service.authenticate(first.access_token)
    assert service.list_sessions(ctx)[0].current is True


def test_login_replay_is_distinct_from_wrong_code():
    service, clock = build_service()
    login(service, source="web")
    spent = service.totp_provisioning_code("alice", clock.now())
    challenge = service.begin_login("alice", "pw", "mobile")
    # a truly wrong code stays totp_invalid (and still leaves no session)
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge.challenge_id, "000000")
    assert exc.value.code is ErrorCode.TOTP_INVALID
    assert len(service.store.list_active_sessions("alice")) == 1

    challenge2 = service.begin_login("alice", "pw", "mobile")
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge2.challenge_id, spent)
    assert exc.value.code is ErrorCode.TOTP_REPLAY


# ------------------------------------------------------------- boundary
# 3. the freshness window edge semantics are unchanged by the new ledger
# ----------------------------------------------------------------
def test_freshness_boundary_unchanged_after_ledger_change():
    service, clock = build_service(reauth_freshness=40.0)
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)

    clock.advance(31.0)
    code = service.totp_provisioning_code("alice", clock.now())
    assert service.reauthenticate(ctx, code).fresh_until == clock.now() + 40.0

    # exactly at fresh_until: admitted (inclusive edge)
    clock.advance(40.0)
    assert service.logout_other_sessions(ctx) == 0
    # one epsilon past: reauth_required (rejected op changed nothing)
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.logout_other_sessions(ctx)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED
