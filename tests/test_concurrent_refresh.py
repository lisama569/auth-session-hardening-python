"""Concurrent / duplicated refresh token submissions.

Deterministic concurrency is achieved with a subclass hook
(``_refresh_claimed``), not sleeps: the winning request pauses after
atomically claiming the token, while N duplicate requests race in.
Exactly one caller can ever win.
"""
import threading

import pytest

from auth.errors import AuthError, ErrorCode
from auth.store import RefreshRecord
from tests.conftest_service import build_service
from tests.test_sessions import login


class BarrierService(type(build_service()[0])):  # subclass of SessionService
    """Service that opens a deterministic window after claiming a token."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._gate = threading.Event()
        self.claim_events: dict[str, threading.Event] = {}
        self._claim_lock = threading.Lock()

    def open_gate(self) -> None:
        self._gate.set()

    def _refresh_claimed(self, record: RefreshRecord) -> None:
        with self._claim_lock:
            event = self.claim_events.setdefault(record.jti, threading.Event())
        event.set()
        # Winner blocks here until the test releases the gate.
        self._gate.wait()

    def wait_until_claimed(self, jti: str, timeout: float = 2.0) -> None:
        with self._claim_lock:
            event = self.claim_events.setdefault(jti, threading.Event())
        assert event.wait(timeout), "winner never claimed the refresh token"


def _extract_jti(service, token: str) -> str:
    return service.keyring.verify(token).jti


def _build_barrier_service():
    base, clock = build_service()
    svc = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=300.0, refresh_ttl=3600.0,
    )
    return svc, clock


def test_exactly_one_winner_under_concurrent_refresh():
    service, _ = _build_barrier_service()
    tokens = login(service)

    results: list[object] = []
    lock = threading.Lock()

    def winner():
        try:
            out = service.refresh(tokens.refresh_token)
            with lock:
                results.append(("ok", out))
        except AuthError as exc:
            with lock:
                results.append(("err", exc.code))

    def loser():
        try:
            service.refresh(tokens.refresh_token)
            with lock:
                results.append(("ok", None))
        except AuthError as exc:
            with lock:
                results.append(("err", exc.code))

    t_winner = threading.Thread(target=winner)
    t_winner.start()
    service.wait_until_claimed(_extract_jti(service, tokens.refresh_token))

    # Winner is now holding the claim; fire 7 duplicates concurrently.
    losers = [threading.Thread(target=loser) for _ in range(7)]
    for t in losers:
        t.start()
    for t in losers:
        t.join(timeout=2.0)

    service.open_gate()
    t_winner.join(timeout=2.0)

    outcomes = [kind for kind, _ in results]
    assert outcomes.count("ok") == 1, outcomes
    # All losers must see the *concurrent* reason, never reuse/invalid.
    duplicate_codes = [code for kind, code in results if kind == "err"]
    assert duplicate_codes == [ErrorCode.REFRESH_TOKEN_CONCURRENT] * 7, duplicate_codes

    # Only one new active refresh credential exists for the family.
    new_tokens = results[[kind for kind, _ in results].index("ok")][1]
    assert new_tokens.refresh_token != tokens.refresh_token
    active = [
        r for r in service.store._refreshes.values()
        if r.state.value == "active"
    ]
    assert len(active) == 1
    assert service.keyring.verify(new_tokens.refresh_token).jti == active[0].jti


def test_sequential_replay_after_commit_is_reuse_not_concurrent():
    """Once the winner committed, a replay is reuse (family revoked)."""
    service, _ = build_service()
    tokens = login(service)
    service.refresh(tokens.refresh_token)  # committed winner

    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REUSE


def test_duplicate_after_concurrent_loser_still_blocked():
    """A loser that hit CONCURRENT may not retry into the rotation."""
    service, _ = _build_barrier_service()
    tokens = login(service)

    holder: dict[str, object] = {}

    def winner():
        try:
            holder["result"] = service.refresh(tokens.refresh_token)
        except AuthError as exc:
            holder["result"] = exc.code

    t = threading.Thread(target=winner)
    t.start()
    service.wait_until_claimed(_extract_jti(service, tokens.refresh_token))

    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_CONCURRENT

    service.open_gate()
    t.join(timeout=2.0)
    assert hasattr(holder["result"], "refresh_token")

    # Post-commit replay is unambiguously reuse.
    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REUSE
