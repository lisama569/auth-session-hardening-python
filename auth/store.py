"""Thread-safe in-memory persistence (no external services).

Entities:
* :class:`UserRecord`  - persisted identity, roles, MFA secret.
* :class:`SessionRecord` - login session with a monotonically increasing
  token version (logout / refresh rotation bump it, instantly
  invalidating previously issued access tokens).
* :class:`RefreshRecord` - one refresh credential and its family chain.

The atomicity contract for refresh rotation lives in
:meth:`Store.replace_refresh`: exactly one concurrent caller can win.
"""
from __future__ import annotations

import secrets
import threading
from dataclasses import dataclass

from auth.clock import Clock, SystemClock


from enum import Enum


class RefreshState(str, Enum):
    ACTIVE = "active"
    ROTATED = "rotated"   # successfully used to mint a successor
    REVOKED = "revoked"   # logout, reuse-detection or admin revoke


@dataclass
class UserRecord:
    user_id: str
    password_hash: str
    roles: frozenset[str] = frozenset()
    # server-side persisted permission scopes — the *authoritative* set
    scopes: frozenset[str] = frozenset()
    totp_secret: bytes | None = None
    totp_enrolled: bool = False


@dataclass
class SessionRecord:
    session_id: str
    user_id: str
    created_at: float
    source: str = "web"
    token_version: int = 0
    revoked: bool = False
    revoked_reason: str | None = None
    # Freshness of the last successful second factor for this session.
    mfa_last_verified_at: float | None = None
    # TOTP steps already consumed (login + step-up reauth) so a one-time
    # code can never authorize two sensitive operations.
    mfa_consumed_steps: tuple[int, ...] = ()


@dataclass
class RefreshRecord:
    jti: str
    family_id: str
    session_id: str
    user_id: str
    issued_at: float
    expires_at: float
    state: RefreshState = RefreshState.ACTIVE
    successor_jti: str | None = None
    used_at: float | None = None
    inflight: bool = False


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(12)}"


# Replay history depth: comfortably beyond the TOTP verifier's max skew
# window (3 steps each side) so replay detection never forgets a step
# that could still cryptographically validate.
MFA_STEPS_RETAINED = 8


class MfaConsumeResult(str, Enum):
    """Outcome of an atomic TOTP step consumption attempt."""

    OK = "ok"
    SESSION_GONE = "session_gone"
    STEP_REPLAYED = "step_replayed"


class Store:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._lock = threading.RLock()
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._refreshes: dict[str, RefreshRecord] = {}
        # Per-user, cross-session ledger of absolute TOTP steps already
        # consumed (by login or step-up). This is the authoritative
        # one-time-use record: a code consumed in one session of the user
        # can never authorize a sensitive operation from another.
        self._user_mfa_steps: dict[str, tuple[int, ...]] = {}

    # ---- users ----
    def upsert_user(self, user: UserRecord) -> None:
        with self._lock:
            self._users[user.user_id] = user

    def get_user(self, user_id: str) -> UserRecord | None:
        with self._lock:
            return self._users.get(user_id)

    # ---- sessions ----
    def create_session(self, user_id: str, source: str = "web") -> SessionRecord:
        with self._lock:
            record = SessionRecord(
                session_id=_new_id("sess"),
                user_id=user_id,
                created_at=self._clock.now(),
                source=source,
            )
            self._sessions[record.session_id] = record
            return record

    def get_session(self, session_id: str) -> SessionRecord | None:
        with self._lock:
            return self._sessions.get(session_id)

    def list_active_sessions(self, user_id: str) -> list[SessionRecord]:
        """Snapshot of the user's non-revoked sessions."""
        with self._lock:
            return [
                SessionRecord(
                    session_id=r.session_id,
                    user_id=r.user_id,
                    created_at=r.created_at,
                    source=r.source,
                    token_version=r.token_version,
                    revoked=r.revoked,
                    revoked_reason=r.revoked_reason,
                    mfa_last_verified_at=r.mfa_last_verified_at,
                    mfa_consumed_steps=r.mfa_consumed_steps,
                )
                for r in self._sessions.values()
                if r.user_id == user_id and not r.revoked
            ]

    def bump_token_version(self, session_id: str) -> int:
        """Atomically increment and return the new version."""
        with self._lock:
            record = self._sessions[session_id]
            record.token_version += 1
            return record.token_version

    def revoke_session(self, session_id: str, reason: str) -> None:
        with self._lock:
            record = self._sessions.get(session_id)
            if record is not None:
                record.revoked = True
                record.revoked_reason = reason

    def terminate_session(self, session_id: str, reason: str, now: float) -> bool:
        """Atomically revoke a session and kill every bound refresh credential.

        One lock acquisition performs all three state changes so a
        concurrent refresh cannot interleave: session marked revoked,
        token version bumped (outstanding access tokens die immediately),
        and every refresh record of the session's family moved to
        ``REVOKED`` (an in-flight claim included).

        Returns ``False`` when the session does not exist or was already
        revoked — the caller treats both identically (existence hiding).
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.revoked:
                return False
            record.revoked = True
            record.revoked_reason = reason
            record.token_version += 1
            for refresh in self._refreshes.values():
                if refresh.session_id == session_id:
                    refresh.state = RefreshState.REVOKED
                    refresh.inflight = False
                    if refresh.used_at is None:
                        refresh.used_at = now
            return True

    def terminate_other_sessions(
        self, user_id: str, keep_session_id: str, reason: str, now: float,
    ) -> int:
        """Terminate every active session of the user except ``keep_session_id``.

        The kept session is never touched (its current credential pair
        stays usable). Returns the number of terminated sessions.
        """
        with self._lock:
            targets = [
                r.session_id
                for r in self._sessions.values()
                if r.user_id == user_id
                and not r.revoked
                and r.session_id != keep_session_id
            ]
            for sid in targets:
                record = self._sessions[sid]
                record.revoked = True
                record.revoked_reason = reason
                record.token_version += 1
                for refresh in self._refreshes.values():
                    if refresh.session_id == sid:
                        refresh.state = RefreshState.REVOKED
                        refresh.inflight = False
                        if refresh.used_at is None:
                            refresh.used_at = now
            return len(targets)

    # ---- MFA freshness (step-up reauthentication) ----
    def get_mfa_state(self, session_id: str) -> tuple[float | None, frozenset[int]] | None:
        """Return ``(last_verified_at, consumed_totp_steps)`` or ``None``.

        The returned steps are the per-session view (a subset of the
        user's cross-session ledger).
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            return record.mfa_last_verified_at, frozenset(record.mfa_consumed_steps)

    def get_consumed_steps(self, user_id: str) -> frozenset[int]:
        """Snapshot of the user's cross-session consumed TOTP steps."""
        with self._lock:
            return frozenset(self._user_mfa_steps.get(user_id, ()))

    @staticmethod
    def _append_bounded(steps: tuple[int, ...], step: int) -> tuple[int, ...]:
        """Append *step*, keeping at most ``MFA_STEPS_RETAINED`` entries."""
        if step in steps:
            return steps
        return (*steps[-(MFA_STEPS_RETAINED - 1):], step)

    def record_mfa_login(
        self, session_id: str, user_id: str, at: float, consumed_step: int,
    ) -> bool:
        """Record a login second factor: anchor the session and register
        the one-time code's step in the user's cross-session ledger.

        Login remains idempotent across devices (two logins presenting
        the same code both succeed): the step is recorded once, but a
        login never rejects on replay. Refuses a missing/revoked session.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.revoked:
                return False
            record.mfa_last_verified_at = at
            record.mfa_consumed_steps = self._append_bounded(
                record.mfa_consumed_steps, consumed_step)
            self._user_mfa_steps[user_id] = self._append_bounded(
                self._user_mfa_steps.get(user_id, ()), consumed_step)
            return True

    def consume_mfa_step(
        self, session_id: str, user_id: str, at: float, consumed_step: int,
    ) -> MfaConsumeResult:
        """Atomically replay-check a TOTP step, consume it and slide the
        freshness window — all under one lock acquisition.

        The replay ledger is per **user**, so the step is rejected no
        matter which of the user's sessions (or which concurrent request)
        already consumed it. Either every state change happens or none:

        * ``STEP_REPLAYED`` -> nothing is written (the window does not
          slide, no ledger/session entry is added);
        * ``SESSION_GONE``   -> missing/revoked session, nothing written;
        * ``OK``             -> user ledger + session history gain the
          step once, and this session's anchor moves to ``at`` once.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.revoked:
                return MfaConsumeResult.SESSION_GONE
            if consumed_step in self._user_mfa_steps.get(user_id, ()):
                return MfaConsumeResult.STEP_REPLAYED
            record.mfa_last_verified_at = at
            record.mfa_consumed_steps = self._append_bounded(
                record.mfa_consumed_steps, consumed_step)
            self._user_mfa_steps[user_id] = self._append_bounded(
                self._user_mfa_steps.get(user_id, ()), consumed_step)
            return MfaConsumeResult.OK

    def mark_mfa_verified(
        self, session_id: str, at: float, consumed_step: int,
    ) -> bool:
        """Record a successful second factor for a session.

        Kept for compatibility/administration; prefer the atomic
        :meth:`consume_mfa_step` on the reauthentication path, which also
        enforces cross-session one-time use.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.revoked:
                return False
            record.mfa_last_verified_at = at
            if consumed_step not in record.mfa_consumed_steps:
                # Keep replay history bounded: a TOTP code older than the
                # verifier's skew window fails as totp_invalid anyway, so
                # only the recent steps can ever match as a replay.
                record.mfa_consumed_steps = (
                    *record.mfa_consumed_steps[-(MFA_STEPS_RETAINED - 1):],
                    consumed_step,
                )
            return True

    # ---- refresh tokens ----
    def add_refresh(self, record: RefreshRecord) -> None:
        with self._lock:
            self._refreshes[record.jti] = record

    def get_refresh(self, jti: str) -> RefreshRecord | None:
        with self._lock:
            return self._refreshes.get(jti)

    def replace_refresh(self, old_jti: str, new_record: RefreshRecord) -> None:
        """Atomically mark *old_jti* rotated and store *new_record*.

        Only an ``ACTIVE``, non-inflight record can win. Raises
        :class:`LookupError` when the old record is missing or no longer
        exchangeable; the caller translates that into a distinguishable
        error (concurrent vs reuse vs revoked).
        """
        with self._lock:
            old = self._refreshes.get(old_jti)
            if old is None:
                raise LookupError("refresh token not found")
            if old.state is not RefreshState.ACTIVE or not old.inflight:
                raise LookupError("refresh token not exchangeable")
            old.state = RefreshState.ROTATED
            old.successor_jti = new_record.jti
            old.used_at = self._clock.now()
            old.inflight = False
            self._refreshes[new_record.jti] = new_record

    def mark_inflight(self, jti: str) -> RefreshRecord:
        """Atomically claim a refresh token for an in-flight rotation.

        Returns a *copy* of the claimed record. Raises :class:`LookupError`
        when the record is missing/already claimed/non-active.
        """
        with self._lock:
            record = self._refreshes.get(jti)
            if record is None:
                raise LookupError("refresh token not found")
            if record.state is not RefreshState.ACTIVE or record.inflight:
                raise LookupError("refresh token not claimable")
            record.inflight = True
            # shallow copy is sufficient: callers only read fields
            return RefreshRecord(
                jti=record.jti,
                family_id=record.family_id,
                session_id=record.session_id,
                user_id=record.user_id,
                issued_at=record.issued_at,
                expires_at=record.expires_at,
                state=record.state,
                successor_jti=record.successor_jti,
                used_at=record.used_at,
                inflight=record.inflight,
            )

    def clear_inflight(self, jti: str) -> None:
        with self._lock:
            record = self._refreshes.get(jti)
            if record is not None and record.state is RefreshState.ACTIVE:
                record.inflight = False

    def revoke_family(self, family_id: str, reason: str, now: float) -> None:
        with self._lock:
            for record in self._refreshes.values():
                if record.family_id == family_id:
                    record.state = RefreshState.REVOKED
                    record.inflight = False
                    if record.used_at is None:
                        record.used_at = now
