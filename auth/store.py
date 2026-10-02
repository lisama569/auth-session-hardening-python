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
    # Last successful step-up reauthentication (sensitive-op freshness).
    last_reauth_at: float | None = None


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


class Store:
    def __init__(self, clock: Clock | None = None) -> None:
        self._clock = clock or SystemClock()
        self._lock = threading.RLock()
        self._users: dict[str, UserRecord] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._refreshes: dict[str, RefreshRecord] = {}
        # Consumed step-up TOTP step numbers per user (replay defense):
        # a one-time code that already authorized a sensitive operation
        # can never authorize a second one.
        self._reauth_steps: dict[str, set[int]] = {}

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
        """All live (non-revoked) sessions of *user_id*, oldest first."""
        with self._lock:
            return [
                record for record in self._sessions.values()
                if record.user_id == user_id and not record.revoked
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

    def terminate_session(self, session_id: str, user_id: str, reason: str, now: float) -> bool:
        """Atomically terminate one session owned by *user_id*.

        Revokes the session, bumps its token version (outstanding access
        tokens die immediately via the version check) and revokes every
        refresh record of the session's families. Returns ``True`` only
        when a live session owned by *user_id* was terminated; a missing,
        foreign or already-revoked session yields ``False`` so callers
        can render one uniform "not found" answer.
        """
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.user_id != user_id or record.revoked:
                return False
            record.revoked = True
            record.revoked_reason = reason
            record.token_version += 1
            families: set[str] = set()
            for refresh in self._refreshes.values():
                if refresh.session_id == session_id:
                    refresh.state = RefreshState.REVOKED
                    refresh.inflight = False
                    if refresh.used_at is None:
                        refresh.used_at = now
                    families.add(refresh.family_id)
            return True

    def terminate_other_sessions(
        self, keep_session_id: str, user_id: str, reason: str, now: float,
    ) -> list[str]:
        """Atomically terminate every live session of *user_id* except one.

        The kept session's token version is untouched, so its current
        access and refresh credentials stay valid. Returns the terminated
        session ids (oldest first).
        """
        with self._lock:
            victims = [
                record for record in self._sessions.values()
                if record.user_id == user_id
                and record.session_id != keep_session_id
                and not record.revoked
            ]
            victims.sort(key=lambda r: r.created_at)
            victim_ids = {record.session_id for record in victims}
            for record in victims:
                record.revoked = True
                record.revoked_reason = reason
            for refresh in self._refreshes.values():
                if refresh.session_id in victim_ids:
                    refresh.state = RefreshState.REVOKED
                    refresh.inflight = False
                    if refresh.used_at is None:
                        refresh.used_at = now
            return [record.session_id for record in victims]

    def mark_reauthenticated(self, session_id: str, now: float) -> None:
        """Stamp the session's last successful step-up verification."""
        with self._lock:
            record = self._sessions.get(session_id)
            if record is not None:
                record.last_reauth_at = now

    # ---- step-up reauthentication: one-time code consumption ----
    def consume_reauth_step(
        self, user_id: str, step: int, min_retained_step: int,
    ) -> bool:
        """Atomically claim TOTP *step* for *user_id*.

        Returns ``True`` when this is the first consumption of *step*;
        ``False`` when the step was already consumed (a replay). Steps
        older than *min_retained_step* are pruned — they can never recur
        as valid TOTP codes and need no tracking.
        """
        with self._lock:
            consumed = self._reauth_steps.setdefault(user_id, set())
            if step in consumed:
                return False
            consumed -= {old for old in consumed if old < min_retained_step}
            consumed.add(step)
            return True

    def reauth_step_consumed(self, user_id: str, step: int) -> bool:
        with self._lock:
            return step in self._reauth_steps.get(user_id, ())

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
