"""TOTP second-factor verification with failure protection.

Failure counters are keyed by ``(user_id, source)``. Rules (all
time-based, driven by an injectable clock):

* ``1 .. rate_limit_threshold-1`` failures -> ``totp_invalid`` /
  ``totp_clock_skew`` with the running failure count.
* At ``rate_limit_threshold`` failures (and each further one) the
  pair enters a rate-limit window (``rate_limit_window_seconds``) and
  attempts return ``mfa_rate_limited`` with ``retry_after``.
* At ``lock_threshold`` failures the pair is locked for
  ``lock_window_seconds``: **every** attempt, even with a correct code,
  returns ``mfa_locked``.
* A successful verification resets the counter to zero immediately.
* Expiry of the lock window also resets the counter (a fresh attempt at
  ``t >= locked_until`` starts from zero). The lock boundary is
  exclusive: an attempt exactly at ``locked_until`` is admitted.
* A code valid only outside ``tolerance_steps`` but within
  ``max_skew_steps`` yields ``totp_clock_skew`` (a counted failure),
  distinguishable from a plain wrong code.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import threading
from dataclasses import dataclass
from enum import Enum

from auth.clock import Clock, SystemClock
from auth.logging_utils import log_decision


class TotpResult(str, Enum):
    OK = "ok"
    INVALID = "totp_invalid"
    CLOCK_SKEW = "totp_clock_skew"
    RATE_LIMITED = "mfa_rate_limited"
    LOCKED = "mfa_locked"


@dataclass(frozen=True)
class MfaStatus:
    """Explainable outcome of a verification attempt."""

    result: TotpResult
    failures: int
    locked_until: float | None
    retry_after: float | None
    matched_step: int | None = None


@dataclass
class _Counter:
    failures: int = 0
    locked_until: float = 0.0
    rate_limit_until: float = 0.0


class TotpVerifier:
    def __init__(
        self,
        clock: Clock | None = None,
        *,
        digits: int = 6,
        period: int = 30,
        tolerance_steps: int = 1,
        max_skew_steps: int = 3,
        rate_limit_threshold: int = 3,
        rate_limit_window_seconds: float = 60.0,
        lock_threshold: int = 5,
        lock_window_seconds: float = 300.0,
    ) -> None:
        self._clock = clock or SystemClock()
        self._digits = digits
        self._period = period
        self._tolerance = tolerance_steps
        self._max_skew = max_skew_steps
        self._rl_threshold = rate_limit_threshold
        self._rl_window = rate_limit_window_seconds
        self._lock_threshold = lock_threshold
        self._lock_window = lock_window_seconds
        self._counters: dict[tuple[str, str], _Counter] = {}
        self._lock = threading.RLock()

    @property
    def max_skew_steps(self) -> int:
        return self._max_skew

    # ---- TOTP primitives (RFC 6238 / 4226, HMAC-SHA1) ----
    def generate_secret(self) -> bytes:
        """Return a new unpadded base32-encoded TOTP secret."""
        return base64.b32encode(secrets.token_bytes(20)).rstrip(b"=")

    def _hotp(self, secret: bytes, counter: int) -> str:
        key = base64.b32decode(secret + b"=" * (-len(secret) % 8))
        msg = struct.pack(">Q", counter)
        digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = digest[-1] & 0x0F
        binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFF_FFFF
        return str(binary % 10**self._digits).zfill(self._digits)

    def code_at(self, secret: bytes, timestamp: float | None = None) -> str:
        """Compute the TOTP code for a timestamp (test/local helper)."""
        if timestamp is None:
            timestamp = self._clock.now()
        return self._hotp(secret, int(timestamp // self._period))

    def step_at(self, timestamp: float | None = None) -> int:
        """Absolute TOTP step number at a timestamp (used for replay tracking)."""
        if timestamp is None:
            timestamp = self._clock.now()
        return int(timestamp // self._period)

    def _match(self, secret: bytes, code: str, now: float) -> tuple[TotpResult | None, int | None]:
        """Return (result, matched_step). result None means fully invalid."""
        if not (code.isdigit() and len(code) == self._digits):
            return None, None
        base_step = int(now // self._period)
        for delta in range(0, self._tolerance + 1):
            for step in (base_step + delta, base_step - delta) if delta else (base_step,):
                if hmac.compare_digest(self._hotp(secret, step), code):
                    return TotpResult.OK, step - base_step
        for delta in range(self._tolerance + 1, self._max_skew + 1):
            for step in (base_step + delta, base_step - delta):
                if hmac.compare_digest(self._hotp(secret, step), code):
                    return TotpResult.CLOCK_SKEW, step - base_step
        return None, None

    # ---- state inspection / administration ----
    def status(self, user_id: str, source: str) -> MfaStatus:
        """Current counter / lock state without performing a check."""
        with self._lock:
            counter = self._counters.get((user_id, source), _Counter())
            now = self._clock.now()
            locked = counter.failures >= self._lock_threshold and now < counter.locked_until
            retry: float | None = None
            if locked:
                retry = max(0.0, counter.locked_until - now)
            elif counter.failures >= self._rl_threshold and now < counter.rate_limit_until:
                retry = max(0.0, counter.rate_limit_until - now)
            return MfaStatus(
                result=TotpResult.LOCKED if locked else (
                    TotpResult.RATE_LIMITED if retry is not None else TotpResult.OK
                ),
                failures=counter.failures,
                locked_until=counter.locked_until if counter.locked_until else None,
                retry_after=retry,
            )

    def reset(self, user_id: str, source: str) -> None:
        """Administrative reset of a counter."""
        with self._lock:
            self._counters.pop((user_id, source), None)

    # ---- verification ----
    def verify(self, user_id: str, source: str, secret: bytes, code: str) -> MfaStatus:
        """Verify a code and apply failure accounting.

        Gate outcomes (LOCKED / RATE_LIMITED) never reach the code check.
        Returns :class:`MfaStatus` rather than raising, so callers can
        branch on the distinguishable result.
        """
        with self._lock:
            now = self._clock.now()
            counter = self._counters.setdefault((user_id, source), _Counter())

            # Lock window expiry resets the counter explicitly.
            if counter.failures >= self._lock_threshold and now >= counter.locked_until:
                log_decision(
                    "mfa.lock_expired", "counter_reset",
                    user=user_id, source=source, at=now, locked_until=counter.locked_until,
                )
                counter.failures = 0
                counter.locked_until = 0.0
                counter.rate_limit_until = 0.0

            if counter.failures >= self._lock_threshold and now < counter.locked_until:
                retry = counter.locked_until - now
                log_decision(
                    "mfa.verify", "mfa_locked", user=user_id, source=source,
                    failures=counter.failures, retry_after=retry, code_evaluated=False,
                )
                return MfaStatus(TotpResult.LOCKED, counter.failures, counter.locked_until, retry)

            in_rl_window = (
                counter.failures >= self._rl_threshold and now < counter.rate_limit_until
            )
            matched, step = self._match(secret, str(code).strip(), now)

            if matched is TotpResult.OK:
                if in_rl_window:
                    # Throttling: even a correct code is refused while the
                    # window is open, and the counter is not reset.
                    retry = counter.rate_limit_until - now
                    log_decision(
                        "mfa.verify", "mfa_rate_limited", user=user_id, source=source,
                        failures=counter.failures, retry_after=retry, code_correct=True,
                    )
                    return MfaStatus(TotpResult.RATE_LIMITED, counter.failures, None, retry)
                log_decision(
                    "mfa.verify", "ok", user=user_id, source=source,
                    prior_failures=counter.failures, matched_step=step,
                )
                counter.failures = 0
                counter.locked_until = 0.0
                counter.rate_limit_until = 0.0
                return MfaStatus(TotpResult.OK, 0, None, None, step)

            if matched is TotpResult.CLOCK_SKEW:
                result_kind = TotpResult.CLOCK_SKEW
            else:
                result_kind = TotpResult.INVALID

            counter.failures += 1
            if counter.failures >= self._lock_threshold:
                counter.locked_until = now + self._lock_window
                counter.rate_limit_until = counter.locked_until
                log_decision(
                    "mfa.verify", "mfa_locked", user=user_id, source=source,
                    failures=counter.failures, locked_until=counter.locked_until,
                    code_result=result_kind.value,
                )
                return MfaStatus(TotpResult.LOCKED, counter.failures, counter.locked_until,
                                 self._lock_window, step)

            if counter.failures >= self._rl_threshold:
                counter.rate_limit_until = now + self._rl_window
                log_decision(
                    "mfa.verify", "mfa_rate_limited", user=user_id, source=source,
                    failures=counter.failures, retry_after=self._rl_window,
                    code_result=result_kind.value,
                )
                return MfaStatus(TotpResult.RATE_LIMITED, counter.failures, None,
                                 self._rl_window, step)

            log_decision(
                "mfa.verify", result_kind.value, user=user_id, source=source,
                failures=counter.failures, matched_step=step,
            )
            return MfaStatus(result_kind, counter.failures, None, None, step)
