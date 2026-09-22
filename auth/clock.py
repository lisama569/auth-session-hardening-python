"""Injectable clock so time-dependent logic is fully testable locally."""
from __future__ import annotations

import time
from typing import Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Return current unix time in seconds."""
        ...


class SystemClock:
    def now(self) -> float:
        return time.time()


class FixedClock:
    """Deterministic clock that only advances when told to."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = float(start)

    def now(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("cannot rewind the clock")
        self._now += seconds

    def set(self, value: float) -> None:
        self._now = float(value)
