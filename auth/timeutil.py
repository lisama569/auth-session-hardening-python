"""可注入的时钟，测试中可自由推进时间，不依赖真实外部服务。"""

from __future__ import annotations

import time
from collections.abc import Callable


class Clock:
    """时间源封装。

    - 默认使用系统 wall clock（``time.time``）；
    - 测试中使用 :class:`FixedClock` 或注入可调用对象，使"过期/锁定窗口/
      时间步"等行为完全可复现。
    """

    def __init__(self, source: Callable[[], float] | None = None) -> None:
        self._source = source or time.time

    def now(self) -> float:
        """当前 Unix 时间戳（秒）。"""
        return float(self._source())

    def advance(self, seconds: float) -> None:
        """推进时钟。

        基础 Clock 包装真实时间，不可推进；需要推进时请使用
        :class:`FixedClock`。
        """
        raise TypeError("系统时钟不可推进；测试请使用 FixedClock")


class FixedClock(Clock):
    """起点固定、可手动推进的时钟，测试专用。"""

    def __init__(self, start: float | None = None) -> None:
        # 固定取一个远离 0 的整数起点，避免过期判断与 0 值混淆
        self._now = float(start if start is not None else 1_700_000_000.0)
        super().__init__(source=lambda: self._now)

    def advance(self, seconds: float) -> None:
        if seconds < 0:
            raise ValueError("只能向前推进时钟")
        self._now += float(seconds)

    def set(self, value: float) -> None:
        self._now = float(value)
