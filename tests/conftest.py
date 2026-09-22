"""测试公共夹具。

所有测试均使用：
* :class:`FixedClock` —— 时间可精确推进，不依赖真实墙钟；
* :class:`InMemoryStore` —— 内存存储，不依赖任何外部服务；
* 本地生成的 TOTP 密钥与口令，无真实凭据。
"""

from __future__ import annotations

import logging

import pytest

from auth.bootstrap import AuthContainer
from auth.timeutil import FixedClock
from auth.totp import TOTPConfig

# 打开关键输入/判定日志（caplog 也会捕获）
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock()


@pytest.fixture
def config() -> TOTPConfig:
    # 小阈值、短窗口，便于边界断言
    return TOTPConfig(
        digits=6,
        period=30,
        skew=1,
        max_attempts=5,
        throttle_after=3,
        throttle_seconds=60.0,
        lock_seconds=300.0,
        max_timestamp_skew_seconds=120.0,
    )


@pytest.fixture
def container(clock: FixedClock, config: TOTPConfig) -> AuthContainer:
    c = AuthContainer(clock=clock, totp_config=config, seed_demo=True)
    return c


@pytest.fixture
def client(container):
    from fastapi.testclient import TestClient

    from auth.api import create_app

    return TestClient(create_app(container.service))
