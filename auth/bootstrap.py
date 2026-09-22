"""应用装配：把存储、时钟、凭据权威、TOTP 验证器与服务组合起来。

本地演示使用系统时钟与内存存储；测试可注入 :class:`FixedClock` 与空种子数据。
"""

from __future__ import annotations

from fastapi import FastAPI

from .api import create_app
from .service import AuthService
from .store import InMemoryStore
from .timeutil import Clock
from .tokens import TokenAuthority
from .totp import TOTPVerifier, TOTPConfig


class AuthContainer:
    def __init__(self, clock: Clock | None = None,
                 totp_config: TOTPConfig | None = None,
                 seed_demo: bool = True) -> None:
        self.clock = clock or Clock()
        self.store = InMemoryStore()
        self.tokens = TokenAuthority(self.store, self.clock)
        self.totp = TOTPVerifier(self.store, self.clock, totp_config)
        self.service = AuthService(self.store, self.tokens, self.totp, self.clock)
        if seed_demo:
            self._seed_demo_users()

    def _seed_demo_users(self) -> None:
        """固定演示账号，便于本地复现（口令仅用于本地）。"""
        from .totp import TOTPVerifier as _T

        # admin / viewer 带 MFA；editor 不启用 MFA
        secret_admin = _T.generate_secret()
        secret_viewer = _T.generate_secret()
        self._demo_totp_secrets = {
            "admin": secret_admin,
            "viewer": secret_viewer,
        }
        self.service.register(
            "u-admin", "admin", "admin-pass",
            roles=["admin"], totp_secret=secret_admin)
        self.service.register(
            "u-editor", "editor", "editor-pass",
            roles=["editor"])
        self.service.register(
            "u-viewer", "viewer", "viewer-pass",
            roles=["viewer"], totp_secret=secret_viewer)


def build_app(clock: Clock | None = None, seed_demo: bool = True) -> tuple[FastAPI, AuthContainer]:
    container = AuthContainer(clock=clock, seed_demo=seed_demo)
    return create_app(container.service), container
