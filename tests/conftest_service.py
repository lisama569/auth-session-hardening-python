"""Shared in-process service builder for tests."""
from __future__ import annotations

from auth.authz import Authorizer, ResourceSpec
from auth.clock import FixedClock
from auth.mfa import TotpVerifier
from auth.sessions import SessionService
from auth.store import Store
from auth.tokens import KeyRing


def build_service(
    start: float = 1_000_000.0,
    require_mfa: bool = True,
    reauth_freshness: float = 300.0,
):
    clock = FixedClock(start)
    store = Store(clock=clock)
    keyring = KeyRing(clock=clock)
    verifier = TotpVerifier(clock=clock)
    authorizer = Authorizer(store)
    service = SessionService(
        store, keyring, verifier, authorizer, clock=clock,
        access_ttl=300.0, refresh_ttl=3600.0,
        reauth_freshness=reauth_freshness, require_mfa=require_mfa,
    )
    service.register_user(
        "alice", "pw", roles={"reader"},
        scopes={"docs:read", "profile:read"},
    )
    service.register_user(
        "bob", "pw", roles={"writer"},
        scopes={"docs:read", "docs:write", "profile:read"},
    )
    for name, scope in (
        ("docs", "docs:read"),
        ("docs-admin", "docs:write"),
        ("profile", "profile:read"),
    ):
        authorizer.register_resource(ResourceSpec(name, frozenset({scope})))
    return service, clock
