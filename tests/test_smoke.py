"""Smoke test: skeleton imports and construction must not blow up."""
from auth.clock import FixedClock
from auth.tokens import KeyRing
from auth.mfa import TotpVerifier
from auth.store import Store
from auth.authz import Authorizer
from auth.sessions import SessionService
from auth.app import build_app


def test_skeleton_wires_together():
    clock = FixedClock(1_000_000.0)
    store = Store(clock=clock)
    keyring = KeyRing(clock=clock)
    verifier = TotpVerifier(clock=clock)
    authz = Authorizer(store)
    svc = SessionService(store, keyring, verifier, authz, clock=clock)
    app = build_app(svc, seeded=False)
    assert app is not None
