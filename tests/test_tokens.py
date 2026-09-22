"""Token signing/verification, expiry and signing-key rotation."""
import pytest

from auth.clock import FixedClock
from auth.errors import AuthError, ErrorCode
from auth.tokens import KeyRing, TokenClaims


def _claims(clock: FixedClock, typ: str = "access", ttl: float = 100.0, **kw) -> dict:
    base = TokenClaims(
        jti="jti-1", typ=typ, sub="u1", sid="s1", kid="",
        iat=clock.now(), exp=clock.now() + ttl, scopes=frozenset({"a:read"}),
        **kw,
    ).to_dict()
    return base


def test_sign_and_verify_roundtrip():
    clock = FixedClock(1000.0)
    ring = KeyRing(clock=clock)
    token = ring.sign(_claims(clock))
    claims = ring.verify(token)
    assert claims.sub == "u1"
    assert claims.scopes == frozenset({"a:read"})


def test_tampered_token_rejected():
    clock = FixedClock(1000.0)
    ring = KeyRing(clock=clock)
    token = ring.sign(_claims(clock))
    payload, sig = token.split(".")
    tampered = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB") + "." + sig
    with pytest.raises(AuthError) as exc:
        ring.verify(tampered)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_INVALID


def test_expired_access_token_is_distinguishable():
    clock = FixedClock(1000.0)
    ring = KeyRing(clock=clock)
    token = ring.sign(_claims(clock, ttl=50.0))
    clock.advance(50.0)  # exp == now -> expired (boundary is exclusive)
    with pytest.raises(AuthError) as exc:
        ring.verify(token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_EXPIRED


def test_expired_refresh_token_is_distinguishable():
    clock = FixedClock(1000.0)
    ring = KeyRing(clock=clock)
    token = ring.sign(_claims(clock, typ="refresh", ttl=10.0))
    clock.advance(11.0)
    with pytest.raises(AuthError) as exc:
        ring.verify(token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_EXPIRED


def test_key_rotation_invalidates_all_old_tokens():
    clock = FixedClock(1000.0)
    ring = KeyRing(clock=clock)
    old_access = ring.sign(_claims(clock))
    old_refresh = ring.sign(_claims(clock, typ="refresh"))
    old_kid = ring.kid
    new_kid = ring.rotate()
    assert new_kid != old_kid
    for token in (old_access, old_refresh):
        with pytest.raises(AuthError) as exc:
            ring.verify(token)
        assert exc.value.code is ErrorCode.KEY_VERSION_STALE


def test_malformed_token_rejected():
    ring = KeyRing(clock=FixedClock(0.0))
    for bad in ("", "not-a-token", "a.b.c"):
        with pytest.raises(AuthError) as exc:
            ring.verify(bad)
        assert exc.value.code is ErrorCode.ACCESS_TOKEN_INVALID
