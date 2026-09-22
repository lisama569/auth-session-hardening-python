"""Sequential session lifecycle tests (concurrency lives separately)."""
import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service


def login(service, user="alice", source="web", code=None):
    challenge = service.begin_login(user, "pw", source)
    code = code or service.totp_provisioning_code(user)
    return service.complete_login(challenge.challenge_id, code)


def test_login_requires_correct_password():
    service, _ = build_service()
    with pytest.raises(AuthError) as exc:
        service.begin_login("alice", "wrong")
    assert exc.value.code is ErrorCode.INVALID_CREDENTIALS
    with pytest.raises(AuthError) as exc:
        service.begin_login("ghost", "pw")
    assert exc.value.code is ErrorCode.INVALID_CREDENTIALS


def test_mfa_challenge_expiry_is_distinguishable():
    service, clock = build_service()
    challenge = service.begin_login("alice", "pw")
    clock.advance(121.0)
    code = service.totp_provisioning_code("alice", clock.now())
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge.challenge_id, code)
    assert exc.value.code is ErrorCode.CHALLENGE_EXPIRED
    # challenge is single-use: replay also fails (not found)
    with pytest.raises(AuthError) as exc:
        service.complete_login(challenge.challenge_id, code)
    assert exc.value.code is ErrorCode.CHALLENGE_NOT_FOUND


def test_refresh_rotates_and_old_pair_stops_working():
    service, clock = build_service()
    tokens = login(service)

    # old access works
    ctx = service.authenticate(tokens.access_token)
    assert ctx.user_id == "alice"

    rotated = service.refresh(tokens.refresh_token)
    assert rotated.refresh_token != tokens.refresh_token

    # old refresh token -> reuse rejection; reuse burns the family AND
    # the session (conservative security response to suspected theft)
    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REUSE

    # both old and rotated access tokens are dead after reuse detection
    with pytest.raises(AuthError) as exc:
        service.authenticate(rotated.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    with pytest.raises(AuthError) as exc:
        service.authenticate(tokens.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED

    # whole family burned after reuse: rotated token revoked too
    with pytest.raises(AuthError) as exc:
        service.refresh(rotated.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED


def test_refresh_chain_advances_many_times():
    service, _ = build_service()
    tokens = login(service)
    for _ in range(5):
        tokens = service.refresh(tokens.refresh_token)
    ctx = service.authenticate(tokens.access_token)
    assert ctx.user_id == "alice"


def test_expired_refresh_token_rejected():
    service, clock = build_service()
    tokens = login(service)
    clock.advance(3601.0)
    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_EXPIRED


def test_expired_access_token_rejected():
    service, clock = build_service()
    tokens = login(service)
    clock.advance(301.0)
    with pytest.raises(AuthError) as exc:
        service.authenticate(tokens.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_EXPIRED


def test_logout_invalidates_refresh_family_and_access_tokens():
    service, _ = build_service()
    tokens = login(service)
    service.logout(tokens.refresh_token)

    with pytest.raises(AuthError) as exc:
        service.authenticate(tokens.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED

    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED


def test_key_rotation_kills_outstanding_credentials():
    service, _ = build_service()
    tokens = login(service)
    service.rotate_signing_key()
    for raw, expected in (
        (tokens.access_token, ErrorCode.KEY_VERSION_STALE),
        (tokens.refresh_token, ErrorCode.KEY_VERSION_STALE),
    ):
        with pytest.raises(AuthError) as exc:
            service.refresh(raw) if raw == tokens.refresh_token else service.authenticate(raw)
        assert exc.value.code is expected

    # logout still works with an old-key token (payload-based locate)
    service.logout(tokens.refresh_token)


def test_refresh_revoked_family_after_other_member_logout():
    service, _ = build_service()
    tokens = login(service)
    rotated = service.refresh(tokens.refresh_token)
    service.logout(rotated.refresh_token)
    # even the latest credential is dead after logout
    with pytest.raises(AuthError) as exc:
        service.refresh(rotated.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED


def test_mfa_failures_isolated_by_source():
    service, _ = build_service()
    ch_web = service.begin_login("alice", "pw", "web")
    codes = []
    for _ in range(5):
        with pytest.raises(AuthError) as exc:
            service.complete_login(ch_web.challenge_id, "000000")
        codes.append(exc.value.code)
    assert codes == [
        ErrorCode.TOTP_INVALID,
        ErrorCode.TOTP_INVALID,
        ErrorCode.MFA_RATE_LIMITED,
        ErrorCode.MFA_RATE_LIMITED,
        ErrorCode.MFA_LOCKED,
    ]

    # A different source is not locked for the same user.
    ch_mobile = service.begin_login("alice", "pw", "mobile")
    code = service.totp_provisioning_code("alice")
    tokens = service.complete_login(ch_mobile.challenge_id, code)
    assert tokens.access_token


def test_refresh_after_session_revoked_is_distinguishable():
    service, _ = build_service()
    tokens = login(service)
    service.store.revoke_session(
        service.keyring.verify(tokens.refresh_token).sid, "admin_revoke")
    with pytest.raises(AuthError) as exc:
        service.refresh(tokens.refresh_token)
    assert exc.value.code is ErrorCode.SESSION_REVOKED


def test_random_token_strings_are_rejected_as_invalid():
    service, _ = build_service()
    login(service)
    for garbage in ("", "abc", "a.b", "...."):
        with pytest.raises(AuthError) as exc:
            service.refresh(garbage)
        assert exc.value.code is ErrorCode.REFRESH_TOKEN_INVALID
