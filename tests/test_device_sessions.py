"""Multi-device session management: listing, targeted and bulk revocation.

Covers the externally observable guarantees:

* each session has a stable id, source, creation time and a ``current``
  marker identifying the session of the request in progress;
* targeted / bulk revocation kills both access and refresh credentials
  immediately with distinguishable reasons;
* foreign-owned and nonexistent session ids are *indistinguishable*;
* untouched sessions of the same account keep working.
"""
import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service
from tests.test_sessions import login


def _ctx(service, tokens):
    return service.authenticate(tokens.access_token)


def _second_login(service, user="alice", source="mobile"):
    # A second device presents a *fresh* one-time code: one OTP can only
    # ever complete one login (per-user consumption ledger).
    service._clock.advance(31.0)
    return login(service, user=user, source=source)


def test_list_sessions_shows_metadata_and_marks_current():
    service, clock = build_service()
    web_login_at = clock.now()
    web = login(service, source="web")
    mobile = _second_login(service, source="mobile")
    mobile_login_at = clock.now()

    web_ctx = _ctx(service, web)
    mob_ctx = _ctx(service, mobile)
    infos = service.list_sessions(web_ctx)
    by_id = {s.session_id: s for s in infos}

    assert set(by_id) == {web_ctx.session_id, mob_ctx.session_id}
    assert by_id[web_ctx.session_id].current is True
    assert by_id[web_ctx.session_id].source == "web"
    assert by_id[mob_ctx.session_id].current is False
    assert by_id[mob_ctx.session_id].source == "mobile"
    # ids are stable references across calls
    again = {s.session_id for s in service.list_sessions(web_ctx)}
    assert again == set(by_id)
    # created_at is the login instant of each session
    assert by_id[web_ctx.session_id].created_at == web_login_at
    assert by_id[mob_ctx.session_id].created_at == mobile_login_at

    # Viewed from the mobile session, the current marker flips.
    mob_infos = {s.session_id: s for s in service.list_sessions(mob_ctx)}
    assert mob_infos[mob_ctx.session_id].current is True
    assert mob_infos[web_ctx.session_id].current is False


def test_terminate_one_session_kills_its_tokens_but_not_siblings():
    service, _ = build_service()
    web = login(service, source="web")
    mobile = _second_login(service, source="mobile")
    web_ctx = _ctx(service, web)
    mob_ctx = _ctx(service, mobile)

    service.terminate_session(web_ctx, mob_ctx.session_id)

    # revoked access/refresh credentials fail with distinguishable codes
    with pytest.raises(AuthError) as exc:
        service.authenticate(mobile.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    with pytest.raises(AuthError) as exc:
        service.refresh(mobile.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED

    # revoked session no longer listed; the caller's own session intact
    remaining = {s.session_id for s in service.list_sessions(web_ctx)}
    assert remaining == {web_ctx.session_id}
    ctx = service.authenticate(web.access_token)
    assert ctx.session_id == web_ctx.session_id

    # terminating an already-revoked session looks exactly like "missing"
    with pytest.raises(AuthError) as exc:
        service.terminate_session(web_ctx, mob_ctx.session_id)
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND


def test_terminate_current_session_is_allowed():
    service, _ = build_service()
    web = login(service, source="web")
    ctx = _ctx(service, web)
    service.terminate_session(ctx, ctx.session_id)
    with pytest.raises(AuthError) as exc:
        service.authenticate(web.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    assert service.list_sessions(ctx) == []


def test_foreign_and_nonexistent_session_ids_are_indistinguishable():
    service, _ = build_service()
    alice = login(service, user="alice", source="web")
    bob = login(service, user="bob", source="mobile")
    alice_ctx = _ctx(service, alice)
    bob_ctx = _ctx(service, bob)

    # Alice cannot manage Bob's session: same error as a nonexistent id.
    with pytest.raises(AuthError) as exc:
        service.terminate_session(alice_ctx, bob_ctx.session_id)
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND
    with pytest.raises(AuthError) as exc:
        service.terminate_session(alice_ctx, "sess_does_not_exist")
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND

    # Bob's session is completely unaffected by Alice's attempt.
    infos = {s.session_id for s in service.list_sessions(bob_ctx)}
    assert bob_ctx.session_id in infos
    assert service.authenticate(bob.access_token).session_id == bob_ctx.session_id

    # Listing is owner-scoped: Alice never sees Bob's session.
    assert bob_ctx.session_id not in {
        s.session_id for s in service.list_sessions(alice_ctx)
    }


def test_logout_others_revokes_all_but_current():
    service, _ = build_service()
    current = login(service, source="web")
    other_a = _second_login(service, source="mobile")
    other_b = _second_login(service, source="cli")
    ctx = _ctx(service, current)

    count = service.logout_other_sessions(ctx)
    assert count == 2

    for tokens in (other_a, other_b):
        with pytest.raises(AuthError) as exc:
            service.authenticate(tokens.access_token)
        assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
        with pytest.raises(AuthError) as exc:
            service.refresh(tokens.refresh_token)
        assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED

    # current session remains fully usable, access + refresh
    assert service.authenticate(current.access_token).session_id == ctx.session_id
    rotated = service.refresh(current.refresh_token)
    assert service.authenticate(rotated.access_token).session_id == ctx.session_id

    # idempotent: no further sessions to terminate
    assert service.logout_other_sessions(_ctx(service, rotated)) == 0


def test_consumed_totp_step_history_is_bounded():
    from auth.store import MFA_STEPS_RETAINED
    service, _ = build_service()
    tokens = login(service)
    sid = service.keyring.verify(tokens.access_token).sid

    # login already consumed one step; mark many more distinct steps.
    for step in range(1, MFA_STEPS_RETAINED + 5):
        assert service.store.mark_mfa_verified(sid, float(step), step) is True

    _, consumed = service.store.get_mfa_state(sid)
    assert len(consumed) <= MFA_STEPS_RETAINED
    # the most recent steps are retained, oldest pruned
    assert (MFA_STEPS_RETAINED + 4) in consumed
    assert 1 not in consumed
