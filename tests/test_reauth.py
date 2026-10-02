"""Step-up reauthentication for sensitive operations.

Guarantees under test:

* a sensitive op needs a second factor verified within the configurable
  freshness window; the boundary is *inclusive* (``now == fresh_until``
  admitted, ``now == fresh_until + epsilon`` rejected);
* rejection is a distinct ``reauth_required``, separate from a wrong
  code (``totp_invalid``) and throttling/locking;
* the one-time code used for a step-up cannot authorize a second op
  (``totp_replay``); a fresh step-up slides the window forward;
* login itself establishes freshness and consumes its code.
"""
import pytest

from auth.errors import AuthError, ErrorCode
from tests.conftest_service import build_service
from tests.test_sessions import login

WINDOW = 120.0


def _svc():
    return build_service(reauth_freshness=WINDOW)


def _code(service, user="alice"):
    return service.totp_provisioning_code(user, service._clock.now())


def test_fresh_right_after_login_but_stale_after_window():
    service, clock = _svc()
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)

    # immediately after login the sensitive op is admitted
    assert service.logout_other_sessions(ctx) == 0

    # exactly at the boundary: still admitted (inclusive)
    clock.advance(WINDOW)
    assert service.logout_other_sessions(ctx) == 0

    # one epsilon past the boundary: reauth required
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.logout_other_sessions(ctx)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_reauth_extends_window_from_new_instant():
    service, clock = _svc()
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)

    clock.advance(WINDOW - 10.0)
    result = service.reauthenticate(ctx, _code(service))
    assert result.verified_at == clock.now()
    assert result.fresh_until == clock.now() + WINDOW

    # the window slid: advancing to what would have been the old edge is
    # still well within the new window
    clock.advance(20.0)
    assert service.logout_other_sessions(ctx) == 0

    # and the new far boundary is again inclusive
    clock.advance(WINDOW - 20.0)
    assert service.logout_other_sessions(ctx) == 0
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.logout_other_sessions(ctx)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_reauth_failures_are_distinguishable():
    service, clock = _svc()
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)

    # wrong code -> totp_invalid (and does not grant freshness)
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, "000000")
    assert exc.value.code is ErrorCode.TOTP_INVALID

    # drive the verifier into rate limiting (3rd failure): distinct code
    with pytest.raises(AuthError):
        service.reauthenticate(ctx, "111111")
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, "222222")
    assert exc.value.code is ErrorCode.MFA_RATE_LIMITED

    # freshness state untouched by failed attempts; window still anchored
    # at login, so past it the sensitive op demands reauth
    clock.advance(WINDOW + 1.0)
    with pytest.raises(AuthError) as exc:
        service.logout_other_sessions(ctx)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_one_time_code_cannot_be_replayed():
    # Freshness window (40s) is longer than one TOTP step (30s), so the
    # reauth happens with a *new* step's code. The replay stays inside
    # both the freshness window and the code's tolerance window, proving
    # the rejection is replay detection rather than staleness.
    service, clock = build_service(reauth_freshness=40.0)
    tokens = login(service)                 # t0: consumes TOTP step 0
    ctx = service.authenticate(tokens.access_token)

    clock.advance(31.0)                     # t31: step 1 is now valid
    code = _code(service)
    assert service.reauthenticate(ctx, code).fresh_until == clock.now() + 40.0

    # same one-time code again within its 30s validity -> replay
    clock.advance(1.0)                      # t32, still step 1
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY

    # the rejected replay must not have slid the window (still t71):
    # exactly t71 admitted, t71.001 refused
    clock.advance(39.0)                     # t71
    assert service.logout_other_sessions(ctx) == 0
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.logout_other_sessions(ctx)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_login_code_is_consumed_for_reauth():
    service, clock = _svc()
    challenge = service.begin_login("alice", "pw", "web")
    code = service.totp_provisioning_code("alice", clock.now())
    tokens = service.complete_login(challenge.challenge_id, code)
    ctx = service.authenticate(tokens.access_token)

    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, code)
    assert exc.value.code is ErrorCode.TOTP_REPLAY


def test_revoked_session_cannot_escalate_via_reauth():
    service, _ = _svc()
    tokens = login(service)
    ctx = service.authenticate(tokens.access_token)
    service.terminate_session(ctx, ctx.session_id)
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(ctx, _code(service))
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND
