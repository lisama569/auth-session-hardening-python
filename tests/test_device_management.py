"""Multi-device session management + step-up reauthentication tests.

Covers:
* session listing (stable id, source, created_at, current-session marker)
* single-session and batch ("sign out other devices") termination
* foreign vs nonexistent session ids being externally identical (404)
* reauthentication freshness window boundaries (exclusive upper edge)
* one-time-code non-replay (sequential and concurrent)
* refresh rotation interleaved with concurrent termination

All timing is driven by a FixedClock and TOTP codes are produced with
``service.totp_provisioning_code`` — no network or real IdP involved.
"""
from __future__ import annotations

import threading

import pytest

from auth.authz import Authorizer, ResourceSpec
from auth.clock import FixedClock
from auth.errors import AuthError, ErrorCode
from auth.mfa import TotpVerifier
from auth.sessions import SessionService
from auth.store import RefreshRecord, Store
from auth.tokens import KeyRing
from tests.conftest_service import build_service
from tests.test_sessions import login


def build_reauth_service(start: float = 1_000_000.0, *, window: float = 300.0,
                         access_ttl: float = 100_000.0):
    """Service with a long access TTL so freshness boundaries are isolated
    from ordinary access-token expiry."""
    clock = FixedClock(start)
    store = Store(clock=clock)
    keyring = KeyRing(clock=clock)
    verifier = TotpVerifier(clock=clock)
    authorizer = Authorizer(store)
    service = SessionService(
        store, keyring, verifier, authorizer, clock=clock,
        access_ttl=access_ttl, refresh_ttl=3_600.0,
        reauth_window=window,
    )
    service.register_user("alice", "pw", scopes={"docs:read", "profile:read"})
    service.register_user("bob", "pw", scopes={"docs:read", "profile:read"})
    for name, scope in (("docs", "docs:read"), ("profile", "profile:read")):
        authorizer.register_resource(ResourceSpec(name, frozenset({scope})))
    return service, clock


def _totp(service, clock):
    return service.totp_provisioning_code("alice", clock.now())


# ---------------------------------------------------------------- listing

def test_list_sessions_reports_stable_id_source_time_and_current():
    service, clock = build_reauth_service()
    web = login(service, "alice", "web")
    clock.advance(5)
    mobile = login(service, "alice", "mobile")

    sessions = service.list_sessions(web.access_token)
    assert [s.source for s in sessions] == ["web", "mobile"]  # oldest first
    by_source = {s.source: s for s in sessions}
    assert by_source["web"].current is True
    assert by_source["mobile"].current is False

    # The same list viewed from the other device flips the current marker,
    # and ids are stable references.
    other = {s.source: s for s in service.list_sessions(mobile.access_token)}
    assert other["mobile"].current is True
    assert other["web"].current is False
    assert other["web"].session_id == by_source["web"].session_id
    assert other["mobile"].session_id == by_source["mobile"].session_id

    # Revoked sessions disappear from the listing.
    service.revoke_session(web.access_token, by_source["mobile"].session_id)
    remaining = service.list_sessions(web.access_token)
    assert [s.source for s in remaining] == ["web"]


def test_revoked_session_credentials_die_immediately_but_siblings_live():
    service, _ = build_reauth_service()
    web = login(service, "alice", "web")
    mobile = login(service, "alice", "mobile")
    cli = login(service, "alice", "cli")
    target = service.keyring.verify(mobile.access_token).sid

    service.revoke_session(web.access_token, target)

    # both credential kinds of the named session are rejected distinctly
    with pytest.raises(AuthError) as exc:
        service.authenticate(mobile.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    with pytest.raises(AuthError) as exc:
        service.refresh(mobile.refresh_token)
    assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED

    # sessions not named in the request are completely unaffected
    assert service.authenticate(web.access_token).session_id == \
        service.keyring.verify(web.access_token).sid
    rotated = service.refresh(cli.refresh_token)
    assert service.authenticate(rotated.access_token).user_id == "alice"


def test_revoked_session_access_is_distinguishable_from_missing_session():
    service, _ = build_reauth_service()
    web = login(service, "alice", "web")
    mobile = login(service, "alice", "mobile")
    sid = service.keyring.verify(mobile.access_token).sid
    service.revoke_session(web.access_token, sid)

    # presenting the killed access token: session exists-but-revoked
    with pytest.raises(AuthError) as exc:
        service.authenticate(mobile.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED

    # a validly signed token pointing at a session id that never existed
    # is a different, distinguishable outcome
    from auth.tokens import TokenClaims
    claims = service.keyring.verify(web.access_token)
    ghost = TokenClaims(
        jti=claims.jti, typ="access", sub="alice", sid="sess_never_existed",
        kid=service.keyring.kid, iat=claims.iat, exp=claims.exp, ver=0,
        scopes=claims.scopes,
    )
    token = service.keyring.sign(ghost.to_dict())
    with pytest.raises(AuthError) as exc:
        service.authenticate(token)
    assert exc.value.code is ErrorCode.SESSION_NOT_FOUND


# ------------------------------------------------- ownership / existence

def test_foreign_and_nonexistent_session_ids_are_indistinguishable():
    service, _ = build_reauth_service()
    alice = login(service, "alice", "web")
    bob = login(service, "bob", "web")
    bob_sid = service.keyring.verify(bob.access_token).sid

    targets = {
        "nonexistent": "sess_does_not_exist",
        "foreign": bob_sid,
        "already_revoked": None,  # filled below
    }
    already = service.keyring.verify(alice.access_token).sid
    # alice terminates one of her own sessions first...
    extra = login(service, "alice", "cli")
    extra_sid = service.keyring.verify(extra.access_token).sid
    service.revoke_session(alice.access_token, extra_sid)
    targets["already_revoked"] = extra_sid

    answers = {}
    for label, sid in targets.items():
        with pytest.raises(AuthError) as exc:
            service.revoke_session(alice.access_token, sid)
        answers[label] = exc.value.code
    # every case: same error code ...
    assert answers == {
        "nonexistent": ErrorCode.NOT_FOUND,
        "foreign": ErrorCode.NOT_FOUND,
        "already_revoked": ErrorCode.NOT_FOUND,
    }

    # ... and bob's session is untouched by alice's failed attempts
    assert service.authenticate(bob.access_token).user_id == "bob"

    # every sensitive entry shares the rule: revoke-others never takes a
    # foreign id either (it can only ever target the caller's own account)
    bob_session = service.store.get_session(bob_sid)
    assert bob_session is not None and not bob_session.revoked


def test_revoke_others_keeps_current_session_and_kills_the_rest():
    service, _ = build_reauth_service()
    web = login(service, "alice", "web")
    mobile = login(service, "alice", "mobile")
    cli = login(service, "alice", "cli")
    bob = login(service, "bob", "web")

    code = _totp(service, service._clock)
    result = service.revoke_other_sessions(web.access_token, code)
    terminated = set(result.terminated_session_ids)
    assert terminated == {
        service.keyring.verify(mobile.access_token).sid,
        service.keyring.verify(cli.access_token).sid,
    }
    assert result.reauthenticated is True

    # current session's access + refresh remain fully usable
    assert service.authenticate(web.access_token).user_id == "alice"
    rotated = service.refresh(web.access_token and web.refresh_token)
    assert service.authenticate(rotated.access_token).user_id == "alice"

    # other devices: both credential types dead
    for tokens in (mobile, cli):
        with pytest.raises(AuthError) as exc:
            service.authenticate(tokens.access_token)
        assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
        with pytest.raises(AuthError) as exc:
            service.refresh(tokens.refresh_token)
        assert exc.value.code is ErrorCode.REFRESH_TOKEN_REVOKED

    # other accounts are not touched
    assert service.authenticate(bob.access_token).user_id == "bob"


# -------------------------------------------------- freshness window rules

def test_sensitive_op_requires_fresh_reauth():
    service, _ = build_reauth_service(window=300.0)
    web = login(service, "alice", "web")
    login(service, "alice", "mobile")
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED

    # still rejected right after a plain login (login-time MFA does not
    # itself count as a step-up for a later sensitive operation)
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_freshness_window_boundary_is_exclusive_and_predictable():
    service, clock = build_reauth_service(window=300.0)
    web = login(service, "alice", "web")
    login(service, "alice", "mobile")

    service.reauthenticate(web.access_token, _totp(service, clock))

    # anywhere strictly inside the window: admitted (no new code needed)
    clock.advance(299.999)
    assert service.revoke_other_sessions(web.access_token).reauthenticated is False

    # the sensitive call does not itself extend freshness
    # exactly at t0 + window: lapsed (exclusive boundary)
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED

    # and one epsilon later: still lapsed, same answer
    clock.advance(0.001)
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED


def test_successful_reauth_within_window_slides_freshness_forward():
    service, clock = build_reauth_service(window=300.0)
    web = login(service, "alice", "web")
    login(service, "alice", "mobile")

    service.reauthenticate(web.access_token, _totp(service, clock))
    clock.advance(200)
    # another successful verification slides the deadline to now + window
    service.reauthenticate(web.access_token, _totp(service, clock))
    clock.advance(299.999)  # 499.999 since first reauth, <300 since second
    result = service.revoke_other_sessions(web.access_token)
    assert result.reauthenticated is False

    # providing a fresh code together with the sensitive op also slides
    clock.advance(1)  # exactly 300 after second reauth -> lapsed
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED
    result = service.revoke_other_sessions(web.access_token, _totp(service, clock))
    assert result.reauthenticated is True
    clock.advance(299.999)
    assert service.revoke_other_sessions(web.access_token).reauthenticated is False


# --------------------------------------- distinguishable rejection reasons

def test_reauth_rejections_are_all_distinguishable():
    service, clock = build_reauth_service()
    web = login(service, "alice", "web")
    login(service, "alice", "mobile")

    # stale freshness
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token)
    assert exc.value.code is ErrorCode.REAUTH_REQUIRED

    # plain wrong code
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, "000000")
    assert exc.value.code is ErrorCode.TOTP_INVALID

    # clock-skew-only code (2 periods back, outside ±1 tolerance window)
    skew_code = service.totp_provisioning_code("alice", clock.now() - 60)
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, skew_code)
    assert exc.value.code is ErrorCode.TOTP_CLOCK_SKEW

    # rate limited at the third failure
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, "111111")
    assert exc.value.code is ErrorCode.MFA_RATE_LIMITED


def test_reauth_locked_is_distinct_from_required():
    service, clock = build_reauth_service()
    web = login(service, "alice", "web")
    # 5 failures -> locked (thresholds are the verifier defaults)
    for bad in ("000000", "111111", "222222", "333333", "444444"):
        try:
            service.reauthenticate(web.access_token, bad)
        except AuthError:
            pass
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(web.access_token, _totp(service, clock))
    assert exc.value.code is ErrorCode.MFA_LOCKED
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, _totp(service, clock))
    assert exc.value.code is ErrorCode.MFA_LOCKED


# -------------------------------------------------- one-time code non-replay

def test_step_up_code_cannot_be_replayed_for_a_second_sensitive_op():
    service, clock = build_reauth_service()
    web = login(service, "alice", "web")
    login(service, "alice", "mobile")
    code = _totp(service, clock)

    assert service.revoke_other_sessions(web.access_token, code).reauthenticated is True

    # same code, second sensitive operation -> replay, nothing is terminated
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, code)
    assert exc.value.code is ErrorCode.REAUTH_CODE_REUSED

    # replay must not have tampered with failure accounting: a brand-new
    # code at the next period still succeeds
    clock.advance(30)
    assert service.revoke_other_sessions(
        web.access_token, _totp(service, clock)).reauthenticated is True

    # the old code is dead in the new period too (it simply doesn't match;
    # either invalid or — if within skew — still consumed), never accepted
    clock.advance(30)
    with pytest.raises(AuthError) as exc:
        service.revoke_other_sessions(web.access_token, code)
    assert exc.value.code in (
        ErrorCode.TOTP_INVALID, ErrorCode.REAUTH_CODE_REUSED,
        ErrorCode.TOTP_CLOCK_SKEW,
    )


def test_consumed_step_is_rejected_for_other_sessions_of_same_user():
    service, clock = build_reauth_service()
    web = login(service, "alice", "web")
    mobile = login(service, "alice", "mobile")
    code = _totp(service, clock)
    service.reauthenticate(web.access_token, code)
    # the one-time code cannot fund a step-up on a sibling session either
    with pytest.raises(AuthError) as exc:
        service.reauthenticate(mobile.access_token, code)
    assert exc.value.code is ErrorCode.REAUTH_CODE_REUSED


# ------------------------------------------------------------- concurrency

class _StepUpBarrierService(SessionService):
    """Pauses the FIRST step-up between code verification and the atomic
    step consumption, creating a deterministic replay race."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gate = threading.Event()
        self.arrived = threading.Event()
        self._arm_block = True

    def _reauth_about_to_consume(self, user_id, absolute_step):  # noqa: D401
        if not self._arm_block:
            return
        self._arm_block = False
        self.arrived.set()
        self.gate.wait()


def test_concurrent_step_up_with_same_code_only_one_consumes():
    service, clock = build_reauth_service()
    barrier = _StepUpBarrierService(
        service.store, service.keyring, service.verifier, service.authorizer,
        clock, access_ttl=100_000.0, refresh_ttl=3_600.0, reauth_window=300.0,
    )
    web = login(barrier, "alice", "web")
    mobile = login(barrier, "alice", "mobile")
    code = _totp(barrier, clock)

    outcomes: list[ErrorCode | str] = []
    lock = threading.Lock()

    def first():
        try:
            barrier.reauthenticate(web.access_token, code)
            with lock:
                outcomes.append("ok")
        except AuthError as exc:
            with lock:
                outcomes.append(exc.code)

    t1 = threading.Thread(target=first)
    t1.start()
    assert barrier.arrived.wait(2.0), "first step-up never reached consume"

    def second():
        try:
            barrier.reauthenticate(mobile.access_token, code)
            with lock:
                outcomes.append("ok")
        except AuthError as exc:
            with lock:
                outcomes.append(exc.code)

    t2 = threading.Thread(target=second)
    t2.start()
    t2.join(timeout=2.0)
    barrier.gate.set()
    t1.join(timeout=2.0)

    def _label(o):
        return o.value if isinstance(o, ErrorCode) else o

    assert sorted(_label(o) for o in outcomes) == sorted(
        ["ok", ErrorCode.REAUTH_CODE_REUSED.value]), outcomes

    # only one step number was ever recorded; freshness was stamped once
    step = service.verifier.step_at(clock.now())
    assert service.store.reauth_step_consumed("alice", step)
    web_session = service.store.get_session(
        service.keyring.verify(web.access_token).sid)
    mobile_session = service.store.get_session(
        service.keyring.verify(mobile.access_token).sid)
    stamped = [s.last_reauth_at is not None for s in (web_session, mobile_session)]
    # exactly one of the two racing callers won — identity is not assumed
    assert sorted(stamped) == [False, True]


def test_terminate_other_devices_during_inflight_refresh_is_consistent():
    from tests.test_concurrent_refresh import BarrierService

    base, clock = build_reauth_service()
    barrier = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=100_000.0, refresh_ttl=3_600.0,
    )
    web = login(barrier, "alice", "web")
    mobile = login(barrier, "alice", "mobile")
    mobile_jti = barrier.keyring.verify(mobile.refresh_token).jti

    holder: dict[str, object] = {}

    def refreshing():
        try:
            holder["result"] = barrier.refresh(mobile.refresh_token)
        except AuthError as exc:
            holder["result"] = exc.code

    t = threading.Thread(target=refreshing)
    t.start()
    barrier.wait_until_claimed(mobile_jti)

    # While the rotation is in flight (claimed, not committed), another
    # device performs a step-up and signs everyone else out.
    result = barrier.revoke_other_sessions(web.access_token, _totp(barrier, clock))
    assert service_sid(barrier, mobile.access_token) in result.terminated_session_ids

    barrier.open_gate()
    t.join(timeout=2.0)

    # the in-flight refresh must not have slipped through after revocation
    assert holder["result"] is ErrorCode.SESSION_REVOKED, holder["result"]

    # mobile credentials are dead either way; the current session lives
    with pytest.raises(AuthError) as exc:
        barrier.authenticate(mobile.access_token)
    assert exc.value.code is ErrorCode.ACCESS_TOKEN_REVOKED
    assert barrier.authenticate(web.access_token).user_id == "alice"
    assert barrier.refresh(web.refresh_token).access_token

    # no successor credential was ever stored for the killed family
    active = [r for r in barrier.store._refreshes.values() if r.state.value == "active"]
    assert all(r.session_id == service_sid(barrier, web.access_token) for r in active)


def service_sid(service, access_token: str) -> str:
    return service.keyring.verify(access_token).sid


def test_single_revoke_racing_inflight_refresh_is_consistent():
    from tests.test_concurrent_refresh import BarrierService

    base, clock = build_reauth_service()
    barrier = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=100_000.0, refresh_ttl=3_600.0,
    )
    web = login(barrier, "alice", "web")
    mobile = login(barrier, "alice", "mobile")
    mobile_sid = service_sid(barrier, mobile.access_token)
    mobile_jti = barrier.keyring.verify(mobile.refresh_token).jti

    holder: dict[str, object] = {}

    def refreshing():
        try:
            holder["result"] = barrier.refresh(mobile.refresh_token)
        except AuthError as exc:
            holder["result"] = exc.code

    t = threading.Thread(target=refreshing)
    t.start()
    barrier.wait_until_claimed(mobile_jti)
    barrier.revoke_session(web.access_token, mobile_sid)
    barrier.open_gate()
    t.join(timeout=2.0)

    assert holder["result"] is ErrorCode.SESSION_REVOKED
    assert barrier.authenticate(web.access_token).user_id == "alice"


# --------------------------------------------------------------- HTTP layer

def test_http_device_management_end_to_end():
    from fastapi.testclient import TestClient
    from auth.app import build_app

    base, clock = build_reauth_service()
    http = TestClient(build_app(base, seeded=False))

    def http_login(source):
        ch = http.post("/auth/login/start",
                       json={"user_id": "alice", "password": "pw", "source": source})
        assert ch.status_code == 200
        code = base.totp_provisioning_code("alice", clock.now())
        done = http.post("/auth/login/complete",
                         json={"challenge_id": ch.json()["challenge_id"], "code": code})
        assert done.status_code == 200
        return done.json()

    web = http_login("web")
    mobile = http_login("mobile")
    h = {"Authorization": f"Bearer {web['access_token']}"}

    # listing shape
    r = http.get("/auth/sessions", headers=h)
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert [s["source"] for s in sessions] == ["web", "mobile"]
    assert sessions[0]["session_id"].startswith("sess_")
    assert sessions[0]["current"] is True
    assert sessions[1]["current"] is False
    assert isinstance(sessions[0]["created_at"], float)

    # no / malformed Authorization header -> 401 / 400
    assert http.get("/auth/sessions").status_code == 401
    assert http.get("/auth/sessions", headers={"Authorization": "Bearer junk"}
                    ).status_code == 400

    # log bob in on a third device so we can probe cross-account access
    ch = http.post("/auth/login/start",
                   json={"user_id": "bob", "password": "pw", "source": "cli"})
    bcode = base.totp_provisioning_code("bob", clock.now())
    bob = http.post("/auth/login/complete",
                    json={"challenge_id": ch.json()["challenge_id"], "code": bcode}).json()
    bob_sid = base.keyring.verify(bob["access_token"]).sid

    r_foreign = http.post("/auth/sessions/revoke",
                          json={"session_id": bob_sid}, headers=h)
    r_missing = http.post("/auth/sessions/revoke",
                          json={"session_id": "sess_nope"}, headers=h)
    assert (r_foreign.status_code, r_foreign.json()) == (404, {"error": "not_found"})
    assert (r_missing.status_code, r_missing.json()) == (404, {"error": "not_found"})

    # sensitive op without freshness -> 403, distinct from wrong code (400)
    r = http.post("/auth/sessions/revoke-others", json={}, headers=h)
    assert r.status_code == 403 and r.json()["error"] == "reauth_required"
    r = http.post("/auth/sessions/revoke-others", json={"code": "000000"}, headers=h)
    assert r.status_code == 400 and r.json()["error"] == "totp_invalid"

    # code replay over HTTP -> 409
    code = base.totp_provisioning_code("alice", clock.now())
    r = http.post("/auth/sessions/revoke-others", json={"code": code}, headers=h)
    assert r.status_code == 200
    assert len(r.json()["terminated_session_ids"]) == 1
    assert r.json()["reauthenticated"] is True
    r2 = http.post("/auth/sessions/revoke-others", json={"code": code}, headers=h)
    assert r2.status_code == 409 and r2.json()["error"] == "reauth_code_reused"

    # mobile is dead, web alive — at both credential types
    assert http.get("/resources/docs",
                    headers={"Authorization": f"Bearer {mobile['access_token']}"}
                    ).status_code == 409
    assert http.post("/auth/refresh",
                     json={"refresh_token": mobile["refresh_token"]}
                     ).json()["error"] == "refresh_token_revoked"
    assert http.get("/resources/docs", headers=h).status_code == 200

    # dedicated reauth endpoint grants freshness for a subsequent call
    clock.advance(30)  # next TOTP period: a genuinely fresh code
    code = base.totp_provisioning_code("alice", clock.now())
    r = http.post("/auth/reauthenticate", json={"code": code}, headers=h)
    assert r.status_code == 200 and r.json() == {"status": "reauthenticated"}
    r = http.post("/auth/sessions/revoke-others", json={}, headers=h)
    assert r.status_code == 200 and r.json()["reauthenticated"] is False


def test_http_revoke_single_session_shape():
    from fastapi.testclient import TestClient
    from auth.app import build_app

    base, clock = build_reauth_service()
    http = TestClient(build_app(base, seeded=False))
    ch = http.post("/auth/login/start",
                   json={"user_id": "alice", "password": "pw", "source": "web"})
    code = base.totp_provisioning_code("alice", clock.now())
    web = http.post("/auth/login/complete",
                    json={"challenge_id": ch.json()["challenge_id"], "code": code}).json()
    ch = http.post("/auth/login/start",
                   json={"user_id": "alice", "password": "pw", "source": "mobile"})
    code = base.totp_provisioning_code("alice", clock.now())
    mobile = http.post("/auth/login/complete",
                       json={"challenge_id": ch.json()["challenge_id"], "code": code}).json()
    h = {"Authorization": f"Bearer {web['access_token']}"}
    sid = base.keyring.verify(mobile["access_token"]).sid
    r = http.post("/auth/sessions/revoke", json={"session_id": sid}, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "revoked"


def test_revoke_others_does_not_kill_inflight_refresh_of_current_session():
    """The kept device's own in-flight refresh must commit normally even
    while a batch termination for the same account is in progress."""
    from tests.test_concurrent_refresh import BarrierService

    base, clock = build_reauth_service()
    barrier = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, clock,
        access_ttl=100_000.0, refresh_ttl=3_600.0,
    )
    web = login(barrier, "alice", "web")
    login(barrier, "alice", "mobile")
    web_jti = barrier.keyring.verify(web.refresh_token).jti

    holder: dict[str, object] = {}

    def refreshing():
        try:
            holder["result"] = barrier.refresh(web.refresh_token)
        except AuthError as exc:
            holder["result"] = exc.code

    t = threading.Thread(target=refreshing)
    t.start()
    barrier.wait_until_claimed(web_jti)
    # batch termination happens while the CURRENT session's refresh is
    # in flight; the current session is explicitly excluded
    result = barrier.revoke_other_sessions(web.access_token, _totp(barrier, clock))
    assert result.terminated_session_ids  # the other device was terminated
    barrier.open_gate()
    t.join(timeout=2.0)

    new_tokens = holder["result"]
    assert hasattr(new_tokens, "access_token"), new_tokens
    assert barrier.authenticate(new_tokens.access_token).user_id == "alice"
    assert barrier.refresh(new_tokens.refresh_token).access_token
