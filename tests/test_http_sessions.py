"""HTTP shape of the multi-device session management endpoints."""
import pytest
from fastapi.testclient import TestClient

from auth.app import build_app
from tests.conftest_service import build_service
from tests.test_sessions import login


@pytest.fixture()
def stack():
    service, clock = build_service(reauth_freshness=120.0)
    http = TestClient(build_app(service, seeded=False))
    return http, service, clock


def _http_login(http, service, clock, user="alice", source="web"):
    ch = http.post("/auth/login/start",
                   json={"user_id": user, "password": "pw", "source": source})
    assert ch.status_code == 200, ch.text
    code = service.totp_provisioning_code(user, clock.now())
    res = http.post("/auth/login/complete",
                    json={"challenge_id": ch.json()["challenge_id"], "code": code})
    assert res.status_code == 200, res.text
    return res.json()


def _sid(service, tokens):
    return service.keyring.verify(tokens["access_token"]).sid


def test_list_and_terminate_over_http(stack):
    http, service, clock = stack
    web = _http_login(http, service, clock, source="web")
    mob = _http_login(http, service, clock, source="mobile")
    h = {"Authorization": f"Bearer {web['access_token']}"}

    r = http.get("/auth/sessions", headers=h)
    assert r.status_code == 200
    sessions = r.json()["sessions"]
    assert len(sessions) == 2
    current = [s for s in sessions if s["current"]]
    assert len(current) == 1
    assert current[0]["session_id"] == _sid(service, web)
    assert {s["source"] for s in sessions} == {"web", "mobile"}
    assert all("created_at" in s for s in sessions)

    target = _sid(service, mob)
    r = http.post("/auth/sessions/terminate", headers=h, json={"session_id": target})
    assert r.status_code == 200
    assert r.json()["status"] == "terminated"

    # victim's credentials die with distinguishable codes
    r = http.get("/auth/sessions",
                 headers={"Authorization": f"Bearer {mob['access_token']}"})
    assert r.status_code == 409
    assert r.json()["error"] == "access_token_revoked"
    r = http.post("/auth/refresh", json={"refresh_token": mob["refresh_token"]})
    assert r.status_code == 409
    assert r.json()["error"] == "refresh_token_revoked"


def test_foreign_and_missing_ids_are_identical_404(stack):
    http, service, clock = stack
    alice = _http_login(http, service, clock, user="alice", source="web")
    bob = _http_login(http, service, clock, user="bob", source="mobile")
    h = {"Authorization": f"Bearer {alice['access_token']}"}

    r_foreign = http.post("/auth/sessions/terminate", headers=h,
                          json={"session_id": _sid(service, bob)})
    r_missing = http.post("/auth/sessions/terminate", headers=h,
                          json={"session_id": "sess_ghost"})
    assert r_foreign.status_code == r_missing.status_code == 404
    assert r_foreign.json() == r_missing.json() == {"error": "session_not_found"}

    # bob untouched
    r = http.get("/auth/sessions",
                 headers={"Authorization": f"Bearer {bob['access_token']}"})
    assert r.status_code == 200
    assert len(r.json()["sessions"]) == 1


def test_logout_others_step_up_then_success(stack):
    http, service, clock = stack
    cur = _http_login(http, service, clock, source="web")
    _http_login(http, service, clock, source="mobile")
    _http_login(http, service, clock, source="cli")
    h = {"Authorization": f"Bearer {cur['access_token']}"}

    # fresh right after login
    r = http.post("/auth/sessions/logout-others", headers=h)
    assert r.status_code == 200
    assert r.json()["terminated"] == 2
    # current session survives
    assert http.get("/auth/sessions", headers=h).status_code == 200

    # after the window the sensitive op is refused with a distinct 403
    clock.advance(120.001)
    r = http.post("/auth/sessions/logout-others", headers=h)
    assert r.status_code == 403
    assert r.json()["error"] == "reauth_required"

    # a wrong code is a different result (400), not the step-up signal
    r = http.post("/auth/sessions/reauthenticate", headers=h, json={"code": "000000"})
    assert r.status_code == 400
    assert r.json()["error"] == "totp_invalid"

    # correct step-up re-establishes freshness; op succeeds again
    code = service.totp_provisioning_code("alice", clock.now())
    r = http.post("/auth/sessions/reauthenticate", headers=h, json={"code": code})
    assert r.status_code == 200
    assert r.json()["fresh_until"] == clock.now() + 120.0
    r = http.post("/auth/sessions/logout-others", headers=h)
    assert r.status_code == 200


def test_replay_of_one_time_code_is_409(stack):
    http, service, clock = stack
    cur = _http_login(http, service, clock, source="web")
    h = {"Authorization": f"Bearer {cur['access_token']}"}
    clock.advance(31.0)  # next TOTP step
    code = service.totp_provisioning_code("alice", clock.now())
    assert http.post("/auth/sessions/reauthenticate", headers=h,
                     json={"code": code}).status_code == 200
    r = http.post("/auth/sessions/reauthenticate", headers=h, json={"code": code})
    assert r.status_code == 409
    assert r.json()["error"] == "totp_replay"


def test_cross_session_replay_of_one_time_code_is_409(stack):
    # Same one-time code consumed by a step-up on device A is presented on
    # device B (another session of the same user): 409 totp_replay — not a
    # successful step-up, and distinguishable from a wrong code (400) and
    # rate limiting (429).
    http, service, clock = stack
    web = _http_login(http, service, clock, source="web")
    mob = _http_login(http, service, clock, source="mobile")
    h_web = {"Authorization": f"Bearer {web['access_token']}"}
    h_mob = {"Authorization": f"Bearer {mob['access_token']}"}

    clock.advance(31.0)  # next TOTP step, valid for both sessions
    code = service.totp_provisioning_code("alice", clock.now())
    assert http.post("/auth/sessions/reauthenticate", headers=h_web,
                     json={"code": code}).status_code == 200

    r = http.post("/auth/sessions/reauthenticate", headers=h_mob,
                  json={"code": code})
    assert r.status_code == 409
    assert r.json()["error"] == "totp_replay"

    # the same body with a wrong code proves the distinction is stable
    r_wrong = http.post("/auth/sessions/reauthenticate", headers=h_mob,
                        json={"code": "000000"})
    assert r_wrong.status_code == 400
    assert r_wrong.json()["error"] == "totp_invalid"


def test_session_endpoints_require_authentication(stack):
    http, _, _ = stack
    assert http.get("/auth/sessions").status_code == 401
    assert http.post("/auth/sessions/terminate",
                     json={"session_id": "x"}).status_code == 401
    assert http.post("/auth/sessions/logout-others").status_code == 401
