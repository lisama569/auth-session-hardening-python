"""End-to-end HTTP behavior via FastAPI TestClient (no real network)."""
import threading

import pytest
from fastapi.testclient import TestClient

from auth.app import build_app
from tests.conftest_service import build_service
from tests.test_concurrent_refresh import BarrierService, _extract_jti
from tests.test_sessions import login


@pytest.fixture()
def client():
    base, clock = build_service()
    app = build_app(base, seeded=False)
    return TestClient(app), base, clock


def _http_login(client_svc_tuple, user="alice"):
    client, service, _ = client_svc_tuple
    ch = client.post("/auth/login/start", json={"user_id": user, "password": "pw"})
    assert ch.status_code == 200, ch.text
    code = service.totp_provisioning_code(user)
    res = client.post("/auth/login/complete",
                      json={"challenge_id": ch.json()["challenge_id"], "code": code})
    assert res.status_code == 200, res.text
    return res.json()


def test_full_login_refresh_logout_flow(client):
    http, _, _ = client
    tokens = _http_login(client)
    r = http.get("/resources/docs",
                 headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert r.status_code == 200
    assert r.json()["resource"] == "docs"

    refreshed = http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refreshed.status_code == 200

    # old access no longer works
    old = http.get("/resources/docs",
                   headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert old.status_code == 409

    # replay -> 409 with distinguishable code
    replay = http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert replay.status_code == 409
    assert replay.json()["error"] == "refresh_token_reuse"

    # logout with the current refresh token
    cur = refreshed.json()["refresh_token"]
    out = http.post("/auth/logout", json={"refresh_token": cur})
    assert out.status_code == 200
    dead = http.post("/auth/refresh", json={"refresh_token": cur})
    assert dead.status_code == 409
    assert dead.json()["error"] == "refresh_token_revoked"


def test_missing_and_forbidden_resources_both_404(client):
    http, _, _ = client
    tokens = _http_login(client)
    headers = {"Authorization": f"Bearer {tokens['access_token']}"}
    r1 = http.get("/resources/does-not-exist", headers=headers)
    r2 = http.get("/resources/docs-admin", headers=headers)
    assert r1.status_code == r2.status_code == 404
    assert r1.json()["error"] == "not_found"
    assert r2.json()["error"] == "forbidden"


def test_unauthenticated_request_is_401(client):
    http, _, _ = client
    r = http.get("/resources/docs")
    assert r.status_code == 401
    assert r.json()["error"] == "unauthenticated"


def test_mfa_lockout_via_http(client):
    http, service, _ = client
    ch = http.post("/auth/login/start", json={"user_id": "alice", "password": "pw"})
    challenge_id = ch.json()["challenge_id"]
    codes_seen = set()
    for _ in range(4):
        r = http.post("/auth/login/complete",
                      json={"challenge_id": challenge_id, "code": "000000"})
        codes_seen.add(r.json()["error"])
    fifth = http.post("/auth/login/complete",
                      json={"challenge_id": challenge_id, "code": "000000"})
    assert fifth.status_code == 409
    assert fifth.json()["error"] == "mfa_locked"

    # Even a correct code is rejected while locked (new challenge).
    ch2 = http.post("/auth/login/start", json={"user_id": "alice", "password": "pw"})
    good = service.totp_provisioning_code("alice")
    r = http.post("/auth/login/complete",
                  json={"challenge_id": ch2.json()["challenge_id"], "code": good})
    assert r.status_code == 409
    assert r.json()["error"] == "mfa_locked"


def test_concurrent_refresh_http_only_one_wins(client):
    http, base, _ = client

    # Swap in a barrier service sharing the same state.
    barrier = BarrierService(
        base.store, base.keyring, base.verifier, base.authorizer, base._clock,
        access_ttl=300.0, refresh_ttl=3600.0,
    )
    app = build_app(barrier, seeded=False)
    http2 = TestClient(app)

    tokens = _http_login((http2, barrier, None))
    payload = {"refresh_token": tokens["refresh_token"]}
    results = []
    lock = threading.Lock()

    def call_refresh():
        r = http2.post("/auth/refresh", json=payload)
        with lock:
            results.append((r.status_code, r.json()["error"] if r.status_code != 200 else "ok"))

    winner = threading.Thread(target=call_refresh)
    winner.start()
    barrier.wait_until_claimed(_extract_jti(barrier, tokens["refresh_token"]))

    losers = [threading.Thread(target=call_refresh) for _ in range(4)]
    for t in losers:
        t.start()
    for t in losers:
        t.join(timeout=3.0)
    barrier.open_gate()
    winner.join(timeout=3.0)

    oks = [r for r in results if r[1] == "ok"]
    blocked = [r for r in results if r[1] == "refresh_token_concurrent"]
    assert len(oks) == 1, results
    assert len(blocked) == 4, results


def test_key_rotation_endpoint_invalidates_tokens(client):
    http, _, _ = client
    tokens = _http_login(client)
    r = http.post("/admin/rotate-keys")
    assert r.status_code == 200

    stale = http.get("/resources/docs",
                     headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert stale.status_code == 401
    assert stale.json()["error"] == "key_version_stale"
