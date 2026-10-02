"""Local end-to-end walkthrough — no network, no external services.

Run:  uv run python scripts/local_demo.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from auth.app import build_app  # noqa: E402
from tests.conftest_service import build_service  # noqa: E402


def show(title: str, response) -> None:
    print(f"[{title}] {response.status_code} {response.json()}")


def _login(http, base, clock, user="alice", source="web"):
    ch = http.post(
        "/auth/login/start",
        json={"user_id": user, "password": "pw", "source": source},
    )
    show(f"login/start ({user}/{source})", ch)
    code = base.totp_provisioning_code(user, clock.now())
    done = http.post(
        "/auth/login/complete",
        json={"challenge_id": ch.json()["challenge_id"], "code": code},
    )
    show(f"login/complete ({user}/{source})", done)
    return done.json()


def main() -> None:
    base, clock = build_service(reauth_freshness=120.0)
    http = TestClient(build_app(base, seeded=False))

    # 1) password + TOTP login
    tokens = _login(http, base, clock, "alice", "web")
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}

    # 2) authorized / forbidden(==404) / missing(==404)
    show("GET docs (allowed)", http.get("/resources/docs", headers=auth))
    show("GET docs-admin (forbidden==404)", http.get("/resources/docs-admin", headers=auth))
    show("GET ghost (missing==404)", http.get("/resources/ghost", headers=auth))

    # 3) refresh rotation (the new pair replaces the old one). The
    # replay-detection demo is deferred: by design a replayed refresh
    # burns the whole family + session, which would mask the steps below.
    rot = http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    show("refresh (winner)", rot)

    # 4) multi-device session management, driven by the rotated pair
    cur = rot.json()
    auth = {"Authorization": f"Bearer {cur['access_token']}"}
    mobile = _login(http, base, clock, "alice", "mobile")
    lap = _login(http, base, clock, "alice", "cli")
    show("list my sessions", http.get("/auth/sessions", headers=auth))

    # foreign / nonexistent session ids are the same 404 envelope
    mobile_sid = base.keyring.verify(mobile["access_token"]).sid
    show("terminate own mobile session",
         http.post("/auth/sessions/terminate", headers=auth,
                   json={"session_id": mobile_sid}))
    show("terminate again (already gone == not_found)",
         http.post("/auth/sessions/terminate", headers=auth,
                   json={"session_id": mobile_sid}))
    show("terminate nonexistent id (identical 404)",
         http.post("/auth/sessions/terminate", headers=auth,
                   json={"session_id": "sess_ghost"}))

    # sensitive op needs a fresh second factor
    show("logout-others while fresh",
         http.post("/auth/sessions/logout-others", headers=auth))
    clock.advance(120.001)
    show("logout-others after window (403 reauth_required)",
         http.post("/auth/sessions/logout-others", headers=auth))
    code = base.totp_provisioning_code("alice", clock.now())
    show("step-up reauthenticate",
         http.post("/auth/sessions/reauthenticate", headers=auth, json={"code": code}))
    show("replay same code (409 totp_replay)",
         http.post("/auth/sessions/reauthenticate", headers=auth, json={"code": code}))
    show("logout-others after reauth",
         http.post("/auth/sessions/logout-others", headers=auth))

    # replay the pre-rotation refresh: conservative family+session burn
    show("refresh (replay=reuse, burns family/session)",
         http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}))

    # 5) login again to demonstrate logout + key rotation cleanly
    bob = _login(http, base, clock, "bob", "mobile")
    bob_auth = {"Authorization": f"Bearer {bob['access_token']}"}
    show("bob GET docs-admin (allowed)",
         http.get("/resources/docs-admin", headers=bob_auth))

    show("rotate signing key", http.post("/admin/rotate-keys"))
    show("old access after rotation", http.get("/resources/docs-admin", headers=bob_auth))
    show("logout with old-key token",
         http.post("/auth/logout", json={"refresh_token": bob["refresh_token"]}))


if __name__ == "__main__":
    main()
