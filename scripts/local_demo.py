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


def main() -> None:
    base, clock = build_service()
    http = TestClient(build_app(base, seeded=False))

    # 1) password + TOTP login
    ch = http.post("/auth/login/start", json={"user_id": "alice", "password": "pw"})
    show("login/start", ch)
    code = base.totp_provisioning_code("alice")
    done = http.post(
        "/auth/login/complete",
        json={"challenge_id": ch.json()["challenge_id"], "code": code},
    )
    show("login/complete", done)
    tokens = done.json()
    auth = {"Authorization": f"Bearer {tokens['access_token']}"}

    # 2) authorized / forbidden(==404) / missing(==404)
    show("GET docs (allowed)", http.get("/resources/docs", headers=auth))
    show("GET docs-admin (forbidden==404)", http.get("/resources/docs-admin", headers=auth))
    show("GET ghost (missing==404)", http.get("/resources/ghost", headers=auth))

    # 3) refresh rotation
    rot = http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    show("refresh (winner)", rot)
    show("refresh (replay=reuse)",
         http.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]}))

    # 4) login again to demonstrate logout + key rotation cleanly
    ch = http.post("/auth/login/start", json={"user_id": "bob", "password": "pw"})
    code = base.totp_provisioning_code("bob")
    bob = http.post(
        "/auth/login/complete",
        json={"challenge_id": ch.json()["challenge_id"], "code": code},
    ).json()
    bob_auth = {"Authorization": f"Bearer {bob['access_token']}"}
    show("bob GET docs-admin (allowed)",
         http.get("/resources/docs-admin", headers=bob_auth))

    show("rotate signing key", http.post("/admin/rotate-keys"))
    show("old access after rotation", http.get("/resources/docs-admin", headers=bob_auth))
    show("logout with old-key token",
         http.post("/auth/logout", json={"refresh_token": bob["refresh_token"]}))


if __name__ == "__main__":
    main()
