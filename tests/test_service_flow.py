"""服务编排与 HTTP 全链路集成测试。"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from auth.tokens import ACCESS_TOKEN_TTL


def _viewer_totp(container):
    return container.totp.generate_code(container._demo_totp_secrets["viewer"])  # noqa: SLF001


def test_login_without_mfa_issues_session(client):
    r = client.post("/auth/login",
                    json={"username": "editor", "password": "editor-pass"})
    assert r.status_code == 200
    body = r.json()
    assert body["mfa_required"] is False
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == ACCESS_TOKEN_TTL
    assert "docs:write" in body["scopes"]


def test_login_bad_password_is_generic(client):
    r = client.post("/auth/login", json={"username": "editor", "password": "x"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_credentials"
    # 不存在用户与错误口令同因
    r2 = client.post("/auth/login", json={"username": "ghost", "password": "x"})
    assert r2.json() == r.json()


def test_mfa_login_flow_and_wrong_code(client, container):
    r = client.post("/auth/login",
                    json={"username": "viewer", "password": "viewer-pass"})
    assert r.json()["mfa_required"] is True
    mfa_token = r.json()["mfa_token"]
    bad = client.post("/auth/mfa", json={"mfa_token": mfa_token, "code": "000000"})
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "totp_incorrect"
    ok = client.post("/auth/mfa",
                     json={"mfa_token": mfa_token, "code": _viewer_totp(container)})
    assert ok.status_code == 200
    assert "docs:read" in ok.json()["scopes"]


def test_mfa_token_invalid_after_key_rotation(client, container):
    r = client.post("/auth/login",
                    json={"username": "viewer", "password": "viewer-pass"})
    mfa_token = r.json()["mfa_token"]
    container.tokens.rotate_signing_key()
    r = client.post("/auth/mfa",
                    json={"mfa_token": mfa_token, "code": _viewer_totp(container)})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_mfa_token"


def test_refresh_then_reuse_and_concurrent(client):
    sess = client.post("/auth/login",
                       json={"username": "editor", "password": "editor-pass"}).json()
    rt = sess["refresh_token"]
    # 串行重复：先成功，再 reused，再 revoked
    assert client.post("/auth/refresh", json={"refresh_token": rt}).status_code == 200
    r = client.post("/auth/refresh", json={"refresh_token": rt})
    assert r.json()["error"]["code"] == "refresh_token_reused"
    # 并发：全新会话的刷新凭据，32 并发恰好一个成功
    sess2 = client.post("/auth/login",
                        json={"username": "editor", "password": "editor-pass"}).json()
    rt2 = sess2["refresh_token"]

    def call(_):
        resp = client.post("/auth/refresh", json={"refresh_token": rt2})
        if resp.status_code == 200:
            return "ok"
        return resp.json()["error"]["code"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        out = list(pool.map(call, range(32)))
    assert out.count("ok") == 1, out
    assert set(out) <= {"ok", "refresh_token_reused", "refresh_token_revoked"}


def test_logout_revokes_both_tokens(client):
    sess = client.post("/auth/login",
                       json={"username": "editor", "password": "editor-pass"}).json()
    r = client.post("/auth/logout",
                    json={"refresh_token": sess["refresh_token"],
                          "access_token": sess["access_token"]})
    assert r.status_code == 200
    rr = client.post("/auth/refresh", json={"refresh_token": sess["refresh_token"]})
    assert rr.json()["error"]["code"] == "refresh_token_revoked"
    ar = client.get("/api/docs/doc-1/read",
                    headers={"Authorization": f"Bearer {sess['access_token']}"})
    assert ar.json()["error"]["code"] == "access_token_revoked"


def test_access_token_expiry_via_http(client, container):
    sess = client.post("/auth/login",
                       json={"username": "editor", "password": "editor-pass"}).json()
    container.clock.advance(ACCESS_TOKEN_TTL + 1)
    r = client.get("/api/docs/doc-1/read",
                   headers={"Authorization": f"Bearer {sess['access_token']}"})
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "access_token_expired"


def test_mfa_lockout_enforced_over_http(client, container, clock):
    r = client.post("/auth/login",
                    json={"username": "viewer", "password": "viewer-pass"})
    mfa_token = r.json()["mfa_token"]
    # 制造 5 次错误（含限流等待）直到锁定
    failures = 0
    while failures < 5:
        resp = client.post("/auth/mfa",
                           json={"mfa_token": mfa_token, "code": "000000"})
        code = resp.json()["error"]["code"]
        if code == "totp_incorrect":
            failures += 1
        elif code == "mfa_throttled":
            clock.advance(61)
        else:
            pytest.fail(f"unexpected {code}")
    # 锁定窗口内即使正确口令也拒绝（mfa_token 仍在 5 分钟有效期内：总推进 <300s）
    r = client.post("/auth/mfa",
                    json={"mfa_token": mfa_token, "code": _viewer_totp(container)})
    assert r.json()["error"]["code"] == "account_locked"


def test_scope_authority_remains_consistent_after_config_change(client, container):
    """配置变更（服务端降权）后，两个入口结论保持以服务端为准且一致。"""
    sess = client.post("/auth/login",
                       json={"username": "admin", "password": "admin-pass"})
    mfa = sess.json()["mfa_token"]
    code = container.totp.generate_code(container._demo_totp_secrets["admin"])  # noqa: SLF001
    body = client.post("/auth/mfa", json={"mfa_token": mfa, "code": code}).json()
    h = {"Authorization": f"Bearer {body['access_token']}"}
    assert client.get("/api/admin/whoami", headers=h).status_code == 200
    # 服务端撤销 admin 角色（凭据内仍声称 admin 权限）
    user = container.store.get_user_by_username("admin")
    user.roles = ["viewer"]
    user.scopes = []
    r = client.get("/api/admin/whoami", headers=h)
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "forbidden"
    # 同一降权主体在资源入口也被一致拒绝（404 同形）
    assert client.get("/api/docs/doc-1/write", headers=h).status_code == 404
    assert client.get("/api/docs/doc-1/read", headers=h).status_code == 200
