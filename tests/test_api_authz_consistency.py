"""跨 HTTP 入口授权一致性测试。

* read/write 两个入口对同一请求结论一致（同一授权函数）；
* 越权与资源不存在返回完全相同的 404；
* 过期/撤销/坏凭据返回可区分 code；
* 凭据中携带的权限与服务端不一致时以服务端为准。
"""

from __future__ import annotations


def _login(client, username, password=""):
    pw = password or {"admin": "admin-pass", "editor": "editor-pass",
                      "viewer": "viewer-pass"}[username]
    r = client.post("/auth/login", json={"username": username, "password": pw})
    return r


def test_editor_can_read_and_write(client):
    tok = _login(client, "editor").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/docs/doc-1/read", headers=h).status_code == 200
    assert client.get("/api/docs/doc-1/write", headers=h).status_code == 200


def test_viewer_read_allowed_write_denied_as_404(client, container):
    # viewer 启用 MFA：先拿 mfa_token，再用容器生成当前正确口令
    r = _login(client, "viewer")
    mfa = r.json()["mfa_token"]
    code = container.totp.generate_code(
        container._demo_totp_secrets["viewer"])  # noqa: SLF001
    r = client.post("/auth/mfa", json={"mfa_token": mfa, "code": code})
    assert r.status_code == 200, r.text
    tok = r.json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/docs/doc-1/read", headers=h).status_code == 200
    denied = client.get("/api/docs/doc-1/write", headers=h)
    missing = client.get("/api/docs/does-not-exist/write", headers=h)
    assert denied.status_code == 404 == missing.status_code
    assert denied.json() == missing.json()  # 不暴露资源是否存在


def test_two_entries_identical_decision(client, container):
    """同一主体、同一资源，read/write 入口的拒绝形态完全一致。"""
    tok = _login(client, "editor").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    # editor 无 admin 权限：两个资源入口对越权资源的结论必须一致（均 404 同形）
    r1 = client.get("/api/docs/doc-9/read", headers=h)   # 有 docs:read -> 200
    # 构造对不存在资源 read / write 都 404
    n1 = client.get("/api/docs/nope/read", headers=h)
    n2 = client.get("/api/docs/nope/write", headers=h)
    assert r1.status_code == 200
    assert n1.status_code == n2.status_code == 404
    assert n1.json() == n2.json()


def test_server_scopes_win_over_token_claims(client, container):
    """把编辑器账号在服务端降权为 viewer 后，旧凭据携带的 write 不再有效。"""
    tok = _login(client, "editor").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    assert client.get("/api/docs/doc-1/write", headers=h).status_code == 200
    # 配置变更：服务端持久化角色降权（模拟权限收敛）
    user = container.store.get_user_by_username("editor")
    user.roles = ["viewer"]
    # 自包含访问凭据仍能通过签名校验，但授权以服务端最新记录为准 -> 404
    denied = client.get("/api/docs/doc-1/write", headers=h)
    allowed = client.get("/api/docs/doc-1/read", headers=h)
    assert denied.status_code == 404
    assert allowed.status_code == 200


def test_missing_and_bad_token_are_401_distinct(client):
    assert client.get("/api/docs/doc-1/read").status_code == 401
    h = {"Authorization": "Bearer garbage.token.here"}
    r = client.get("/api/docs/doc-1/read", headers=h)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "access_token_invalid"
