"""统一授权判定测试。"""

from __future__ import annotations

import pytest

from auth import authz, errors


def test_resolve_scopes_is_union_of_stored_and_role():
    scopes = authz.resolve_scopes(["editor"], ["extra:read"])
    assert scopes == frozenset({"docs:read", "docs:write", "extra:read"})


def test_unknown_role_grants_nothing():
    p = authz.build_principal("u", ["ghost"], [])
    assert p.scopes == frozenset()


def test_token_claims_are_ignored_when_elevated():
    """凭据里多写的权限绝不参与判定，以服务端持久化为准。"""
    p = authz.build_principal(
        "u1", ["viewer"], ["docs:read"], token_scopes=["admin:write", "docs:read"])
    assert "admin:write" not in p.scopes
    authz.authorize(p, "docs:read")
    with pytest.raises(errors.Forbidden):
        authz.authorize(p, "admin:write")


def test_token_claims_cannot_reduce_server_grants():
    """凭据里少写权限同样不影响：服务端授予的权限仍然有效（稳定性）。"""
    p = authz.build_principal(
        "u1", ["editor"], [], token_scopes=["docs:read"])  # 少声明 docs:write
    assert "docs:write" in p.scopes
    authz.authorize(p, "docs:write")


def test_authorize_or_404_masks_forbidden():
    p = authz.build_principal("u1", ["viewer"], [])
    with pytest.raises(errors.NotFound):
        authz.authorize_or_404(p, "docs:write", resource="doc-1")


def test_decision_is_stable_across_calls():
    p = authz.build_principal("u1", ["viewer"], [])
    for _ in range(5):
        authz.authorize(p, "docs:read")  # 恒允许
        with pytest.raises(errors.NotFound):
            authz.authorize_or_404(p, "docs:write")  # 恒拒绝
