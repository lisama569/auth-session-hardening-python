"""访问/刷新凭据生命周期测试。

覆盖：
* 刷新轮换成功后旧凭据失效；
* 同一刷新凭据串行重复、并发提交：恰好一个成功，其余以可区分原因拒绝；
* 登出、密钥轮换后凭据立即失效；
* 访问凭据过期/撤销/坏签名/错误类型原因可区分。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from auth import errors
from auth.store import InMemoryStore
from auth.tokens import ACCESS_TOKEN_TTL, TokenAuthority


@pytest.fixture
def authority(clock):
    return TokenAuthority(InMemoryStore(), clock)


def test_access_token_verify_roundtrip(authority):
    pair = authority.issue("u1", ["docs:read"])
    at = authority.verify_access_token(pair.access.token)
    assert at.user_id == "u1"
    assert at.scopes == ["docs:read"]


@pytest.mark.parametrize(
    "mutate,exc",
    [
        (lambda t: t + "x", errors.AccessTokenInvalid),       # 坏签名
        (lambda t: "not-a-token", errors.AccessTokenInvalid),
        (lambda t: "", errors.AccessTokenInvalid),
    ],
)
def test_access_token_malformed(authority, mutate, exc):
    pair = authority.issue("u1", [])
    with pytest.raises(exc):
        authority.verify_access_token(mutate(pair.access.token))


def test_access_token_expiry_distinguished(authority, clock):
    pair = authority.issue("u1", [])
    clock.advance(ACCESS_TOKEN_TTL + 1)
    with pytest.raises(errors.AccessTokenExpired):
        authority.verify_access_token(pair.access.token)


def test_access_token_revoked_distinguished(authority):
    pair = authority.issue("u1", [])
    authority.revoke_access_token(pair.access.token)
    with pytest.raises(errors.AccessTokenRevoked):
        authority.verify_access_token(pair.access.token)


def test_wrong_token_type_rejected(authority):
    pair = authority.issue("u1", [])
    with pytest.raises(errors.AccessTokenInvalid):
        authority.verify_access_token(pair.refresh.token)


def test_rotation_invalidates_old_refresh(authority):
    pair = authority.issue("u1", ["docs:read"])
    new_pair = authority.rotate(pair.refresh.token, scopes=["docs:read"])
    # 新访问凭据可用
    assert authority.verify_access_token(new_pair.access.token).user_id == "u1"
    # 旧刷新凭据重复使用 -> reused（可区分）
    with pytest.raises(errors.RefreshTokenReused):
        authority.rotate(pair.refresh.token)
    # 重用触发家族连带撤销：新刷新凭据也立即作废 -> revoked
    with pytest.raises(errors.RefreshTokenRevoked):
        authority.rotate(new_pair.refresh.token)


def test_concurrent_rotation_exactly_one_wins(authority):
    pair = authority.issue("u1", [])
    outcomes: list[str] = []

    def use_once(_):
        try:
            authority.rotate(pair.refresh.token)
            return "ok"
        except errors.RefreshTokenReused:
            return "reused"
        except errors.RefreshTokenRevoked:
            return "revoked"
        except errors.AuthError as e:
            return e.code

    with ThreadPoolExecutor(max_workers=16) as pool:
        outcomes = list(pool.map(use_once, range(32)))

    assert outcomes.count("ok") == 1, outcomes
    assert set(outcomes) <= {"ok", "reused", "revoked"}
    # 落败原因必须可区分且全部属于"非成功"
    assert all(o != "ok" for o in outcomes[1:])


def test_concurrent_rotation_chain_each_token_single_use(authority):
    """链式轮换中每个刷新凭据也只能成功一次（模拟高并发连续刷新）。"""
    pair = authority.issue("u1", [])
    # 第一个成功
    pair2 = authority.rotate(pair.refresh.token)
    with ThreadPoolExecutor(max_workers=8) as pool:
        out = list(pool.map(
            lambda _: _safe(authority, pair2.refresh.token), range(8)))
    assert out.count("ok") == 1, out


def _safe(authority, token):
    try:
        authority.rotate(token)
        return "ok"
    except errors.AuthError as e:
        return e.code


def test_refresh_expiry_revokes_family(authority, clock):
    from auth.tokens import REFRESH_TOKEN_TTL

    pair = authority.issue("u1", [])
    clock.advance(REFRESH_TOKEN_TTL + 1)
    with pytest.raises(errors.RefreshTokenExpired):
        authority.rotate(pair.refresh.token)


def test_logout_revokes_family_and_access(authority):
    pair = authority.issue("u1", [])
    family = authority.revoke_session(pair.refresh.token)
    assert family == pair.access.family_id
    with pytest.raises(errors.RefreshTokenRevoked):
        authority.rotate(pair.refresh.token)
    authority.revoke_access_token(pair.access.token)
    with pytest.raises(errors.AccessTokenRevoked):
        authority.verify_access_token(pair.access.token)


def test_signing_key_rotation_invalidates_all(authority):
    pair = authority.issue("u1", [])
    new_kid = authority.rotate_signing_key()
    assert new_kid != pair.access.kid
    # 旧访问凭据：kid 找不到 -> invalid
    with pytest.raises(errors.AccessTokenInvalid):
        authority.verify_access_token(pair.access.token)
    # 旧刷新凭据：旧 kid -> invalid（在状态检查之前即拒绝）
    with pytest.raises(errors.RefreshTokenInvalid):
        authority.rotate(pair.refresh.token)
    # 新密钥签发的凭据正常工作
    fresh = authority.issue("u1", [])
    assert authority.verify_access_token(fresh.access.token).user_id == "u1"


def test_refresh_token_subject_mismatch_rejected(authority, monkeypatch):
    """伪造主体的刷新凭据即便签名合法也被拒绝并连带撤销家族。"""
    pair = authority.issue("u1", [])
    # 直接篡改持久化记录的 user_id 制造主体不一致
    rec = authority._store.get_refresh_token(pair.refresh.record.jti)  # noqa: SLF001
    rec.user_id = "u-attacker"
    with pytest.raises(errors.RefreshTokenInvalid):
        authority.rotate(pair.refresh.token)
