"""Unified authorization decisions across all entry points."""
import pytest

from auth.authz import Decision
from auth.errors import AuthError, ErrorCode
from auth.store import UserRecord
from tests.conftest_service import build_service
from tests.test_sessions import login


def test_unknown_resource_and_forbidden_resource_are_indistinguishable():
    service, _ = build_service()
    tokens = login(service, "alice")
    authz = service.authorizer

    # Resource that does not exist
    d1 = authz.decide("nonexistent", user_id="alice",
                      credential_scopes=frozenset({"docs:read"}))
    # Resource alice lacks scope for
    d2 = authz.decide("docs-admin", user_id="alice",
                      credential_scopes=frozenset({"docs:read"}))
    assert d1.decision is Decision.DENY_NOT_FOUND
    assert d2.decision is Decision.DENY_NOT_FOUND
    # External shape identical; only the internal reason code differs.
    assert d1.reason is ErrorCode.NOT_FOUND
    assert d2.reason is ErrorCode.FORBIDDEN


def test_unauthenticated_decision_is_distinct():
    service, _ = build_service()
    d = service.authorizer.decide("docs", user_id=None, credential_scopes=None)
    assert d.decision is Decision.DENY_UNAUTHENTICATED
    assert d.reason is ErrorCode.UNAUTHENTICATED


def test_persisted_scopes_win_over_credential_scopes():
    service, _ = build_service()
    tokens = login(service, "alice")

    # Credential lies about having docs:write; persistence says no.
    forged = frozenset({"docs:read", "docs:write", "profile:read"})
    d = service.authorizer.decide(
        "docs-admin", user_id="alice", credential_scopes=forged)
    assert d.decision is Decision.DENY_NOT_FOUND
    assert d.reason is ErrorCode.FORBIDDEN
    assert d.effective_scopes == frozenset({"docs:read", "profile:read"})

    # And a credential missing scopes that persistence grants still allows
    # (server-side grant is authoritative, stable across tokens).
    d2 = service.authorizer.decide(
        "docs", user_id="bob", credential_scopes=frozenset())
    assert d2.allowed


def test_permission_change_takes_effect_for_outstanding_tokens():
    """If persistence changes, every entry point changes conclusion."""
    service, _ = build_service()
    tokens = login(service, "alice")
    # Access token contains docs:read scope snapshot.
    assert service.authorize_request("docs", tokens.access_token).user_id == "alice"

    # Admin narrows persisted scopes; the old token must now be denied.
    user = service.store.get_user("alice")
    service.store.upsert_user(UserRecord(
        user_id=user.user_id, password_hash=user.password_hash,
        roles=user.roles, scopes=frozenset({"profile:read"}),
        totp_secret=user.totp_secret, totp_enrolled=user.totp_enrolled,
    ))
    with pytest.raises(AuthError) as exc:
        service.authorize_request("docs", tokens.access_token)
    assert exc.value.code is ErrorCode.FORBIDDEN
    # profile still works
    assert service.authorize_request("profile", tokens.access_token).user_id == "alice"


def test_decision_is_consistent_repeatedly():
    service, _ = build_service()
    login(service, "bob")
    outcomes = {
        service.authorizer.decide(
            "docs-admin", user_id="bob", credential_scopes=frozenset()
        ).decision
        for _ in range(10)
    }
    assert outcomes == {Decision.ALLOW}
