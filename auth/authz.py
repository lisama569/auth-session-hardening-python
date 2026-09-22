"""Unified role/scope authorization decisioning.

Every external entry point MUST obtain its decision from
:meth:`Authorizer.decide`, so the same request always yields the same
conclusion. Decisions use the **server-persisted** scopes/roles as the
authority; scopes carried inside a presented credential are treated as
advisory only and reconciled deterministically (persistence wins).

To avoid exposing whether a protected target exists, an unknown
resource and an off-limits resource both surface as ``not_found`` to
outsiders; the precise reason stays in :class:`AuthDecision` for logs.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from auth.errors import AuthError, ErrorCode
from auth.logging_utils import log_decision
from auth.store import Store


class Decision(str, Enum):
    ALLOW = "allow"
    DENY_NOT_FOUND = "not_found"
    DENY_UNAUTHENTICATED = "unauthenticated"


@dataclass(frozen=True)
class AuthDecision:
    decision: Decision
    reason: ErrorCode
    resource: str | None
    subject: str | None
    required_scopes: frozenset[str] = frozenset()
    effective_scopes: frozenset[str] = frozenset()

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def ensure_allowed(self) -> None:
        """Raise the typed error corresponding to a denial."""
        if self.decision is Decision.ALLOW:
            return
        raise AuthError(code=self.reason)


@dataclass(frozen=True)
class ResourceSpec:
    name: str
    required_scopes: frozenset[str]


class Authorizer:
    def __init__(self, store: Store, resources: dict[str, ResourceSpec] | None = None) -> None:
        self._store = store
        self._resources: dict[str, ResourceSpec] = dict(resources or {})

    def register_resource(self, spec: ResourceSpec) -> None:
        self._resources[spec.name] = spec

    def has_resource(self, name: str) -> bool:
        return name in self._resources

    def decide(
        self,
        resource: str,
        *,
        user_id: str | None,
        credential_scopes: frozenset[str] | None,
    ) -> AuthDecision:
        """Single decision function shared by every entry point.

        Order (stable and explainable):
        1. no subject         -> DENY_UNAUTHENTICATED
        2. unknown resource   -> DENY_NOT_FOUND (reason NOT_FOUND)
        3. persistence wins   -> effective scopes come from the stored
           user record; credential-only scopes are dropped
        4. insufficient scope -> DENY_NOT_FOUND (reason FORBIDDEN),
           indistinguishable externally from case 2
        """
        if user_id is None:
            decision = AuthDecision(
                Decision.DENY_UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED,
                resource, None,
            )
            log_decision("authz.decide", decision.decision.value, resource=resource)
            return decision

        spec = self._resources.get(resource)
        if spec is None:
            decision = AuthDecision(
                Decision.DENY_NOT_FOUND, ErrorCode.NOT_FOUND, resource, user_id,
            )
            log_decision(
                "authz.decide", decision.decision.value, resource=resource,
                subject=user_id, basis="resource_missing",
            )
            return decision

        user = self._store.get_user(user_id)
        if user is None:
            # Subject disappeared from persistence: treat as unauthenticated.
            decision = AuthDecision(
                Decision.DENY_UNAUTHENTICATED, ErrorCode.UNAUTHENTICATED,
                resource, user_id, spec.required_scopes, frozenset(),
            )
            log_decision(
                "authz.decide", decision.decision.value, resource=resource,
                subject=user_id, basis="subject_missing",
            )
            return decision

        # Deterministic reconciliation: server persistence is authoritative.
        effective = frozenset(user.scopes)
        credential = frozenset(credential_scopes or ())
        if credential != effective:
            log_decision(
                "authz.scope_reconcile", "persistence_wins", subject=user_id,
                credential_scopes=credential, persisted_scopes=effective,
                dropped=credential - effective, added=effective - credential,
            )

        if not spec.required_scopes <= effective:
            decision = AuthDecision(
                Decision.DENY_NOT_FOUND, ErrorCode.FORBIDDEN, resource, user_id,
                spec.required_scopes, effective,
            )
            log_decision(
                "authz.decide", decision.decision.value, resource=resource,
                subject=user_id, required=spec.required_scopes,
                effective=effective, missing=spec.required_scopes - effective,
                basis="scope_insufficient",
            )
            return decision

        decision = AuthDecision(
            Decision.ALLOW, ErrorCode.FORBIDDEN, resource, user_id,
            spec.required_scopes, effective,
        )
        log_decision(
            "authz.decide", "allow", resource=resource, subject=user_id,
            required=spec.required_scopes, effective=effective,
            basis="scope_satisfied",
        )
        return decision
