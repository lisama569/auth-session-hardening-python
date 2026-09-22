"""统一角色/权限判定。所有入口共用同一结论。

权威模型（确定性、稳定）：

* **唯一权威是服务端持久化数据**：``StoredUser.roles`` 与 ``StoredUser.scopes``。
* 主体最终权限 = 持久化显式 scopes ∪ 角色隐含 scopes（:data:`ROLE_SCOPE_MAP`）。
* 访问凭据中携带的 scopes **仅被视为客户端声明**，一律忽略；即使凭据被篡改
  写入更高权限，也不会影响判定（且凭据受 HMAC 保护，篡改即失效）。
* 越权与资源不存在对外返回**完全相同**的 404，避免暴露目标资源是否存在；
  差异仅记录在服务端日志中，便于解释。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from . import errors

logger = logging.getLogger("auth.authz")

# role -> 该角色隐含的 scopes；这是服务端安全配置，不接受客户端覆盖
ROLE_SCOPE_MAP: dict[str, frozenset[str]] = {
    "admin": frozenset({"admin:read", "admin:write", "docs:read", "docs:write"}),
    "editor": frozenset({"docs:read", "docs:write"}),
    "viewer": frozenset({"docs:read"}),
}


@dataclass(frozen=True)
class Principal:
    """已认证主体，携带**经服务端重算**的有效权限。"""

    user_id: str
    roles: tuple[str, ...]
    scopes: frozenset[str]

    def has_scope(self, required: str) -> bool:
        return required in self.scopes


def resolve_scopes(roles: list[str] | tuple[str, ...],
                   stored_scopes: list[str] | tuple[str, ...]) -> frozenset[str]:
    """以服务端持久化数据重算有效权限。

    显式授予的 scopes 与角色隐含 scopes 取并集；未识别角色不授予任何权限。
    """
    effective: set[str] = set(stored_scopes)
    for role in roles:
        effective.update(ROLE_SCOPE_MAP.get(role, frozenset()))
    return frozenset(effective)


def build_principal(user_id: str, roles: list[str], stored_scopes: list[str],
                    token_scopes: list[str] | None = None,
                    source: str = "unknown") -> Principal:
    """构造主体。

    ``token_scopes`` 仅用于记录"凭据声明 vs 服务端权威"的差异日志，
    绝不参与授权结论。
    """
    effective = resolve_scopes(roles, stored_scopes)
    if token_scopes is not None:
        declared = frozenset(token_scopes)
        missing = declared - effective
        extra = effective - declared
        if missing or extra:
            logger.info(
                "scope divergence source=%s user=%s declared_not_granted=%s "
                "granted_not_declared=%s -> decision_uses=server_store",
                source, user_id, sorted(missing), sorted(extra))
    return Principal(user_id=user_id, roles=tuple(roles), scopes=effective)


def authorize(principal: Principal, required_scope: str, *,
              resource: str = "") -> None:
    """统一授权判定。权限不足抛 :class:`Forbidden`（403，供内部/受信入口使用）。"""
    granted = principal.has_scope(required_scope)
    logger.info(
        "authorize user=%s resource=%s required=%s effective=%s decision=%s",
        principal.user_id, resource, required_scope,
        sorted(principal.scopes), "allow" if granted else "deny")
    if not granted:
        raise errors.Forbidden(f"缺少权限: {required_scope}")


def authorize_or_404(principal: Principal, required_scope: str, *,
                     resource: str = "") -> None:
    """面向外部资源入口的判定：权限不足与不存在不可区分，统一抛 404。"""
    try:
        authorize(principal, required_scope, resource=resource)
    except errors.Forbidden as exc:
        logger.warning(
            "authorization masked as not_found user=%s resource=%s required=%s reason=%s",
            principal.user_id, resource, required_scope, exc.code)
        raise errors.NotFound() from exc
