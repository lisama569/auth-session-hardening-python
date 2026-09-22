"""FastAPI 入口。

* 所有业务异常经统一处理器返回 ``{"error": {"code", "message"}}``，
  code 稳定可断言；
* 受保护资源只有两类入口（:http:post:`/api/docs/{id}/read` 与
  ``.../write``），二者都调用同一个 :meth:`AuthService.require_scope`，
  因此对同一请求结论必然一致；
* 越权访问与资源不存在对外**完全相同**（404 + not_found），不暴露资源是否存在；
  未认证（坏/过期/撤销凭据）仍是 401，便于客户端区分"先登录"。
"""

from __future__ import annotations

import logging
from dataclasses import asdict

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from . import errors
from .service import AuthService
from .tokens import ACCESS_TOKEN_TTL

logger = logging.getLogger("auth.api")


# 请求/响应模型 --------------------------------------------------------------
class LoginIn(BaseModel):
    username: str
    password: str
    source: str = "web"


class MFAIn(BaseModel):
    mfa_token: str
    code: str
    timestamp: float | None = None


class RefreshIn(BaseModel):
    refresh_token: str


class LogoutIn(BaseModel):
    refresh_token: str
    access_token: str | None = None


def _error_response(exc: errors.AuthError) -> JSONResponse:
    # 资源入口的越权已由 authorize_or_404 转成 NotFound（404，不暴露存在性）；
    # 这里 Forbidden 仅来自显式管理入口，保留 403 以明确表达"已认证但无权"。
    return JSONResponse(
        status_code=exc.http_status,
        content={"error": {"code": exc.code, "message": exc.message}})


def _bearer(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise errors.AccessTokenInvalid("缺少 Bearer 凭据")
    return authorization.split(" ", 1)[1].strip()


def create_app(service: AuthService) -> FastAPI:
    app = FastAPI(title="auth-session-hardening", version="0.1.0")

    @app.exception_handler(errors.AuthError)
    async def handle_auth_error(_request, exc: errors.AuthError):  # noqa: ANN001
        logger.info("api error code=%s message=%s", exc.code, exc.message)
        return _error_response(exc)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/auth/login")
    def login(body: LoginIn):
        result = service.login(body.username, body.password, body.source)
        if result.mfa_required:
            return JSONResponse(status_code=200, content={
                "mfa_required": True,
                "mfa_token": result.mfa_token,
            })
        pair = result.pair
        return {
            "mfa_required": False,
            "access_token": pair.access.token,
            "refresh_token": pair.refresh.token,
            "expires_in": ACCESS_TOKEN_TTL,
            "token_type": "Bearer",
            "scopes": pair.access.scopes,
        }

    @app.post("/auth/mfa")
    def mfa(body: MFAIn):
        result = service.verify_mfa(body.mfa_token, body.code, body.timestamp)
        pair = result.pair
        return {
            "mfa_required": False,
            "access_token": pair.access.token,
            "refresh_token": pair.refresh.token,
            "expires_in": ACCESS_TOKEN_TTL,
            "token_type": "Bearer",
            "scopes": pair.access.scopes,
        }

    @app.post("/auth/refresh")
    def refresh(body: RefreshIn):
        view = service.refresh(body.refresh_token)
        return asdict(view)

    @app.post("/auth/logout")
    def logout(body: LogoutIn):
        service.logout(body.refresh_token, body.access_token)
        return {"status": "logged_out"}

    # 两类受保护资源入口 —— 共用同一判定函数，结论必然一致 -------------------
    def _resource(authorization: str | None, doc_id: str, required_scope: str, action: str):
        token = _bearer(authorization)
        # 越权与不存在不可区分（authorize_or_404 抛 not_found）
        principal = service.require_scope(
            token, required_scope, resource=f"doc:{doc_id}", mask=True)
        # 通过授权后才检查资源是否存在；不存在同样 404（与越权同形）
        if not service.resource_exists(doc_id):
            raise errors.NotFound()
        return {
            "doc_id": doc_id,
            "action": action,
            "viewer": principal.user_id,
            "required_scope": required_scope,
            "decision": "allow",
        }

    @app.get("/api/docs/{doc_id}/read")
    def read_doc(doc_id: str, authorization: str | None = Header(default=None)):
        return _resource(authorization, doc_id, "docs:read", "read")

    @app.get("/api/docs/{doc_id}/write")
    def write_doc(doc_id: str, authorization: str | None = Header(default=None)):
        return _resource(authorization, doc_id, "docs:write", "write")

    # 管理入口：403 明确拒绝（仅用于展示内部判定差异，非资源存在性入口） --------
    @app.get("/api/admin/whoami")
    def whoami(authorization: str | None = Header(default=None)):
        token = _bearer(authorization)
        principal = service.require_scope(token, "admin:read", resource="admin", mask=False)
        return {"user_id": principal.user_id, "roles": list(principal.roles),
                "scopes": sorted(principal.scopes)}

    return app
