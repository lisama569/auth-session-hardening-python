"""FastAPI wiring: all HTTP entry points share the same service.

Endpoints
---------
POST /auth/login/start      -> challenge
POST /auth/login/complete   -> access + refresh tokens
POST /auth/refresh          -> rotated token pair
POST /auth/logout
GET  /auth/sessions                    -> list own active sessions
POST /auth/sessions/reauthenticate     -> step-up TOTP (freshness window)
POST /auth/sessions/terminate          -> revoke one own session
POST /auth/sessions/logout-others      -> revoke other own sessions (fresh MFA)
GET  /resources/{name}      -> protected resources (unified decision)
POST /admin/rotate-keys     -> rotate the signing key

Authorization denials for *missing* and *forbidden* resources return
the same 404 envelope (error code included in body for local debugging);
unauthenticated access returns 401.
"""
from __future__ import annotations

from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from auth.authz import Authorizer, ResourceSpec
from auth.clock import SystemClock
from auth.errors import AuthError, ErrorCode
from auth.logging_utils import log_decision
from auth.mfa import TotpVerifier
from auth.sessions import SessionService
from auth.store import Store
from auth.tokens import KeyRing


class LoginStartRequest(BaseModel):
    user_id: str
    password: str
    source: str = "web"


class LoginCompleteRequest(BaseModel):
    challenge_id: str
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ReauthRequest(BaseModel):
    code: str


class TerminateSessionRequest(BaseModel):
    session_id: str


def _bearer(authorization: str | None) -> str | None:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:]
    return None


def _http_status_for(code: ErrorCode) -> int:
    if code is ErrorCode.UNAUTHENTICATED:
        return 401
    if code in (
        ErrorCode.REFRESH_TOKEN_CONCURRENT,
        ErrorCode.REFRESH_TOKEN_REUSE,
        ErrorCode.REFRESH_TOKEN_REVOKED,
        ErrorCode.ACCESS_TOKEN_REVOKED,
        ErrorCode.SESSION_REVOKED,
        ErrorCode.MFA_LOCKED,
    ):
        return 409
    if code is ErrorCode.MFA_RATE_LIMITED:
        return 429
    if code in (
        ErrorCode.REAUTH_REQUIRED,
    ):
        # Step-up needed: the caller is authenticated but must complete a
        # fresh second factor before retrying the sensitive operation.
        return 403
    if code in (
        ErrorCode.TOTP_REPLAY,
    ):
        return 409
    if code is ErrorCode.REFRESH_TOKEN_EXPIRED or code is ErrorCode.ACCESS_TOKEN_EXPIRED:
        return 401
    if code in (ErrorCode.NOT_FOUND, ErrorCode.FORBIDDEN, ErrorCode.SESSION_NOT_FOUND):
        return 404
    if code is ErrorCode.KEY_VERSION_STALE:
        return 401
    return 400


def create_default_service() -> SessionService:
    store = Store()
    keyring = KeyRing()
    verifier = TotpVerifier()
    authorizer = Authorizer(store)
    service = SessionService(store, keyring, verifier, authorizer)

    # Seed demo principals + resources so the flow is reproducible locally.
    alice = service.register_user(
        "alice", "password-123",
        roles={"reader"}, scopes={"docs:read", "profile:read"},
    )
    bob = service.register_user(
        "bob", "password-123",
        roles={"writer"}, scopes={"docs:read", "docs:write", "profile:read"},
    )
    authorizer.register_resource(ResourceSpec("docs", frozenset({"docs:read"})))
    authorizer.register_resource(ResourceSpec("docs-admin", frozenset({"docs:write"})))
    authorizer.register_resource(ResourceSpec("profile", frozenset({"profile:read"})))
    log_decision(
        "app.seed", "ok",
        users={alice.user_id: sorted(alice.scopes), bob.user_id: sorted(bob.scopes)},
        resources={
            "docs": ["docs:read"],
            "docs-admin": ["docs:write"],
            "profile": ["profile:read"],
        },
    )
    return service


def build_app(service: SessionService | None = None, *, seeded: bool = True) -> FastAPI:
    if service is None:
        service = create_default_service() if seeded else _empty_service()

    app = FastAPI(title="auth-session-hardening", version="0.1.0")
    app.state.service = service

    @app.exception_handler(AuthError)
    async def handle_auth_error(_request, exc: AuthError) -> JSONResponse:  # type: ignore[override]
        log_decision("http.error", exc.code.value, error=exc.code.value)
        return JSONResponse(
            status_code=_http_status_for(exc.code),
            content={"error": exc.code.value},
        )

    @app.post("/auth/login/start")
    async def login_start(body: LoginStartRequest):
        challenge = service.begin_login(body.user_id, body.password, body.source)
        return {"challenge_id": challenge.challenge_id, "expires_at": challenge.expires_at}

    @app.post("/auth/login/complete")
    async def login_complete(body: LoginCompleteRequest):
        tokens = service.complete_login(body.challenge_id, body.code)
        return tokens.__dict__

    @app.post("/auth/refresh")
    async def refresh(body: RefreshRequest):
        tokens = service.refresh(body.refresh_token)
        return tokens.__dict__

    @app.post("/auth/logout")
    async def logout(body: RefreshRequest):
        service.logout(body.refresh_token)
        return {"status": "logged_out"}

    @app.get("/resources/{name}")
    async def get_resource(name: str, authorization: str | None = Header(default=None)):
        token = _bearer(authorization)
        ctx = service.authorize_request(name, token)
        user = service.store.get_user(ctx.user_id)
        return {
            "resource": name,
            "user": ctx.user_id,
            "roles": sorted(user.roles) if user else [],
            "effective_scopes": sorted(ctx.scopes),
        }

    # ---- multi-device session management ----
    @app.get("/auth/sessions")
    async def list_sessions(authorization: str | None = Header(default=None)):
        ctx = service.authenticate(_bearer(authorization))
        sessions = [
            {
                "session_id": s.session_id,
                "source": s.source,
                "created_at": s.created_at,
                "current": s.current,
            }
            for s in service.list_sessions(ctx)
        ]
        return {"sessions": sessions}

    @app.post("/auth/sessions/reauthenticate")
    async def reauthenticate(
        body: ReauthRequest, authorization: str | None = Header(default=None),
    ):
        ctx = service.authenticate(_bearer(authorization))
        result = service.reauthenticate(ctx, body.code)
        return {
            "session_id": result.session_id,
            "verified_at": result.verified_at,
            "fresh_until": result.fresh_until,
        }

    @app.post("/auth/sessions/terminate")
    async def terminate_session(
        body: TerminateSessionRequest, authorization: str | None = Header(default=None),
    ):
        ctx = service.authenticate(_bearer(authorization))
        service.terminate_session(ctx, body.session_id)
        return {"status": "terminated", "session_id": body.session_id}

    @app.post("/auth/sessions/logout-others")
    async def logout_others(authorization: str | None = Header(default=None)):
        ctx = service.authenticate(_bearer(authorization))
        terminated = service.logout_other_sessions(ctx)
        return {"status": "ok", "terminated": terminated}

    @app.post("/admin/rotate-keys")
    async def rotate_keys():
        kid = service.rotate_signing_key()
        return {"rotated_kid": kid}

    return app


def _empty_service() -> SessionService:
    store = Store()
    return SessionService(store, KeyRing(), TotpVerifier(), Authorizer(store))
