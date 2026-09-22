"""Session / credential lifecycle orchestration.

Lifecycle guarantees implemented here:

* Access tokens are short-lived; refresh tokens are rotating, one-time.
* A successful refresh invalidates the presented refresh token, and the
  session token version is bumped, so access tokens issued before it
  stop validating immediately.
* Submitting the *same* refresh token:
    - concurrently with the in-flight winner -> ``refresh_token_concurrent``
    - again after the winner committed       -> ``refresh_token_reuse``
      (which also revokes the whole token family).
* Logout revokes the session and the refresh family and bumps the
  token version, killing outstanding access tokens immediately.
* Signing-key rotation invalidates every token signed with the old key
  (``key_version_stale``).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass

from auth.authz import Authorizer
from auth.clock import Clock, SystemClock
from auth.errors import AuthError, ErrorCode
from auth.logging_utils import log_decision
from auth.mfa import TotpResult, TotpVerifier
from auth.store import RefreshRecord, RefreshState, SessionRecord, Store, UserRecord
from auth.tokens import KeyRing, TokenClaims, b64url_decode

ACCESS_TTL_SECONDS = 300.0                    # 5 minutes
REFRESH_TTL_SECONDS = 60.0 * 60 * 24 * 7      # 7 days
CHALLENGE_TTL_SECONDS = 120.0                 # MFA must complete in 2 minutes

_TOTP_RESULT_TO_CODE = {
    TotpResult.INVALID: ErrorCode.TOTP_INVALID,
    TotpResult.CLOCK_SKEW: ErrorCode.TOTP_CLOCK_SKEW,
    TotpResult.RATE_LIMITED: ErrorCode.MFA_RATE_LIMITED,
    TotpResult.LOCKED: ErrorCode.MFA_LOCKED,
}


@dataclass(frozen=True)
class IssuedTokens:
    access_token: str
    refresh_token: str
    token_type: str
    expires_in: float


@dataclass(frozen=True)
class LoginChallenge:
    challenge_id: str
    user_id: str
    source: str
    expires_at: float


@dataclass(frozen=True)
class AccessContext:
    """Result of presenting an access token at an entry point."""

    user_id: str
    session_id: str
    scopes: frozenset[str]
    claims: TokenClaims


class SessionService:
    def __init__(
        self,
        store: Store,
        keyring: KeyRing,
        verifier: TotpVerifier,
        authorizer: Authorizer | None = None,
        clock: Clock | None = None,
        *,
        access_ttl: float = ACCESS_TTL_SECONDS,
        refresh_ttl: float = REFRESH_TTL_SECONDS,
        challenge_ttl: float = CHALLENGE_TTL_SECONDS,
        require_mfa: bool = True,
    ) -> None:
        self.store = store
        self.keyring = keyring
        self.verifier = verifier
        self.authorizer = authorizer
        self._clock = clock or SystemClock()
        self._access_ttl = access_ttl
        self._refresh_ttl = refresh_ttl
        self._challenge_ttl = challenge_ttl
        self._require_mfa = require_mfa
        self._challenges: dict[str, LoginChallenge] = {}
        self._lock = threading.RLock()

    # ---- local password helpers ----
    @staticmethod
    def hash_password(password: str) -> str:
        # Local-only demo hashing (no external IdP / bcrypt service).
        return hashlib.sha256(("local-pepper:" + password).encode()).hexdigest()

    def register_user(
        self,
        user_id: str,
        password: str,
        roles: frozenset[str] | set[str] = frozenset(),
        scopes: frozenset[str] | set[str] = frozenset(),
        *,
        enroll_totp: bool = True,
    ) -> UserRecord:
        secret = self.verifier.generate_secret() if enroll_totp else None
        record = UserRecord(
            user_id=user_id,
            password_hash=self.hash_password(password),
            roles=frozenset(roles),
            scopes=frozenset(scopes),
            totp_secret=secret,
            totp_enrolled=enroll_totp and secret is not None,
        )
        self.store.upsert_user(record)
        log_decision(
            "user.register", "ok", user=user_id, roles=record.roles,
            scopes=record.scopes, totp_enrolled=record.totp_enrolled,
        )
        return record

    def totp_provisioning_code(self, user_id: str, timestamp: float | None = None) -> str:
        """Test/local helper: current TOTP code for an enrolled user."""
        user = self.store.get_user(user_id)
        if user is None or not user.totp_enrolled or user.totp_secret is None:
            raise AuthError(code=ErrorCode.MFA_NOT_ENROLLED)
        return self.verifier.code_at(user.totp_secret, timestamp)

    # ---- login ----
    def begin_login(self, user_id: str, password: str, source: str = "web") -> LoginChallenge:
        """Validate the first factor; return an MFA challenge."""
        user = self.store.get_user(user_id)
        # Uniform error for unknown user / wrong password (no enumeration).
        if user is None or not hmac.compare_digest(
            user.password_hash, self.hash_password(password)
        ):
            log_decision("login.begin", "invalid_credentials", user=user_id, source=source)
            raise AuthError(code=ErrorCode.INVALID_CREDENTIALS)

        if self._require_mfa:
            if not user.totp_enrolled or user.totp_secret is None:
                raise AuthError(code=ErrorCode.MFA_NOT_ENROLLED)
            challenge = LoginChallenge(
                challenge_id="chl_" + secrets.token_urlsafe(16),
                user_id=user_id,
                source=source,
                expires_at=self._clock.now() + self._challenge_ttl,
            )
            with self._lock:
                self._challenges[challenge.challenge_id] = challenge
            log_decision(
                "login.begin", "mfa_challenge", user=user_id, source=source,
                challenge=challenge.challenge_id, expires_at=challenge.expires_at,
            )
            return challenge

        # MFA disabled (local configuration): issue directly.
        return self._direct_login(user_id, source)

    def _direct_login(self, user_id: str, source: str) -> LoginChallenge:
        # Not used in the hardened configuration; kept for local toggles.
        raise AuthError(code=ErrorCode.MFA_NOT_ENROLLED)

    def complete_login(self, challenge_id: str, code: str) -> IssuedTokens:
        with self._lock:
            challenge = self._challenges.get(challenge_id)
            if challenge is None:
                log_decision("login.complete", "challenge_not_found", challenge=challenge_id)
                raise AuthError(code=ErrorCode.CHALLENGE_NOT_FOUND)
            # Expired challenges are consumed and reported distinctly.
            if challenge.expires_at <= self._clock.now():
                self._challenges.pop(challenge_id, None)
                log_decision(
                    "login.complete", "challenge_expired", challenge=challenge_id,
                    expired_at=challenge.expires_at, now=self._clock.now(),
                )
                raise AuthError(code=ErrorCode.CHALLENGE_EXPIRED)

        user = self.store.get_user(challenge.user_id)
        if user is None or user.totp_secret is None:
            raise AuthError(code=ErrorCode.MFA_NOT_ENROLLED)

        status = self.verifier.verify(user.user_id, challenge.source, user.totp_secret, code)
        if status.result is not TotpResult.OK:
            code_err = _TOTP_RESULT_TO_CODE[status.result]
            log_decision(
                "login.complete", code_err.value, user=user.user_id,
                source=challenge.source, failures=status.failures,
                retry_after=status.retry_after,
            )
            raise AuthError(code=code_err)

        with self._lock:
            self._challenges.pop(challenge_id, None)
        session = self.store.create_session(user.user_id)
        tokens = self._issue(session)
        log_decision(
            "login.complete", "ok", user=user.user_id, source=challenge.source,
            session=session.session_id,
        )
        return tokens

    # ---- refresh rotation ----
    def _refresh_claimed(self, record: RefreshRecord) -> None:
        """Hook invoked after a refresh token is atomically claimed.

        Default no-op; tests override it to create deterministic
        concurrency windows (without sleeping or mocking crypto).
        """

    def refresh(self, refresh_token: str) -> IssuedTokens:
        try:
            claims = self.keyring.verify(refresh_token)
        except AuthError as exc:
            # Malformed/forged tokens have no type; at the refresh entry
            # point they are classified as refresh-credential failures.
            if exc.code in (ErrorCode.ACCESS_TOKEN_INVALID, ErrorCode.ACCESS_TOKEN_EXPIRED):
                raise AuthError(code=ErrorCode.REFRESH_TOKEN_INVALID)
            raise
        if claims.typ != "refresh":
            raise AuthError(code=ErrorCode.REFRESH_TOKEN_INVALID)

        record = self.store.get_refresh(claims.jti)
        if record is None:
            raise AuthError(code=ErrorCode.REFRESH_TOKEN_INVALID)
        if record.state is RefreshState.REVOKED:
            raise AuthError(code=ErrorCode.REFRESH_TOKEN_REVOKED)

        try:
            claimed = self.store.mark_inflight(claims.jti)
        except LookupError:
            # Distinguish "concurrent duplicate" from "post-rotation reuse".
            current = self.store.get_refresh(claims.jti)
            if current is not None and current.inflight:
                log_decision(
                    "refresh", "refresh_token_concurrent", jti=claims.jti,
                    family=record.family_id,
                )
                raise AuthError(code=ErrorCode.REFRESH_TOKEN_CONCURRENT)
            if current is not None and current.state is RefreshState.ROTATED:
                self._handle_reuse(current)
            if current is not None and current.state is RefreshState.REVOKED:
                raise AuthError(code=ErrorCode.REFRESH_TOKEN_REVOKED)
            raise AuthError(code=ErrorCode.REFRESH_TOKEN_INVALID)

        try:
            if claimed.expires_at <= self._clock.now():
                self.store.clear_inflight(claimed.jti)
                raise AuthError(code=ErrorCode.REFRESH_TOKEN_EXPIRED)

            session = self.store.get_session(claimed.session_id)
            if session is None:
                self.store.clear_inflight(claimed.jti)
                raise AuthError(code=ErrorCode.SESSION_NOT_FOUND)
            if session.revoked:
                self.store.clear_inflight(claimed.jti)
                raise AuthError(code=ErrorCode.SESSION_REVOKED)

            self._refresh_claimed(claimed)
            new_version = self.store.bump_token_version(session.session_id)
            new_tokens = self._build_tokens(session, new_version, claimed.family_id)
            new_record = RefreshRecord(
                jti=new_tokens.refresh_claims.jti,
                family_id=claimed.family_id,
                session_id=session.session_id,
                user_id=session.user_id,
                issued_at=self._clock.now(),
                expires_at=new_tokens.refresh_claims.exp,
            )
            self._commit_refresh(claimed.jti, new_record)
        except AuthError:
            # Claim stays only on success paths; release otherwise.
            self.store.clear_inflight(claimed.jti)
            raise

        log_decision(
            "refresh", "ok", user=session.user_id, session=session.session_id,
            family=claimed.family_id, old_jti=claimed.jti,
            new_jti=new_record.jti, token_version=new_version,
        )
        return new_tokens.tokens

    def _commit_refresh(self, old_jti: str, new_record: RefreshRecord) -> None:
        """Atomic rotation commit (overridden in tests for barriers)."""
        self.store.replace_refresh(old_jti, new_record)

    def _handle_reuse(self, record: RefreshRecord) -> None:
        """Replay of an already-rotated credential: burn the family."""
        log_decision(
            "refresh", "refresh_token_reuse", jti=record.jti,
            family=record.family_id, used_at=record.used_at,
        )
        self.store.revoke_family(record.family_id, "refresh_token_reuse", self._clock.now())
        self.store.revoke_session(record.session_id, "refresh_token_reuse")
        raise AuthError(code=ErrorCode.REFRESH_TOKEN_REUSE)

    # ---- logout ----
    def logout(self, refresh_token: str) -> None:
        """Revoke session + whole refresh family.

        Best-effort on malformed/retired-key tokens: the payload is read
        without verifying the signature so logout still works right
        after a signing-key rotation; only revocation state changes.
        """
        jti, sid, family = self._locate_refresh(refresh_token)
        record = self.store.get_refresh(jti) if jti else None
        if record is not None:
            self.store.revoke_family(record.family_id, "logout", self._clock.now())
            self.store.revoke_session(record.session_id, "logout")
            try:
                self.store.bump_token_version(record.session_id)
            except KeyError:
                pass
            log_decision("logout", "ok", jti=jti, family=record.family_id,
                         session=record.session_id)
            return
        if sid:
            self.store.revoke_session(sid, "logout")
            log_decision("logout", "session_only", jti=jti, session=sid, family=family)
            return
        raise AuthError(code=ErrorCode.REFRESH_TOKEN_INVALID)

    def _locate_refresh(self, token: str) -> tuple[str | None, str | None, str | None]:
        try:
            claims = self.keyring.verify(token)
            rec = self.store.get_refresh(claims.jti)
            family = rec.family_id if rec else None
            return claims.jti, claims.sid, family
        except AuthError:
            # Fall back to unverified payload purely to locate state.
            try:
                payload = token.split(".", 1)[0]
                body = json.loads(b64url_decode(payload))
                return str(body.get("jti")), str(body.get("sid")), None
            except Exception:
                return None, None, None

    # ---- authenticate / authorize ----
    def authenticate(self, access_token: str) -> AccessContext:
        try:
            claims = self.keyring.verify(access_token)
        except AuthError as exc:
            if exc.code in (ErrorCode.REFRESH_TOKEN_INVALID, ErrorCode.REFRESH_TOKEN_EXPIRED):
                raise AuthError(code=ErrorCode.ACCESS_TOKEN_INVALID)
            raise
        if claims.typ != "access":
            raise AuthError(code=ErrorCode.ACCESS_TOKEN_INVALID)
        session = self.store.get_session(claims.sid)
        if session is None:
            raise AuthError(code=ErrorCode.SESSION_NOT_FOUND)
        if session.revoked:
            log_decision("access.auth", "access_token_revoked", jti=claims.jti,
                         session=session.session_id, reason=session.revoked_reason)
            raise AuthError(code=ErrorCode.ACCESS_TOKEN_REVOKED)
        if claims.ver != session.token_version:
            log_decision(
                "access.auth", "access_token_revoked", jti=claims.jti,
                session=session.session_id, token_ver=claims.ver,
                current_ver=session.token_version, basis="version_stale",
            )
            raise AuthError(code=ErrorCode.ACCESS_TOKEN_REVOKED)
        return AccessContext(
            user_id=session.user_id,
            session_id=session.session_id,
            scopes=claims.scopes,
            claims=claims,
        )

    def authorize_request(self, resource: str, access_token: str | None) -> AccessContext:
        """Authenticate then ask the Authorizer — same path for all entries."""
        if not access_token:
            decision = self._require_authorizer().decide(
                resource, user_id=None, credential_scopes=None)
            decision.ensure_allowed()
            raise AuthError(code=ErrorCode.UNAUTHENTICATED)  # defensive
        ctx = self.authenticate(access_token)
        decision = self._require_authorizer().decide(
            resource, user_id=ctx.user_id, credential_scopes=ctx.scopes)
        decision.ensure_allowed()
        return ctx

    def _require_authorizer(self) -> Authorizer:
        if self.authorizer is None:
            raise RuntimeError("authorizer not configured")
        return self.authorizer

    # ---- key management ----
    def rotate_signing_key(self) -> str:
        kid = self.keyring.rotate()
        log_decision("key.rotate", "ok", new_kid=kid)
        return kid

    # ---- token issuance internals ----
    def _issue(
        self,
        session: SessionRecord,
        family_id: str | None = None,
    ) -> IssuedTokens:
        bundle = self._build_tokens(session, session.token_version, family_id)
        self.store.add_refresh(RefreshRecord(
            jti=bundle.refresh_claims.jti,
            family_id=bundle.family_id,
            session_id=session.session_id,
            user_id=session.user_id,
            issued_at=self._clock.now(),
            expires_at=bundle.refresh_claims.exp,
        ))
        return bundle.tokens

    def _build_tokens(
        self,
        session: SessionRecord,
        version: int,
        family_id: str | None,
    ) -> "_TokenBundle":
        user = self.store.get_user(session.user_id)
        scopes = frozenset(user.scopes) if user else frozenset()
        now = self._clock.now()
        kid = self.keyring.kid
        family = family_id or "fam_" + secrets.token_urlsafe(12)

        access = TokenClaims(
            jti="at_" + secrets.token_urlsafe(16),
            typ="access", sub=session.user_id, sid=session.session_id,
            kid=kid, iat=now, exp=now + self._access_ttl, ver=version, scopes=scopes,
        )
        refresh = TokenClaims(
            jti="rt_" + secrets.token_urlsafe(16),
            typ="refresh", sub=session.user_id, sid=session.session_id,
            kid=kid, iat=now, exp=now + self._refresh_ttl, ver=version,
        )
        tokens = IssuedTokens(
            access_token=self.keyring.sign(access.to_dict()),
            refresh_token=self.keyring.sign(refresh.to_dict()),
            token_type="Bearer",
            expires_in=self._access_ttl,
        )
        return _TokenBundle(tokens=tokens, access_claims=access,
                            refresh_claims=refresh, family_id=family)


@dataclass(frozen=True)
class _TokenBundle:
    tokens: IssuedTokens
    access_claims: TokenClaims
    refresh_claims: TokenClaims
    family_id: str
