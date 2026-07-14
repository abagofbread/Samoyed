from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

from fastapi import HTTPException, Request, Response
from pydantic import BaseModel


@dataclass(frozen=True)
class AuthSettings:
    username: str
    password: str | None
    api_token: str | None
    secret_key: str
    session_ttl_seconds: int = 86_400

    @property
    def enabled(self) -> bool:
        return bool(self.password or self.api_token)


_settings: AuthSettings | None = None
_sessions: dict[str, float] = {}
SESSION_COOKIE = "samoyed_session"


def get_auth_settings() -> AuthSettings:
    global _settings
    if _settings is None:
        _settings = AuthSettings(
            username=os.environ.get("SAMOYED_USERNAME", "admin"),
            password=os.environ.get("SAMOYED_PASSWORD") or None,
            api_token=os.environ.get("SAMOYED_API_TOKEN") or None,
            secret_key=os.environ.get("SAMOYED_SECRET_KEY") or secrets.token_hex(32),
            session_ttl_seconds=int(os.environ.get("SAMOYED_SESSION_TTL", "86400")),
        )
    return _settings


def reset_auth_settings() -> None:
    """Clear cached settings and sessions (tests only)."""
    global _settings
    _settings = None
    _sessions.clear()


def configure_auth(
    *,
    username: str | None = None,
    password: str | None = None,
    api_token: str | None = None,
) -> AuthSettings:
    """Apply runtime auth config (CLI startup)."""
    global _settings
    if username is not None:
        os.environ["SAMOYED_USERNAME"] = username
    if password is not None:
        os.environ["SAMOYED_PASSWORD"] = password
    if api_token is not None:
        os.environ["SAMOYED_API_TOKEN"] = api_token
    _settings = None
    return get_auth_settings()


PUBLIC_PATHS = frozenset(
    {
        "/login",
        "/api/health",
        "/api/auth/login",
        "/api/auth/status",
        "/api/auth/logout",
    }
)
PUBLIC_PREFIXES = ("/static/",)


def is_public_path(path: str) -> bool:
    if path in PUBLIC_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIXES)


def _purge_expired_sessions() -> None:
    now = time.time()
    expired = [token for token, expiry in _sessions.items() if expiry <= now]
    for token in expired:
        del _sessions[token]


def create_session_token() -> str:
    settings = get_auth_settings()
    _purge_expired_sessions()
    token = secrets.token_urlsafe(32)
    _sessions[token] = time.time() + settings.session_ttl_seconds
    return token


def revoke_session(token: str | None) -> None:
    if token:
        _sessions.pop(token, None)


def verify_session_token(token: str | None) -> bool:
    if not token:
        return False
    _purge_expired_sessions()
    expiry = _sessions.get(token)
    if expiry is None or expiry <= time.time():
        _sessions.pop(token, None)
        return False
    return True


def verify_credentials(username: str, password: str) -> bool:
    settings = get_auth_settings()
    if not settings.password:
        return False
    return secrets.compare_digest(username, settings.username) and secrets.compare_digest(
        password, settings.password
    )


def verify_api_token(authorization: str | None) -> bool:
    """True when Authorization bearer matches SAMOYED_API_TOKEN (CI / automation)."""
    if not authorization or not authorization.lower().startswith("bearer "):
        return False
    token = authorization[7:].strip()
    settings = get_auth_settings()
    return bool(settings.api_token and secrets.compare_digest(token, settings.api_token))


def verify_bearer_token(authorization: str | None) -> bool:
    if not authorization or not authorization.lower().startswith("bearer "):
        return False
    token = authorization[7:].strip()
    settings = get_auth_settings()
    if settings.api_token and secrets.compare_digest(token, settings.api_token):
        return True
    return verify_session_token(token)


def is_authenticated(request: Request) -> bool:
    if not get_auth_settings().enabled:
        return True
    if verify_session_token(request.cookies.get(SESSION_COOKIE)):
        return True
    return verify_bearer_token(request.headers.get("Authorization"))


class LoginRequest(BaseModel):
    username: str
    password: str


def auth_status_payload(request: Request) -> dict[str, object]:
    settings = get_auth_settings()
    authenticated = is_authenticated(request)
    return {
        "auth_required": settings.enabled,
        "authenticated": authenticated,
        "username": settings.username if authenticated else None,
        "login_available": bool(settings.password),
    }


def login(request: LoginRequest, response: Response) -> dict[str, object]:
    settings = get_auth_settings()
    if not settings.enabled:
        return {"authenticated": True, "auth_required": False}
    if not settings.password:
        raise HTTPException(503, "Password login is not configured (set SAMOYED_PASSWORD)")
    if not verify_credentials(request.username, request.password):
        raise HTTPException(401, "Invalid username or password")
    token = create_session_token()
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=settings.session_ttl_seconds,
        path="/",
    )
    return {"authenticated": True, "username": settings.username}


def logout(request: Request, response: Response) -> dict[str, bool]:
    revoke_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"authenticated": False}
