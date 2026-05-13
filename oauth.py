"""Minimal OAuth 2.1 authorization server for the consulta_db MCP.

Implements just enough for an MCP client (e.g. Claude's custom connector) to do
the Authorization Code + PKCE flow described by the MCP auth spec:

  * RFC 9728  protected-resource metadata  -> /.well-known/oauth-protected-resource
  * RFC 8414  authorization-server metadata -> /.well-known/oauth-authorization-server
  * RFC 7591  dynamic client registration   -> POST /register
  *            authorization endpoint        -> GET  /authorize   (auto-approves)
  *            token endpoint                 -> POST /token       (code + refresh)

Tokens (auth codes, access tokens, refresh tokens) are stateless: a base64url
JSON payload signed with HMAC-SHA256, so the server keeps no per-token state and
survives restarts. Confidential clients (with a client_secret) are authenticated
at the token endpoint; public clients rely on PKCE (S256).

Pre-register one client via env vars so its id/secret can be pasted into the
connector dialog:

    OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET   (optional; if unset, dynamic
                                            registration is still available)
    OAUTH_REDIRECT_URIS                     (optional, comma-separated allow-list
                                            for the static client; if unset, any
                                            https redirect_uri is accepted)
    OAUTH_SIGNING_KEY                        (optional; defaults to MCP_AUTH_TOKEN
                                            or a dev key)
"""

from __future__ import annotations

import os
import json
import time
import hmac
import base64
import hashlib
import logging
import secrets

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response, PlainTextResponse
from starlette.routing import Route

log = logging.getLogger("consulta_db")

# ---- config ---------------------------------------------------------------
CODE_TTL = 600              # 10 min
ACCESS_TTL = 3600           # 1 h
REFRESH_TTL = 30 * 24 * 3600  # 30 d
SCOPE = "mcp"

_SIGNING_KEY = (
    os.environ.get("OAUTH_SIGNING_KEY")
    or os.environ.get("MCP_AUTH_TOKEN")
    or "dev-insecure-signing-key-change-me"
).encode()

# client_id -> {"client_secret": str, "redirect_uris": list[str] | None}
_CLIENTS: dict[str, dict] = {}
_STATIC_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", "").strip()
if _STATIC_CLIENT_ID:
    _ru = os.environ.get("OAUTH_REDIRECT_URIS", "").strip()
    _CLIENTS[_STATIC_CLIENT_ID] = {
        "client_secret": os.environ.get("OAUTH_CLIENT_SECRET", "").strip(),
        "redirect_uris": [u.strip() for u in _ru.split(",") if u.strip()] or None,
    }

OAUTH_CONFIGURED = bool(_STATIC_CLIENT_ID) or True  # registration is always on


# ---- token codec ----------------------------------------------------------
def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: dict) -> str:
    body = _b64e(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = _b64e(hmac.new(_SIGNING_KEY, body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def _unsign(token: str) -> dict | None:
    try:
        body, sig = token.split(".", 1)
        expected = _b64e(hmac.new(_SIGNING_KEY, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_b64d(body))
        if float(payload.get("exp", 0)) < time.time():
            return None
        return payload
    except Exception:
        return None


def validate_access_token(token: str) -> dict | None:
    """Return the payload if `token` is a valid, unexpired access token, else None."""
    p = _unsign(token)
    if p and p.get("typ") == "access":
        return p
    return None


# ---- helpers --------------------------------------------------------------
def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
    )
    return f"{proto}://{host}".rstrip("/")


def _client_redirect_ok(client: dict, redirect_uri: str) -> bool:
    allowed = client.get("redirect_uris")
    if allowed is None:
        # No allow-list configured: accept https (and localhost for testing).
        return redirect_uri.startswith("https://") or redirect_uri.startswith("http://localhost") or redirect_uri.startswith("http://127.0.0.1")
    return redirect_uri in allowed


def _client_creds_from_request(request: Request, form: dict) -> tuple[str | None, str | None]:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("basic "):
        try:
            raw = base64.b64decode(auth[6:].strip()).decode()
            cid, _, csec = raw.partition(":")
            return cid, csec
        except Exception:
            pass
    return form.get("client_id"), form.get("client_secret")


def _verify_pkce(code_verifier: str, challenge: str, method: str) -> bool:
    if not challenge:
        return True  # no PKCE was used
    if not code_verifier:
        return False
    if method == "S256" or not method:
        digest = hashlib.sha256(code_verifier.encode()).digest()
        return hmac.compare_digest(_b64e(digest), challenge)
    if method == "plain":
        return hmac.compare_digest(code_verifier, challenge)
    return False


def _err_redirect(redirect_uri: str, error: str, state: str | None, desc: str = "") -> Response:
    from urllib.parse import urlencode

    q = {"error": error}
    if desc:
        q["error_description"] = desc
    if state:
        q["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(q)}", status_code=302)


# ---- endpoint handlers ----------------------------------------------------
async def protected_resource_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": [SCOPE],
        }
    )


async def authorization_server_metadata(request: Request):
    base = _base_url(request)
    return JSONResponse(
        {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256", "plain"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            "scopes_supported": [SCOPE],
        }
    )


async def register(request: Request):
    """RFC 7591 dynamic client registration (open registration)."""
    try:
        body = await request.json()
    except Exception:
        body = {}
    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    client_id = "dyn-" + secrets.token_urlsafe(16)
    client_secret = secrets.token_urlsafe(32)
    _CLIENTS[client_id] = {"client_secret": client_secret, "redirect_uris": redirect_uris}
    log.info("oauth: registered client %s | redirect_uris=%s", client_id, redirect_uris)
    return JSONResponse(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "client_id_issued_at": int(time.time()),
            "client_secret_expires_at": 0,
            "redirect_uris": redirect_uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "client_secret_post",
        },
        status_code=201,
    )


async def authorize(request: Request):
    q = request.query_params
    response_type = q.get("response_type")
    client_id = q.get("client_id", "")
    redirect_uri = q.get("redirect_uri", "")
    state = q.get("state")
    scope = q.get("scope") or SCOPE
    code_challenge = q.get("code_challenge", "")
    code_challenge_method = q.get("code_challenge_method", "S256" if code_challenge else "")
    resource = q.get("resource", "")

    client = _CLIENTS.get(client_id)
    if not client:
        return PlainTextResponse("unknown client_id", status_code=400)
    if not redirect_uri or not _client_redirect_ok(client, redirect_uri):
        return PlainTextResponse("invalid redirect_uri", status_code=400)
    if response_type != "code":
        return _err_redirect(redirect_uri, "unsupported_response_type", state)
    if code_challenge and code_challenge_method not in ("S256", "plain"):
        return _err_redirect(redirect_uri, "invalid_request", state, "bad code_challenge_method")

    # Single-user personal server: auto-approve (the real gates are the
    # client_secret at /token for confidential clients, and PKCE for public ones).
    code = _sign(
        {
            "typ": "code",
            "cid": client_id,
            "ruri": redirect_uri,
            "cc": code_challenge,
            "ccm": code_challenge_method,
            "scope": scope,
            "res": resource,
            "exp": time.time() + CODE_TTL,
        }
    )
    log.info("oauth: issued auth code for client %s", client_id)
    sep = "&" if "?" in redirect_uri else "?"
    loc = f"{redirect_uri}{sep}code={code}"
    if state:
        from urllib.parse import quote

        loc += f"&state={quote(state)}"
    return RedirectResponse(loc, status_code=302)


def _issue_tokens(client_id: str, scope: str, resource: str) -> dict:
    now = time.time()
    access = _sign(
        {"typ": "access", "cid": client_id, "scope": scope, "res": resource, "exp": now + ACCESS_TTL}
    )
    refresh = _sign(
        {"typ": "refresh", "cid": client_id, "scope": scope, "res": resource, "exp": now + REFRESH_TTL}
    )
    return {
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL,
        "refresh_token": refresh,
        "scope": scope,
    }


def _authenticate_client(request: Request, form: dict) -> tuple[str | None, JSONResponse | None]:
    cid, csec = _client_creds_from_request(request, form)
    if not cid:
        return None, JSONResponse({"error": "invalid_client"}, status_code=401)
    client = _CLIENTS.get(cid)
    if client is None:
        return None, JSONResponse({"error": "invalid_client"}, status_code=401)
    expected_secret = client.get("client_secret") or ""
    if expected_secret:
        if not csec or not hmac.compare_digest(csec, expected_secret):
            return None, JSONResponse({"error": "invalid_client"}, status_code=401)
    return cid, None


async def token(request: Request):
    form = dict((await request.form()))
    grant_type = form.get("grant_type")

    if grant_type == "authorization_code":
        cid, err = _authenticate_client(request, form)
        if err:
            return err
        code = form.get("code", "")
        redirect_uri = form.get("redirect_uri", "")
        code_verifier = form.get("code_verifier", "")
        payload = _unsign(code)
        if not payload or payload.get("typ") != "code":
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if payload.get("cid") != cid:
            return JSONResponse({"error": "invalid_grant", "error_description": "client mismatch"}, status_code=400)
        if redirect_uri and payload.get("ruri") and redirect_uri != payload["ruri"]:
            return JSONResponse({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}, status_code=400)
        if not _verify_pkce(code_verifier, payload.get("cc", ""), payload.get("ccm", "")):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE failed"}, status_code=400)
        log.info("oauth: token issued (authorization_code) for client %s", cid)
        return JSONResponse(_issue_tokens(cid, payload.get("scope", SCOPE), payload.get("res", "")))

    if grant_type == "refresh_token":
        cid, err = _authenticate_client(request, form)
        if err:
            return err
        rt = form.get("refresh_token", "")
        payload = _unsign(rt)
        if not payload or payload.get("typ") != "refresh" or payload.get("cid") != cid:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        log.info("oauth: token issued (refresh_token) for client %s", cid)
        return JSONResponse(_issue_tokens(cid, payload.get("scope", SCOPE), payload.get("res", "")))

    return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)


# Paths that the auth middleware must let through unauthenticated.
EXEMPT_PATHS = {
    "/.well-known/oauth-protected-resource",
    "/.well-known/oauth-protected-resource/mcp",
    "/.well-known/oauth-authorization-server",
    "/.well-known/oauth-authorization-server/mcp",
    "/authorize",
    "/token",
    "/register",
}


def www_authenticate_header(base_url: str, error: str | None = None) -> str:
    parts = [f'Bearer resource_metadata="{base_url}/.well-known/oauth-protected-resource"']
    if error:
        parts.append(f'error="{error}"')
    return ", ".join(parts)


def mount(app) -> None:
    """Attach the OAuth routes to a Starlette app (prepended so they win over /mcp)."""
    routes = [
        Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-protected-resource/mcp", protected_resource_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server", authorization_server_metadata, methods=["GET"]),
        Route("/.well-known/oauth-authorization-server/mcp", authorization_server_metadata, methods=["GET"]),
        Route("/register", register, methods=["POST"]),
        Route("/authorize", authorize, methods=["GET"]),
        Route("/token", token, methods=["POST"]),
    ]
    app.router.routes[:0] = routes
    if _STATIC_CLIENT_ID:
        log.info("oauth: static client configured (client_id=%s, secret=%s)",
                 _STATIC_CLIENT_ID, "set" if _CLIENTS[_STATIC_CLIENT_ID]["client_secret"] else "EMPTY")
    log.info("oauth: endpoints mounted (/authorize, /token, /register, metadata)")
