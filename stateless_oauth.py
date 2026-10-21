"""Minimal single-operator OAuth 2.1 authorization server for the HTTP transport.

Remote MCP connectors (Claude, ChatGPT) expect the server they connect to
speak full OAuth 2.1 with dynamic client registration and PKCE - a bare
bearer token isn't enough for their "add custom connector" flow. This
implements just enough of OAuthAuthorizationServerProvider to satisfy that,
with a single shared passcode standing in for a real login screen since
there is exactly one operator of this server.

Stateless: every artifact this server hands out (client_id, login_id,
authorization code, access token, refresh token) is a self-contained payload
signed with HMAC-SHA256 under a key derived from the passcode (or
MCP_OAUTH_SECRET if set). Nothing is kept in memory, so tokens survive
restarts, redeploys and serverless cold starts (e.g. Vercel). Trade-offs:
individual tokens can't be revoked and authorization codes aren't strictly
single-use (they expire after 5 minutes and are bound to a PKCE verifier).
Changing the passcode (or MCP_OAUTH_SECRET) invalidates everything at once.

This proves "the caller knows the passcode", not a real user identity -
network-level access control (e.g. an IP allowlist in front of this
deployment) is what actually restricts who can reach /login at all.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import zlib
from dataclasses import dataclass
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

logger = logging.getLogger(__name__)

_DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 30 * 24 * 3600  # 30 days


def _access_token_ttl_seconds() -> int:
    """Access-token lifetime in seconds, from MCP_ACCESS_TOKEN_TTL (default 30 days).

    The shared passcode is the only interactive login step, so a short-lived
    access token means re-entering the passcode every time it expires -- when a
    connector doesn't silently refresh, a 24h token forces a daily re-login.
    Default to a long lifetime; operators who want tighter tokens can lower it
    (e.g. MCP_ACCESS_TOKEN_TTL=86400 for 24h).
    """
    raw = os.environ.get("MCP_ACCESS_TOKEN_TTL", "").strip()
    if not raw:
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "MCP_ACCESS_TOKEN_TTL=%r is not an integer; using default %ds",
            raw, _DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        )
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    if value <= 0:
        logger.warning(
            "MCP_ACCESS_TOKEN_TTL=%r must be a positive number of seconds; using default %ds",
            raw, _DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
        )
        return _DEFAULT_ACCESS_TOKEN_TTL_SECONDS
    return value


# Access token lifetime, resolved once at import from the environment.
ACCESS_TOKEN_TTL_SECONDS = _access_token_ttl_seconds()
REFRESH_TOKEN_TTL_SECONDS = 365 * 24 * 3600
AUTH_CODE_TTL_SECONDS = 300
LOGIN_TTL_SECONDS = 600

# This server has exactly one access tier, so always grant it in full rather
# than propagating whatever (possibly empty) scope the client requested -
# some MCP clients omit `scope` from the /authorize request entirely, and the
# SDK's own validate_scope(None) returns None rather than the client's
# registered default, which would otherwise silently mint a zero-scope token.
DEFAULT_SCOPES = ["mcp"]


def _b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


@dataclass
class _PendingAuthorization:
    client_id: str
    params: AuthorizationParams
    created_at: float


class SinglePasscodeOAuthProvider(OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]):
    """OAuth authorization server gated by one shared passcode, with no server-side state."""

    def __init__(self, passcode: str):
        self._passcode = passcode
        secret = os.environ.get("MCP_OAUTH_SECRET") or f"mfp-mcp-oauth:{passcode}"
        self._key = hashlib.sha256(secret.encode()).digest()

    def verify_passcode(self, candidate: str) -> bool:
        return secrets.compare_digest(candidate or "", self._passcode)

    # --- Signed payload helpers ---

    def _sign(self, kind: str, payload: dict[str, Any]) -> str:
        body = _b64e(zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 9))
        mac = hmac.new(self._key, f"{kind}.{body}".encode(), hashlib.sha256).digest()
        return f"{body}.{_b64e(mac)}"

    def _verify(self, kind: str, token: str) -> dict[str, Any] | None:
        try:
            body, mac = token.rsplit(".", 1)
            expected = hmac.new(self._key, f"{kind}.{body}".encode(), hashlib.sha256).digest()
            if not hmac.compare_digest(_b64d(mac), expected):
                return None
            payload = json.loads(zlib.decompress(_b64d(body)))
        except Exception:
            return None
        exp = payload.get("exp")
        if exp is not None and exp < time.time():
            return None
        return payload

    def _client_secret_for(self, client_id: str) -> str:
        return hmac.new(self._key, f"client-secret.{client_id}".encode(), hashlib.sha256).hexdigest()

    # --- Dynamic client registration ---

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        payload = self._verify("client", client_id)
        if payload is None:
            return None
        data = dict(payload["c"])
        data["client_id"] = client_id
        if payload.get("s"):
            data["client_secret"] = self._client_secret_for(client_id)
        return OAuthClientInformationFull.model_validate(data)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        # The SDK returns this same object to the client after we return, so
        # replacing client_id/client_secret here is what the client receives.
        metadata = client_info.model_dump(
            mode="json", exclude={"client_id", "client_secret"}, exclude_none=True
        )
        has_secret = client_info.client_secret is not None
        client_id = self._sign("client", {"c": metadata, "s": has_secret, "n": secrets.token_hex(4)})
        client_info.client_id = client_id
        if has_secret:
            client_info.client_secret = self._client_secret_for(client_id)

    # --- Authorization ("login") ---

    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        login_id = self._sign(
            "login",
            {
                "cid": client.client_id,
                "p": params.model_dump(mode="json"),
                "iat": time.time(),
                "exp": time.time() + LOGIN_TTL_SECONDS,
            },
        )
        return f"/login?login_id={login_id}"

    def get_pending(self, login_id: str) -> _PendingAuthorization | None:
        payload = self._verify("login", login_id)
        if payload is None:
            return None
        return _PendingAuthorization(
            client_id=payload["cid"],
            params=AuthorizationParams.model_validate(payload["p"]),
            created_at=payload["iat"],
        )

    def complete_login(self, login_id: str) -> str | None:
        """Issue an authorization code and return the client's redirect URL.

        Returns None if login_id is invalid or expired.
        """
        pending = self.get_pending(login_id)
        if pending is None:
            return None

        params = pending.params
        code = self._sign(
            "code",
            {
                "cid": pending.client_id,
                "sc": params.scopes or DEFAULT_SCOPES,
                "cc": params.code_challenge,
                "ru": str(params.redirect_uri),
                "rue": params.redirect_uri_provided_explicitly,
                "res": params.resource,
                "exp": time.time() + AUTH_CODE_TTL_SECONDS,
                "n": secrets.token_hex(8),
            },
        )
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    # --- Token issuance ---

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        payload = self._verify("code", authorization_code)
        if payload is None or payload["cid"] != client.client_id:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=payload["sc"],
            expires_at=payload["exp"],
            client_id=payload["cid"],
            code_challenge=payload["cc"],
            redirect_uri=payload["ru"],
            redirect_uri_provided_explicitly=payload["rue"],
            resource=payload.get("res"),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        return self._issue_token(client.client_id, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        payload = self._verify("refresh", refresh_token)
        if payload is None or payload["cid"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=payload["cid"],
            scopes=payload["sc"],
            expires_at=int(payload["exp"]),
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        return self._issue_token(client.client_id, scopes or refresh_token.scopes or DEFAULT_SCOPES)

    async def load_access_token(self, token: str) -> AccessToken | None:
        payload = self._verify("access", token)
        if payload is None:
            return None
        return AccessToken(
            token=token,
            client_id=payload["cid"],
            scopes=payload["sc"],
            expires_at=int(payload["exp"]),
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        # Stateless tokens can't be revoked individually; change the passcode
        # (or MCP_OAUTH_SECRET) to invalidate every issued token at once.
        logger.info("Revocation requested; stateless tokens stay valid until they expire")

    def _issue_token(self, client_id: str, scopes: list[str]) -> OAuthToken:
        now = time.time()
        access_token = self._sign(
            "access",
            {"cid": client_id, "sc": scopes, "exp": int(now) + ACCESS_TOKEN_TTL_SECONDS, "n": secrets.token_hex(8)},
        )
        refresh_token = self._sign(
            "refresh",
            {"cid": client_id, "sc": scopes, "exp": int(now) + REFRESH_TOKEN_TTL_SECONDS, "n": secrets.token_hex(8)},
        )
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_TTL_SECONDS,
            refresh_token=refresh_token,
            scope=" ".join(scopes) or None,
        )
