"""11 — Python twin of example 04: Keycloak issues the tokens, this MCP server only verifies them.

Same architecture as `examples/04-keycloak-resource-server` (TypeScript), rebuilt on the official
`mcp` Python SDK (2.1.1) to prove the auth contract is language-independent:

  * Keycloak (http://<PUBLIC_HOST>:8180/realms/mcp) is the OAuth 2.1 authorization server.
  * This process is a PURE resource server: RFC 9728 Protected Resource Metadata at
    /.well-known/oauth-protected-resource/mcp, a `WWW-Authenticate: Bearer … resource_metadata=…`
    challenge on 401, and local JWT validation against Keycloak's JWKS (PyJWT + PyJWKClient).
  * The unchanged TypeScript client of example 04 (`client.ts` here is a copy pointed at port
    4111) walks the whole discovery dance against it — the interop proof.

Environment handling mirrors `src/shared/env.ts`: the repo-root `.env` is loaded first and
existing process environment variables win. Every advertised URL is built from PUBLIC_HOST —
never localhost — so clients on other LAN machines can discover and dial it.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt
from dotenv import load_dotenv
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp.server import MCPServer
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.routes import create_protected_resource_routes
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.transport_security import TransportSecuritySettings

# ---------------------------------------------------------------- env (mirrors src/shared/env.ts)

REPO_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(REPO_ROOT / ".env")  # repo-root .env, existing process env wins (same as dotenv/config)

EXAMPLE_NAME = "11-python-mcp-keycloak"
SCOPE_TOOLS = "mcp:tools"
SCOPE_ADMIN = "mcp:admin"


def env(name: str, fallback: str | None = None) -> str:
    value = (os.environ.get(name) or "").strip()
    if value:
        return value
    if fallback is not None:
        return fallback
    raise RuntimeError(f"Missing required environment variable {name} (see .env.example)")


def detect_lan_address() -> str | None:
    """First non-loopback IPv4 of this machine (what other LAN machines can reach)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))  # TEST-NET-1; UDP connect sends no packet
        address = probe.getsockname()[0]
        return None if address.startswith("127.") else address
    except OSError:
        return None
    finally:
        probe.close()


def public_host() -> str:
    """Host other machines use to reach this box — PUBLIC_HOST, else auto-detected, never localhost."""
    return env("PUBLIC_HOST", detect_lan_address() or "127.0.0.1")


def public_url(port_number: int, path: str = "/mcp") -> str:
    return f"http://{public_host()}:{port_number}{path.rstrip('/')}"


def keycloak_issuer() -> str:
    """Byte-identical to `keycloak().issuer` in src/shared/env.ts (and to the `iss` claim)."""
    base = env("KEYCLOAK_URL", f"http://{public_host()}:{env('KEYCLOAK_PORT', '8180')}").rstrip("/")
    return f"{base}/realms/{env('KEYCLOAK_REALM', 'mcp')}"


def audiences() -> list[str]:
    return [a.strip() for a in env("MCP_AUDIENCE", "mcp-server").split(",") if a.strip()]


PORT = int(env("PORT_11", env("MCP_PORT", "4111")))

# ---------------------------------------------------------------- Keycloak policy (src/shared/jwt.ts twin)


def token_scopes(payload: dict[str, Any]) -> list[str]:
    """The token's own scopes: `scope` (space separated) or the `scp` array some IdPs use."""
    scope = payload.get("scope")
    if isinstance(scope, str):
        return [s for s in scope.split(" ") if s]
    scp = payload.get("scp")
    if isinstance(scp, list):
        return [s for s in scp if isinstance(s, str)]
    return []


def realm_roles(payload: dict[str, Any]) -> list[str]:
    realm_access = payload.get("realm_access")
    roles = realm_access.get("roles") if isinstance(realm_access, dict) else None
    return [r for r in roles if isinstance(r, str)] if isinstance(roles, list) else []


def effective_scopes(payload: dict[str, Any]) -> list[str]:
    """Same rule as `keycloakEffectiveScopes` in src/shared/jwt.ts: scope = what the CLIENT was
    granted, role = what the USER may do; `mcp:admin` survives only for users holding the
    `mcp-admin` realm role. Tools consult nothing but this list."""
    roles = realm_roles(payload)
    return [s for s in token_scopes(payload) if s != SCOPE_ADMIN or "mcp-admin" in roles]


# ---------------------------------------------------------------- token verifier


class JwksTokenVerifier:
    """`mcp.server.auth.provider.TokenVerifier` validating Keycloak JWTs against the realm JWKS.

    PyJWKClient fetches (and caches) the signing keys; `jwt.decode` enforces signature,
    `exp`/`iat`, `iss` and `aud` with 5 s leeway, RS256 only (`alg: none` and HS256 are rejected
    by the allow-list). ANY failure returns None — the SDK's RequireAuthMiddleware turns that
    into 401 + `WWW-Authenticate: Bearer error="invalid_token", … resource_metadata="…"`, which
    is what restarts client-side OAuth discovery. Scope enforcement (403 insufficient_scope) is
    the middleware's job via AuthSettings.required_scopes, not ours.

    `signing_key` (a public key object or PEM) bypasses the JWKS fetch — used by the pytest
    suite to verify the policy hermetically with in-process RSA keys.
    """

    def __init__(
        self,
        *,
        issuer: str,
        audiences: list[str],
        jwks_url: str | None = None,
        signing_key: Any | None = None,
        leeway_seconds: float = 5.0,
    ) -> None:
        if (jwks_url is None) == (signing_key is None):
            raise ValueError("provide exactly one of jwks_url or signing_key")
        self._issuer = issuer
        self._audiences = audiences
        self._signing_key = signing_key
        self._leeway = leeway_seconds
        self._jwk_client = jwt.PyJWKClient(jwks_url, cache_keys=True) if jwks_url else None

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            if self._jwk_client is not None:
                # PyJWKClient is blocking urllib (cached after the first fetch): keep it off the loop.
                key = (await asyncio.to_thread(self._jwk_client.get_signing_key_from_jwt, token)).key
            else:
                key = self._signing_key
            payload: dict[str, Any] = jwt.decode(
                token,
                key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audiences,
                leeway=self._leeway,
                options={"require": ["exp", "iss", "aud"]},
            )
        except jwt.PyJWKClientConnectionError as error:  # our IdP is down, not the client's fault
            print(f"[jwt] cannot fetch the signing keys: {error}", file=sys.stderr)
            return None
        except Exception:  # expired / wrong iss / wrong aud / bad signature / not a JWT / alg not allowed
            return None

        aud = payload.get("aud")
        first_aud = aud[0] if isinstance(aud, list) and aud else aud
        return AccessToken(
            token=token,
            client_id=str(payload.get("azp") or payload.get("client_id") or payload.get("sub") or "unknown"),
            scopes=effective_scopes(payload),
            expires_at=int(payload["exp"]),
            resource=first_aud if isinstance(first_aud, str) and first_aud.startswith(("http://", "https://")) else None,
            subject=payload.get("sub"),
            claims=payload,
        )


# ---------------------------------------------------------------- tools (src/shared/tools.ts twins)


def format_auth_info(access_token: AccessToken | None) -> dict[str, Any]:
    """Plain-JSON view of the verified token for `whoami` — the raw token is deliberately omitted.
    Same shape as `formatAuthInfo` in src/shared/tools.ts, plus top-level subject/username."""
    if access_token is None:
        return {"anonymous": True}
    claims = access_token.claims or {}
    username = claims.get("preferred_username") or claims.get("username")
    info = {
        "clientId": access_token.client_id,
        "scopes": access_token.scopes,
        "expiresAt": access_token.expires_at,
        "expiresAtIso": datetime.fromtimestamp(access_token.expires_at, tz=UTC)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
        if access_token.expires_at
        else None,
        "resource": access_token.resource,
        "subject": access_token.subject,
        "username": username,
        "extra": {
            "sub": claims.get("sub"),
            "username": username,
            "email": claims.get("email"),
            "roles": realm_roles(claims),
            "claims": claims,
        },
    }
    info["extra"] = {k: v for k, v in info["extra"].items() if v is not None}
    return {k: v for k, v in info.items() if v is not None}


def register_tools(server: MCPServer) -> None:
    @server.tool(title="Who am I", description="Returns the identity the server derived from your credentials.", structured_output=False)
    def whoami() -> str:
        return json.dumps(format_auth_info(get_access_token()), indent=2)

    @server.tool(title="Add", description="Adds two numbers.", structured_output=False)
    def add(a: float, b: float) -> str:
        total = a + b
        return str(int(total)) if float(total).is_integer() else str(total)

    @server.tool(title="Admin only", description=f"Succeeds only for callers holding the {SCOPE_ADMIN} scope.", structured_output=False)
    def admin_only() -> str:
        access_token = get_access_token()
        if access_token is not None and SCOPE_ADMIN in access_token.scopes:
            return f"admin ok: {access_token.client_id} has {SCOPE_ADMIN}"
        raise ToolError(f"insufficient_scope: admin_only requires scope {SCOPE_ADMIN}")


# ---------------------------------------------------------------- app assembly


def transport_security() -> TransportSecuritySettings:
    """DNS-rebinding protection: the twin of `allowedHostnames()` in src/shared/http.ts.
    The SDK compares the FULL Host header, so each name is allowed with and without a port."""
    hosts = [public_host(), "localhost", "127.0.0.1", "[::1]"]
    hosts += [h.strip().lower() for h in os.environ.get("MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[pattern for host in hosts for pattern in (f"{host}:*", host)],
        allowed_origins=[f"http://{host}:*" for host in hosts],
    )


def build_app() -> Starlette:
    issuer = keycloak_issuer()
    mcp_url = public_url(PORT)
    verifier = JwksTokenVerifier(
        issuer=issuer,
        audiences=audiences(),
        jwks_url=f"{issuer}/protocol/openid-connect/certs",  # same derivation as keycloak().jwksUri
    )
    server = MCPServer(
        EXAMPLE_NAME,
        token_verifier=verifier,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(issuer),
            resource_server_url=AnyHttpUrl(mcp_url),
            # Enforced by RequireAuthMiddleware (missing scope -> 403 insufficient_scope). The 401
            # challenge carries NO scope= parameter (verified in mcp 2.1.1 bearer_auth.py), so
            # SEP-835 clients fall through to the PRM's scopes_supported below and bob can ask for
            # mcp:admin — the same wiring as example 04's "required scopes on the verifier".
            required_scopes=[SCOPE_TOOLS],
        ),
    )
    register_tools(server)

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    app = server.streamable_http_app(transport_security=transport_security())

    # The SDK's auto-mounted PRM advertises only required_scopes and no resource_name; replace it
    # with the full RFC 9728 document so it is field-by-field identical to example 04's
    # (resource, authorization_servers, scopes_supported, resource_name, bearer_methods_supported).
    well_known = "/.well-known/oauth-protected-resource"
    app.router.routes = [r for r in app.router.routes if not str(getattr(r, "path", "")).startswith(well_known)]
    app.router.routes.extend(
        create_protected_resource_routes(
            resource_url=AnyHttpUrl(mcp_url),
            authorization_servers=[AnyHttpUrl(issuer)],
            scopes_supported=[SCOPE_TOOLS, SCOPE_ADMIN],
            resource_name=EXAMPLE_NAME,
        )
    )
    return app


def main() -> None:
    import uvicorn

    banner = (
        f"[{EXAMPLE_NAME}] listening on 0.0.0.0:{PORT}\n"
        f"[{EXAMPLE_NAME}] MCP endpoint: {public_url(PORT)}   (PUBLIC_HOST {public_host()})\n"
        f"[{EXAMPLE_NAME}] PRM:          {public_url(PORT, '/.well-known/oauth-protected-resource/mcp')}\n"
        f"[{EXAMPLE_NAME}] issuer:       {keycloak_issuer()}"
    )
    print(banner, file=sys.stderr)
    uvicorn.run(build_app(), host="0.0.0.0", port=PORT, log_level="info", access_log=env("MCP_LOG", "1") != "0")


if __name__ == "__main__":
    main()
