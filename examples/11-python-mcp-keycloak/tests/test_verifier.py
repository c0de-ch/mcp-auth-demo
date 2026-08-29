"""Hermetic unit tests of `JwksTokenVerifier` and the effective-scopes rule (no network, no
Keycloak): tokens are minted with an in-process RSA key and verified with `signing_key=`, which
bypasses the JWKS fetch. Every rejection path must yield None — that is what the SDK middleware
turns into 401 + WWW-Authenticate. Run: `uv run --project examples/11-python-mcp-keycloak pytest`.
"""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from server import JwksTokenVerifier, effective_scopes, format_auth_info, token_scopes

ISSUER = "http://192.0.2.10:8180/realms/mcp"
AUDIENCE = "mcp-server"

_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = _PRIVATE_KEY.public_key()
OTHER_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def mint(*, alg: str = "RS256", key: Any = _PRIVATE_KEY, **overrides: Any) -> str:
    claims: dict[str, Any] = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "user-1",
        "azp": "mcp-cli",
        "preferred_username": "alice",
        "scope": "mcp:tools",
        "realm_access": {"roles": ["mcp-user"]},
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm=alg)


def verifier() -> JwksTokenVerifier:
    return JwksTokenVerifier(issuer=ISSUER, audiences=[AUDIENCE], signing_key=PUBLIC_KEY)


async def test_valid_token_yields_access_token_with_effective_scopes() -> None:
    access = await verifier().verify_token(mint(scope="mcp:tools mcp:admin"))
    assert access is not None
    assert access.client_id == "mcp-cli"  # azp wins over sub
    assert access.scopes == ["mcp:tools"]  # mcp:admin dropped: no mcp-admin role
    assert access.subject == "user-1"
    assert isinstance(access.expires_at, int) and access.expires_at > time.time()
    assert access.claims is not None and access.claims["preferred_username"] == "alice"


async def test_admin_scope_survives_only_with_the_admin_role() -> None:
    token = mint(scope="mcp:tools mcp:admin", realm_access={"roles": ["mcp-user", "mcp-admin"]})
    access = await verifier().verify_token(token)
    assert access is not None
    assert access.scopes == ["mcp:tools", "mcp:admin"]


async def test_expired_token_is_rejected() -> None:
    assert await verifier().verify_token(mint(exp=int(time.time()) - 60)) is None


async def test_expiry_leeway_tolerates_small_clock_skew() -> None:
    assert await verifier().verify_token(mint(exp=int(time.time()) - 2)) is not None  # inside 5 s leeway


async def test_wrong_issuer_is_rejected() -> None:
    assert await verifier().verify_token(mint(iss="http://192.0.2.99:8180/realms/other")) is None


async def test_wrong_audience_is_rejected() -> None:
    assert await verifier().verify_token(mint(aud="account")) is None


async def test_missing_claims_are_rejected() -> None:
    for missing in ("exp", "iss", "aud"):
        assert await verifier().verify_token(mint(**{missing: None})) is None


async def test_alg_none_is_rejected() -> None:
    header = jwt.api_jws.base64url_encode(b'{"alg":"none","typ":"JWT"}').decode()
    payload = jwt.api_jws.base64url_encode(b'{"sub":"user-1"}').decode()
    assert await verifier().verify_token(f"{header}.{payload}.") is None


async def test_hs256_with_the_public_key_as_secret_is_rejected() -> None:
    # Classic key-confusion attack; the RS256 allow-list refuses it before any key material is used.
    _, payload, _ = mint().split(".")  # a valid token's claims under a swapped HS256 header
    header = jwt.api_jws.base64url_encode(b'{"alg":"HS256","typ":"JWT"}').decode()
    assert await verifier().verify_token(f"{header}.{payload}.forgedsig") is None


async def test_bad_signature_is_rejected() -> None:
    assert await verifier().verify_token(mint(key=OTHER_PRIVATE_KEY)) is None


async def test_tampered_payload_is_rejected() -> None:
    header, payload, signature = mint().split(".")
    tampered = jwt.api_jws.base64url_encode(b'{"sub":"admin","scope":"mcp:admin"}').decode()
    assert await verifier().verify_token(f"{header}.{tampered}.{signature}") is None


async def test_garbage_is_rejected() -> None:
    assert await verifier().verify_token("not-a-jwt") is None
    assert await verifier().verify_token("") is None


def test_token_scopes_reads_scope_string_and_scp_array() -> None:
    assert token_scopes({"scope": "a b  c"}) == ["a", "b", "c"]
    assert token_scopes({"scp": ["a", "b", 3]}) == ["a", "b"]
    assert token_scopes({}) == []


def test_effective_scopes_never_invents_scopes() -> None:
    assert effective_scopes({"scope": "email", "realm_access": {"roles": ["mcp-admin"]}}) == ["email"]
    assert effective_scopes({"scope": "mcp:admin"}) == []


def test_format_auth_info_omits_the_raw_token() -> None:
    import asyncio

    access = asyncio.run(verifier().verify_token(mint()))
    info = format_auth_info(access)
    assert info["username"] == "alice" and info["subject"] == "user-1"
    assert "token" not in str(info.keys())
    assert access is not None and access.token not in str(info)


def test_verifier_requires_exactly_one_key_source() -> None:
    with pytest.raises(ValueError):
        JwksTokenVerifier(issuer=ISSUER, audiences=[AUDIENCE])
    with pytest.raises(ValueError):
        JwksTokenVerifier(issuer=ISSUER, audiences=[AUDIENCE], jwks_url="http://192.0.2.10/certs", signing_key=PUBLIC_KEY)
