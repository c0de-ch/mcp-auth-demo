"""11 — bonus Python MCP client: the same OAuth dance as the TS client, in `mcp` (Python) 2.1.1.

`OAuthClientProvider` (an httpx auth hook) performs the whole discovery chain on the first 401 —
PRM → Keycloak metadata → Dynamic Client Registration (or OAUTH_CLIENT_ID) → PKCE → browser →
code → tokens — exactly like `src/shared/client/oauth-cli.ts`. This file only supplies what a CLI
must decide for itself: the JSON token store, the loopback callback listener and how the
authorization URL reaches a browser (MCP_BROWSER_CMD / MCP_NO_BROWSER).

Usage: npm run ex:11:client:py [-- http://<host>:4111/mcp | --logout]     (or MCP_SERVER_URL=…)
Env (same knobs as the TS client): OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET, OAUTH_CALLBACK_PORT,
OAUTH_REDIRECT_HOST, MCP_AUTH_STORE_DIR, MCP_BROWSER_CMD, MCP_NO_BROWSER, EXPECT_ADMIN.
Output contract (§4.4): report on stdout, diagnostics on stderr, last stdout line `RESULT <json>`;
exit 0, or 2 when EXPECT_ADMIN disagrees, 1 on any error.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from pydantic import AnyUrl

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from server import PORT, REPO_ROOT, env, public_url  # the example's own env mirror (loads .env)

CALLBACK_TIMEOUT_SECONDS = 300.0


def log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


# ---------------------------------------------------------------- token store (oauth-cli.ts twin)


class FileTokenStorage(TokenStorage):
    """Tokens + client registration in `<MCP_AUTH_STORE_DIR|.mcp-auth>/<sha256(url+name)[:16]>.py.json`
    (mode 0600, git-ignored; `.py.json` so it never collides with the TS client's store).
    A pre-registered client (OAUTH_CLIENT_ID) bypasses the stored registration entirely."""

    def __init__(self, server_url: str, client_name: str, static_client: OAuthClientInformationFull | None) -> None:
        store_dir = Path(env("MCP_AUTH_STORE_DIR", str(REPO_ROOT / ".mcp-auth")))
        key = hashlib.sha256((server_url + client_name).encode()).hexdigest()[:16]
        self.store_file = store_dir / f"{key}.py.json"
        self._static_client = static_client

    def _load(self) -> dict[str, Any]:
        try:
            return json.loads(self.store_file.read_text())
        except (OSError, ValueError):
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self.store_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.store_file.write_text(json.dumps(data, indent=2))
        self.store_file.chmod(0o600)

    async def get_tokens(self) -> OAuthToken | None:
        raw = self._load().get("tokens")
        return OAuthToken.model_validate(raw) if raw else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._save({**self._load(), "tokens": tokens.model_dump(exclude_none=True)})

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        if self._static_client is not None:
            return self._static_client
        raw = self._load().get("client_info")
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        if self._static_client is not None:
            return  # a pre-registered client is configuration, not state
        self._save({**self._load(), "client_info": client_info.model_dump(mode="json", exclude_none=True)})

    def clear(self) -> None:
        self.store_file.unlink(missing_ok=True)


# ---------------------------------------------------------------- loopback callback listener


class CallbackListener:
    """One-shot HTTP listener for the authorization-code redirect (the provider validates state).
    Port 4199 is shared by every example client on this machine: on EADDRINUSE we wait and retry
    instead of failing — another example's login may be in flight."""

    def __init__(self, host: str, port: int) -> None:
        self.result: dict[str, str | None] = {}
        self._done = threading.Event()
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_: Any) -> None:  # silence the default stdout access log
                pass

            def do_GET(self) -> None:  # noqa: N802 (http.server API)
                url = urlparse(self.path)
                if url.path != "/callback":
                    self.send_response(404)
                    self.end_headers()
                    return
                params = {k: v[0] for k, v in parse_qs(url.query).items()}
                page_title = "Authorization failed" if "error" in params or "code" not in params else "Authorized"
                body = f"<!doctype html><title>{page_title}</title><h1>{page_title}</h1><p>Return to the terminal.</p>"
                self.send_response(400 if page_title != "Authorized" else 200)
                self.send_header("content-type", "text/html")
                self.end_headers()
                self.wfile.write(body.encode())
                listener.result = {k: params.get(k) for k in ("code", "state", "iss", "error", "error_description")}
                listener._done.set()

        bind_host = "127.0.0.1" if host in ("127.0.0.1", "localhost", "::1", "[::1]") else "0.0.0.0"
        deadline = time.monotonic() + 30
        while True:
            try:
                self._server = ThreadingHTTPServer((bind_host, port), Handler)
                break
            except OSError as error:
                if error.errno != errno.EADDRINUSE or time.monotonic() >= deadline:
                    raise
                log(f"[oauth] callback port {port} is busy (another example's login?) — retrying…")
                time.sleep(2)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        log(f"[oauth] waiting for callback on http://{bind_host}:{port}/callback")

    def wait(self, timeout: float) -> dict[str, str | None]:
        try:
            if not self._done.wait(timeout):
                raise TimeoutError(f"timed out after {timeout:.0f}s waiting for the OAuth callback")
            return self.result
        finally:
            self._server.shutdown()
            self._server.server_close()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def open_browser(url: str) -> None:
    """MCP_BROWSER_CMD (headless driver in smoke/tests) or xdg-open; MCP_NO_BROWSER=1 prints only.
    The driver runs OUTSIDE this uv project's venv: `uv run` puts .venv/bin first on PATH, which
    would make the conventional `python3 scripts/browser-login.py` resolve to a python without
    Playwright (that is installed system-wide)."""
    if os.environ.get("MCP_NO_BROWSER") == "1":
        return
    driver = (os.environ.get("MCP_BROWSER_CMD") or "").strip()
    command = [*shlex.split(driver), url] if driver else ["xdg-open", url]
    child_env = os.environ.copy()
    venv = child_env.pop("VIRTUAL_ENV", None)
    if venv:
        child_env["PATH"] = os.pathsep.join(p for p in child_env.get("PATH", "").split(os.pathsep) if not p.startswith(venv))
    try:
        subprocess.Popen(command, env=child_env, stdout=sys.stderr, stderr=sys.stderr, start_new_session=True)
    except OSError as error:
        log(f"[oauth] could not launch a browser ({error}); open the URL yourself")


# ---------------------------------------------------------------- provider wiring


def build_provider(server_url: str) -> tuple[OAuthClientProvider, FileTokenStorage]:
    redirect_host = env("OAUTH_REDIRECT_HOST", "127.0.0.1")
    callback_port = int(env("OAUTH_CALLBACK_PORT", "4199"))
    redirect_url = f"http://{redirect_host}:{callback_port}/callback"

    static_client: OAuthClientInformationFull | None = None
    if os.environ.get("OAUTH_CLIENT_ID", "").strip():
        secret = os.environ.get("OAUTH_CLIENT_SECRET", "").strip() or None  # empty = public client
        static_client = OAuthClientInformationFull(
            client_id=env("OAUTH_CLIENT_ID"),
            client_secret=secret,
            token_endpoint_auth_method="client_secret_post" if secret else "none",
            redirect_uris=[AnyUrl(redirect_url)],
        )

    storage = FileTokenStorage(server_url, "11-python-mcp-keycloak py", static_client)
    listener: CallbackListener | None = None

    async def redirect_handler(authorization_url: str) -> None:
        nonlocal listener
        listener = CallbackListener(redirect_host, callback_port)  # bind BEFORE the browser opens
        log("\n==> Authorization required. Open this URL in a browser:\n")
        log(f"    {authorization_url}\n")
        open_browser(authorization_url)

    async def callback_handler() -> AuthorizationCodeResult:
        assert listener is not None, "redirect_handler must run first"
        params = await asyncio.to_thread(listener.wait, CALLBACK_TIMEOUT_SECONDS)
        if params.get("error") or not params.get("code"):
            raise RuntimeError(f"authorization failed: {params.get('error') or 'no code in callback'}")
        return AuthorizationCodeResult(code=params["code"] or "", state=params.get("state"), iss=params.get("iss"))

    provider = OAuthClientProvider(
        server_url=server_url,
        client_metadata=OAuthClientMetadata(
            client_name="11-python-mcp-keycloak py",
            redirect_uris=[AnyUrl(redirect_url)],
            # authorization_code ONLY: with refresh_token declared, the SDK (SEP-2207) appends
            # `offline_access` to the requested scope because Keycloak advertises it — and this
            # realm's users do not hold the offline_access role, so the token exchange fails with
            # "Offline tokens not allowed". Keycloak issues a (session-bound) refresh token for
            # the code grant anyway, which the SDK uses on later runs.
            grant_types=["authorization_code"],
            response_types=["code"],
            token_endpoint_auth_method="none",  # public client: PKCE instead of a secret
            scope="mcp:tools",  # fallback only — the 401/PRM-driven scopes (SEP-835) override it
        ),
        storage=storage,
        redirect_handler=redirect_handler,
        callback_handler=callback_handler,
    )
    return provider, storage


# ---------------------------------------------------------------- the demo (client/run.ts twin)


def outcome(result: Any) -> dict[str, Any]:
    text = "\n".join(c.text for c in result.content if getattr(c, "type", None) == "text")
    try:
        parsed: Any = json.loads(text)
    except ValueError:
        parsed = None
    return {"isError": result.is_error is True, "text": text, "json": parsed}


def fmt(o: dict[str, Any]) -> str:
    body = json.dumps(o["json"]) if o["json"] is not None else o["text"]
    return f"ERROR {body}" if o["isError"] else body


async def run(server_url: str) -> int:
    provider, _ = build_provider(server_url)
    async with create_mcp_http_client(auth=provider) as http_client:
        async with streamable_http_client(server_url, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = sorted(t.name for t in (await session.list_tools()).tools)
                print(f"tools        -> {', '.join(tools)}")
                whoami = outcome(await session.call_tool("whoami", {}))
                print(f"whoami       -> {fmt(whoami)}")
                add = outcome(await session.call_tool("add", {"a": 2, "b": 3}))
                print(f"add(2, 3)    -> {fmt(add)}")
                admin_only = outcome(await session.call_tool("admin_only", {}))
                print(f"admin_only   -> {fmt(admin_only)}")

    line = {
        "example": "11",
        "tools": tools,
        "whoami": whoami["json"] if whoami["json"] is not None else whoami["text"],
        "add": add["text"],
        "adminOnly": "denied" if admin_only["isError"] else "ok",
        "extra": {"client": "python"},
    }
    print(f"RESULT {json.dumps(line, separators=(',', ':'))}")
    expected = (os.environ.get("EXPECT_ADMIN") or "").strip()
    if expected and expected != line["adminOnly"]:
        log(f"EXPECT_ADMIN={expected} but admin_only was {line['adminOnly']}")
        return 2
    return 0


def main() -> int:
    argv = sys.argv[1:]
    positional = next((a for a in argv if not a.startswith("--")), None)
    server_url = positional or env("MCP_SERVER_URL", public_url(PORT))
    if "--logout" in argv:
        _, storage = build_provider(server_url)
        storage.clear()
        print(f"Logged out: removed {storage.store_file}")
        return 0
    log(f"connecting to {server_url} (OAuth via Keycloak; Python client)")
    try:
        return asyncio.run(run(server_url))
    except Exception as error:  # noqa: BLE001 — a CLI reports and exits
        log(f"error: {type(error).__name__}: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
