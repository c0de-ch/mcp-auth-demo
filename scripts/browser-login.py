#!/usr/bin/env python3
"""Headless browser driver for the OAuth login pages (Keycloak and the embedded AS of example 03).

Usage:
    browser-login.py [--user alice] [--password password] [--screenshot-dir test-results]
                     [--timeout 30] <authorization-url>

Used by the example clients through MCP_BROWSER_CMD, e.g.
    MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password" npm run ex:04:client
The client passes the authorization URL as the last argument. The script opens it in headless
Chromium, fills the login form (#username / #password / #kc-login), clicks through a consent page
(input[name=accept], fallback #kc-login) and stops when the browser landed on the loopback
callback (http://<127.0.0.1|localhost|PUBLIC_HOST>:<OAUTH_CALLBACK_PORT>/callback) or the page
says "Authorized". On failure it writes page HTML + a screenshot to --screenshot-dir and exits 1.

Requires Python Playwright with Chromium:  uv run --with playwright python -m playwright install chromium
Run it with `uv run --with playwright python scripts/browser-login.py …` when playwright is not
installed system-wide (set MCP_BROWSER_CMD accordingly).
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

try:
    from playwright.sync_api import TimeoutError as PlaywrightTimeout, sync_playwright
except ImportError:  # pragma: no cover - environment problem, not a test case
    print("browser-login: python playwright is not installed (uv run --with playwright python -m playwright install chromium)", file=sys.stderr)
    sys.exit(3)


def load_dotenv(path: Path) -> None:
    """Minimal .env reader (KEY=VALUE, # comments) so PUBLIC_HOST / OAUTH_CALLBACK_PORT are known."""
    if not path.is_file():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.split(" #", 1)[0].strip().strip('"').strip("'")
        os.environ.setdefault(key.strip(), value)


def callback_hosts() -> set[str]:
    hosts = {"127.0.0.1", "localhost"}
    if os.environ.get("PUBLIC_HOST"):
        hosts.add(os.environ["PUBLIC_HOST"])
    if os.environ.get("OAUTH_REDIRECT_HOST"):
        hosts.add(os.environ["OAUTH_REDIRECT_HOST"])
    return hosts


def is_callback(url: str) -> bool:
    parsed = urlparse(url)
    port = str(parsed.port or "")
    return parsed.path == "/callback" and parsed.hostname in callback_hosts() and port == os.environ.get("OAUTH_CALLBACK_PORT", "4199")


def log(msg: str) -> None:
    print(f"browser-login: {msg}", file=sys.stderr, flush=True)


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    load_dotenv(repo_root / ".env")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--user", default=os.environ.get("DEMO_USER", "alice"))
    parser.add_argument("--password", default=os.environ.get("DEMO_PASSWORD", "password"))
    parser.add_argument("--screenshot-dir", default=str(repo_root / "test-results"))
    parser.add_argument("--timeout", type=float, default=30.0, help="overall timeout in seconds")
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("url")
    args = parser.parse_args()

    deadline = time.monotonic() + args.timeout
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not args.headed)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        # The callback listener answers instantly; do not treat connection errors on it as failure —
        # the client only needs the code that was delivered with the request.
        try:
            log(f"opening {args.url}")
            page.goto(args.url, wait_until="domcontentloaded")
            last_action = ""
            while time.monotonic() < deadline:
                url = page.url
                if is_callback(url) or "Authorized" in (page.content() if url.startswith("http") else ""):
                    log(f"done: {url.split('?')[0]}")
                    return 0
                if page.locator("#username").count() and page.locator("#username").first.is_visible():
                    log(f"login form: user {args.user}")
                    page.fill("#username", args.user)
                    page.fill("#password", args.password)
                    submit = page.locator("#kc-login, button[type=submit], input[type=submit]").first
                    submit.click()
                    last_action = "login"
                    page.wait_for_load_state("domcontentloaded")
                    continue
                accept = page.locator("input[name=accept], #approve, button[name=accept]")
                if accept.count() and accept.first.is_visible():
                    log("consent page: accepting")
                    accept.first.click()
                    last_action = "consent"
                    page.wait_for_load_state("domcontentloaded")
                    continue
                error = page.locator("#input-error, .alert-error, .kc-feedback-text, .error")
                if error.count() and error.first.is_visible():
                    raise RuntimeError(f"page shows an error after {last_action or 'open'}: {error.first.inner_text().strip()[:200]}")
                time.sleep(0.25)
            raise PlaywrightTimeout(f"timed out after {args.timeout}s; last url {page.url}")
        except Exception as exc:  # noqa: BLE001 - report everything
            if is_callback(page.url):
                # navigation error on the callback (listener closed the connection) still means success
                log(f"done (callback reached): {page.url.split('?')[0]}")
                return 0
            out = Path(args.screenshot_dir)
            out.mkdir(parents=True, exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            try:
                page.screenshot(path=str(out / f"browser-login-{stamp}.png"), full_page=True)
                (out / f"browser-login-{stamp}.html").write_text(page.content())
                log(f"saved {out / f'browser-login-{stamp}.png'} and .html")
            except Exception:  # noqa: BLE001
                pass
            log(f"FAILED: {exc}")
            return 1
        finally:
            context.close()
            browser.close()


if __name__ == "__main__":
    sys.exit(main())
