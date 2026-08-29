# 11 — Python twin of example 04 (Keycloak resource server, `mcp` Python SDK)

The spec-recommended AS/RS split of example 04, with the resource server rewritten on the official
`mcp` Python SDK 2.1.1: Keycloak issues the tokens, `server.py` serves RFC 9728 Protected Resource
Metadata and validates JWTs against the realm JWKS (PyJWT + `PyJWKClient`). The **unchanged
TypeScript client** (`client.ts`, example 04's shape) does the whole OAuth discovery dance against
it — the interop proof — and `client.py` is a bonus client on the Python SDK's
`OAuthClientProvider`. Full walk-through: [`docs/11-python-mcp-keycloak.md`](../../docs/11-python-mcp-keycloak.md).

## Run

```bash
npm run kc:up                                     # Keycloak (once)
uv sync --project examples/11-python-mcp-keycloak # Python deps (once; uv creates .venv from uv.lock)
npm run ex:11:server                              # terminal 1 — http://<PUBLIC_HOST>:4111/mcp
npm run ex:11:client                              # terminal 2 — TS client, Dynamic Client Registration
OAUTH_CLIENT_ID=mcp-cli npm run ex:11:client      #   … or the pre-registered client (no consent page)
npm run ex:11:client:py                           # bonus: the Python client, same dance
```

Login as `alice`/`password` (admin denied) or `bob`/`password` (`EXPECT_ADMIN=ok`). Headless:
prefix with `MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password"`.
`-- --logout` wipes the stored tokens; `-- http://<host>:4111/mcp` / `MCP_SERVER_URL` dials another machine.

## Env

| Variable | Default | Meaning |
|---|---|---|
| `PORT_11` (`MCP_PORT`) | `4111` | server port |
| `PUBLIC_HOST`, `KEYCLOAK_URL/PORT/REALM`, `MCP_AUDIENCE`, `MCP_ALLOWED_HOSTS`, `MCP_LOG` | as everywhere | `server.py` re-implements `src/shared/env.ts`'s precedence via `python-dotenv` (repo-root `.env`, process env wins) |
| `OAUTH_CLIENT_ID/SECRET`, `OAUTH_CALLBACK_PORT`, `OAUTH_REDIRECT_HOST`, `MCP_AUTH_STORE_DIR`, `MCP_BROWSER_CMD`, `MCP_NO_BROWSER`, `EXPECT_ADMIN` | as everywhere | both clients honour the same knobs; `client.py` stores under `.mcp-auth/<hash>.py.json` |

## Verify / break it

```bash
npx vitest run examples/11-python-mcp-keycloak      # spawns server.py: PRM shape = 04, 401/403/421 matrix, TS SDK round trips
uv run --project examples/11-python-mcp-keycloak pytest   # hermetic verifier tests (expired/iss/aud/alg-none → None)
curl -s http://<host>:4111/.well-known/oauth-protected-resource/mcp | jq .   # the PRM
curl -si -X POST http://<host>:4111/mcp -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' -d '{}' | grep -i www-authenticate     # the 401 challenge
```

## Integration notes

* **Realm/users lack the `offline_access` role.** The Python SDK auto-appends `offline_access` to
  the requested scope (SEP-2207) whenever the client declares the `refresh_token` grant and the AS
  advertises the scope; Keycloak then refuses the code exchange with `not_allowed: Offline tokens
  not allowed for the user or client` because `alice`/`bob` only hold `mcp-user`/`mcp-admin`.
  `client.py` therefore declares `grant_types=["authorization_code"]` (Keycloak issues a
  session-bound refresh token anyway, which the SDK uses). If the realm ever gets re-opened,
  assigning users the built-in `offline_access` role would let the Python client keep the
  `refresh_token` grant declared. The TS client is unaffected (it implements no SEP-2207).
* **`OAUTH_CALLBACK_PORT` vs `mcp-cli`.** The realm registers `mcp-cli`'s redirect URIs on port
  4199 only (exact match). The smoke row for 11 runs the TS client with `OAUTH_CLIENT_ID=mcp-cli`,
  so `npm run smoke -- 11` must run with the default callback port 4199 — running it with
  `OAUTH_CALLBACK_PORT=4181` makes Keycloak answer `Invalid parameter: redirect_uri`. 4181 works
  for DCR runs (the registration then carries that port).
* **Deliberate behavioural deltas vs the TS twin** (asserted in `server.test.ts`, explained in the
  docs page): forged `Host` → **421** (TS: 403); a foreign principal on an existing session →
  **404 "Session not found"** (TS: 403); tool errors are prefixed `Error executing tool <name>: …`
  by the Python SDK; a JWKS outage surfaces as 401 (`verify_token` → `None`; the TS `jwt.ts`
  answers 500 `ServerError`) — noted as a demo trade-off in the docs threat-model section.
* No shared-module changes were needed; nothing outside `examples/11-python-mcp-keycloak/**` and
  `docs/11-python-mcp-keycloak.md` was touched. `uv.lock` is committed; `.venv/` is git-ignored.
