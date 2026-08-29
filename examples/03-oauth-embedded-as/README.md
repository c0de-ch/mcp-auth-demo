# 03 — OAuth 2.1 with an embedded authorization server

The MCP server **is** the OAuth 2.1 authorization server: one process serves the metadata
documents, `/authorize` (with its own login + consent pages), `/token` (PKCE S256), `/register`
(open DCR), `/revoke` — and the guarded `/mcp` endpoint. No Keycloak. Everything is in memory.

Full walk-through: [`docs/03-oauth-embedded-as.md`](../../docs/03-oauth-embedded-as.md).

| File | Role |
|---|---|
| `server.ts` | `buildApp()`: pages + `mcpAuthRouter` + `requireBearerAuth` on `/mcp` |
| `provider.ts` | `DemoAuthorizationServer`: clients, codes, tokens, refresh rotation, users |
| `pages.ts` | `/login` and `/consent` (Keycloak-compatible element ids for the headless driver) |
| `client.ts` | `CliOAuthProvider` + `connectWithOAuth` — the standard SDK OAuth client |

## Run

```bash
npm run ex:03:server        # terminal 1 — http://<PUBLIC_HOST>:4103/mcp
npm run ex:03:client        # terminal 2 — browser opens: sign in as alice or bob (password: password)
npm run ex:03:client        # again: stored tokens, no browser
OAUTH_CLIENT_ID=mcp-cli npm run ex:03:client   # pre-registered client instead of DCR
npm run ex:03:client -- --logout               # wipe the client's token store
```

Headless (what smoke does): `MCP_BROWSER_CMD="python3 scripts/browser-login.py --user bob --password password" EXPECT_ADMIN=ok npm run ex:03:client`.

Users (DEMO): `alice`/`password` → may grant `mcp:tools`; `bob`/`password` → also `mcp:admin`.
The server is in-memory: after a **server restart** run the client with `--logout` once (its stored
registration/tokens refer to state the server no longer has; with a refresh token present the SDK
recovers on its own, but a clean store is simpler).

## Env

| Variable | Default | Meaning |
|---|---|---|
| `PORT_03` / `MCP_PORT` | 4103 | server port (issuer/resource/PRM are built from `PUBLIC_HOST` + this) |
| `OAUTH_CLIENT_ID` | – (DCR) | `mcp-cli` uses the pre-registered public client |
| `OAUTH_CALLBACK_PORT` | 4199 | client loopback listener; `mcp-cli` is seeded with 4199 **and** 4193 redirect URIs |
| `MCP_RATE_LIMIT` | 1 | `0` disables the SDK auth-router rate limits (tests/smoke) |
| `MCP_BROWSER_CMD`, `MCP_NO_BROWSER`, `MCP_AUTH_STORE_DIR`, `EXPECT_ADMIN`, `MCP_SERVER_URL` | – | see `.env.example` |

## Verify / break

```bash
npx vitest run examples/03-oauth-embedded-as        # the §6.3 negative matrix (42 tests, hermetic)
OAUTH_CALLBACK_PORT=4193 npm run smoke -- 03        # end-to-end on the real port
curl -s http://$PUBLIC_HOST:4103/.well-known/oauth-authorization-server | jq .
```

Break-it recipes (each is a test in `server.test.ts`): reuse an authorization code (revokes every
token from it), replay a rotated refresh token (revokes the family), wrong `code_verifier`,
unregistered/cross-matched redirect URIs, forged consent `csrf`, scope widening on refresh,
`grant_type=client_credentials` (unsupported by the embedded AS), 51× `POST /token` → 429.

## Integration notes

* **smoke row "logout" fails by framework design, not by example behaviour.** `scripts/smoke.ts`'s
  `runClient()` requires a `RESULT` line from every exit-0 step, but the shared
  `handleLogoutFlag()` contract (design §5.7, `src/shared/client/oauth-cli.ts`) prints only
  `Logged out: removed <store>` and exits 0 — a logout never connects, so a `RESULT` line would be
  fabricated. All other 03 rows pass. Suggested integrator fix in `scripts/smoke.ts`: treat a step
  without an `expect` (or with a new `noResult: true` flag) as exit-code-only, e.g.
  `if (!result && !step.expect) return 'exit 0 (no RESULT expected)';` before the throw.
* **§6.3 amendment implemented (SEP-835):** `requireBearerAuth` carries **no** `requiredScopes`,
  so the 401 challenge has `resource_metadata` but no `scope=`; the PRM's
  `scopes_supported: ["mcp:tools","mcp:admin"]` drives what clients request, and
  `provider.verifyAccessToken` throws `InsufficientScopeError` when `mcp:tools` is missing
  (403, still without a pinned `scope=`). Otherwise bob could never obtain `mcp:admin`.
* The seeded `mcp-cli` client registers redirect URIs for callback ports **4199 and 4193** ×
  {127.0.0.1, localhost, `PUBLIC_HOST`} so parallel-agent smoke runs (4193) and the documented
  default (4199) both work; loopback entries additionally get RFC 8252 port relaxation from the SDK.
* No shared-module changes needed; nothing copied from `src/shared`.
