# 04 — Keycloak resource server (the spec-recommended pattern)

Keycloak is the OAuth 2.1 **authorization server**; this MCP server is a pure **resource
server**: it serves RFC 9728 Protected Resource Metadata and verifies Keycloak's RS256 JWTs
against the realm's JWKS (issuer, audience `mcp-server`, expiry, required scope `mcp:tools`,
role-gated `mcp:admin`). It never sees a password and never issues a token.

Full walk-through with the captured discovery trace: **`docs/04-keycloak-resource-server.md`**.

## Run it

```bash
npm run kc:up                # once — Keycloak + realm mcp on http://<PUBLIC_HOST>:8180
npm run ex:04:server         # terminal 1 — http://<PUBLIC_HOST>:4104/mcp
npm run ex:04:client         # terminal 2 — DCR + PKCE + browser; log in as alice/password
```

The first client run performs Dynamic Client Registration, opens the browser (Keycloak login +
consent) and ends with `adminOnly=denied` for alice. Variants:

```bash
npm run ex:04:client                             # second run: stored/refreshed tokens, no browser
npm run ex:04:client -- --logout                 # forget tokens + the dynamically registered client
OAUTH_CLIENT_ID=mcp-cli npm run ex:04:client     # pre-registered public client (no DCR, no consent)
OAUTH_CLIENT_ID=mcp-cli EXPECT_ADMIN=ok npm run ex:04:client        # log in as bob → admin ok
MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password" \
  npm run ex:04:client                           # headless login (CI / smoke)
npm run ex:04:client -- http://192.168.78.87:4104/mcp               # client on another machine
OAUTH_REDIRECT_HOST=$PUBLIC_HOST npm run ex:04:client               # browser on another machine
```

`mcp-cli` only has the callback port **4199** registered — keep `OAUTH_CALLBACK_PORT` at its
default for pre-registered runs. DCR runs register whatever redirect URI the client currently has,
so any free port works there.

## Verify

```bash
npx vitest run examples/04-keycloak-resource-server   # negative matrix (hermetic) + realm-backed rows
npm run smoke -- 04                                   # end-to-end on the real port with the headless browser
```

## Break it (details + captured responses in the docs page)

* no/garbage/expired/tampered token → **401** with `WWW-Authenticate: Bearer error="invalid_token",
  … resource_metadata="…/.well-known/oauth-protected-resource/mcp"` (no `scope=` — SEP-835)
* valid token without `mcp:tools` → **403** `insufficient_scope`, `error_description="missing scope: mcp:tools"`
* token with `aud` ≠ `mcp-server` or a foreign `iss` → **401**
* alice calling `admin_only` → tool error (scope filtered at issuance *and* by `keycloakEffectiveScopes`)
* bob's token on alice's `mcp-session-id` → **403** "session belongs to a different principal"
* `GET /.well-known/oauth-authorization-server` on **this** origin → **404** (no AS mirror on a pure RS)

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT_04` (or `MCP_PORT`) | `4104` | server port |
| `KEYCLOAK_URL` / `KEYCLOAK_REALM` | `http://<PUBLIC_HOST>:8180` / `mcp` | issuer = `<url>/realms/<realm>` |
| `MCP_AUDIENCE` | `mcp-server` | accepted `aud` values (comma list) |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | – (DCR) | pre-registered client instead of DCR |
| `OAUTH_CALLBACK_PORT` / `OAUTH_REDIRECT_HOST` | `4199` / `127.0.0.1` | loopback callback listener |
| `MCP_AUTH_STORE_DIR` | `<repo>/.mcp-auth` | token/registration store (0600) |
| `MCP_BROWSER_CMD` / `MCP_NO_BROWSER` | – | headless login command / print URL only |
| `MCP_SERVER_URL` (or argv) | `http://<PUBLIC_HOST>:4104/mcp` | client target |
| `EXPECT_ADMIN` | – | `ok`/`denied` → client exits 2 on mismatch |

## Integration notes

1. **smoke rows for 04**: the `bob (admin)` step reuses the store the `pre-registered mcp-cli`
   (alice) step just filled, so the client correctly reuses alice's still-valid tokens and exits 2
   (`EXPECT_ADMIN=ok` vs denied). The row sequence needs a `--logout` step in between, exactly as
   example 03's rows have. Verified: `client --logout` followed by the identical bob invocation on
   the same store passes (`adminOnly=ok`, exit 0). Everything else in `smoke -- 04` passes.
2. **smoke under `OAUTH_CALLBACK_PORT=4194`** (parallel-agent convention): the two `mcp-cli` rows
   then fail on Keycloak's "Invalid parameter: redirect_uri" page — only 4199 is registered for
   `mcp-cli` in the realm. The DCR rows pass on any port. Not fixable inside the example.
3. **`CliOAuthProvider` store key** is `sha256(serverUrl + clientName)` and ignores the client id,
   so switching `OAUTH_CLIENT_ID` would silently replay tokens minted for the dynamically
   registered client as `mcp-cli`. Worked around in `client.ts` (the static client id is folded
   into `clientName`); consider keying the shared store by client id in Phase 3.
4. **`src/shared/keycloak.test.ts:95`** still asserts alice's token *contains* `mcp:admin`; since
   the realm's role scope mappings filter that scope at issuance the assertion now fails against
   the running realm (`docs/design.md` + shared README were already corrected in 75d36d4, the
   shared test was not). This example's tests assert the current behaviour.
