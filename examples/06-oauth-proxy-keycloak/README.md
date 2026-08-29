# 06 — OAuth facade in front of Keycloak (`ProxyOAuthServerProvider`)

The MCP server presents itself as the authorization server: metadata, `/register`, `/authorize`,
`/token` and `/revoke` all live on `http://<PUBLIC_HOST>:4106`, and every one of them is proxied
to Keycloak. Clients (which run example 04's exact client code) never learn that Keycloak exists —
except for the browser, which Keycloak redirects **straight back to the CLI callback**.
Full walk-through, limitations and threat model: [`docs/06-oauth-proxy-keycloak.md`](../../docs/06-oauth-proxy-keycloak.md).

## Run it

```bash
npm run kc:up                 # once — Keycloak with the mcp realm
npm run ex:06:server          # terminal 1 — facade on http://<PUBLIC_HOST>:4106/mcp
npm run ex:06:client          # terminal 2 — DCR via the facade + browser login (alice / password)
npm run ex:06:client          # again: stored tokens, no browser
OAUTH_CLIENT_ID=mcp-cli npm run ex:06:client          # pre-registered client, no consent page
npm run ex:06:client -- --logout                      # forget tokens + the DCR'd client
```

Headless (as smoke/CI does it):
`MCP_BROWSER_CMD="python3 scripts/browser-login.py --user bob --password password" EXPECT_ADMIN=ok OAUTH_CLIENT_ID=mcp-cli npm run ex:06:client`

## Verify

```bash
curl -s http://$PUBLIC_HOST:4106/.well-known/oauth-protected-resource/mcp   # authorization_servers = [facade]
curl -s http://$PUBLIC_HOST:4106/.well-known/oauth-authorization-server     # every endpoint on :4106, Keycloak invisible
npx vitest run examples/06-oauth-proxy-keycloak                             # hermetic + Keycloak-backed matrix
```

## Break it (mirrors `server.test.ts`)

```bash
B=http://$PUBLIC_HOST:4106
curl -si "$B/authorize?client_id=unknown&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=http://127.0.0.1:4199/callback" | head -1   # 400 invalid_client, nothing reaches Keycloak
curl -si "$B/authorize?client_id=mcp-cli&response_type=code&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&redirect_uri=http://192.0.2.99:4199/callback" | head -1  # 400 unregistered redirect_uri, local
curl -si $B/token -d 'grant_type=authorization_code&client_id=mcp-cli&code=bogus&code_verifier=ccccccccccccccccccccccccccccccccccccccccccc' | head -1   # 500 server_error "Token exchange failed: 400"
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT_06` / `MCP_PORT` | `4106` | facade port (issuer = `http://<PUBLIC_HOST>:4106/`) |
| `KEYCLOAK_URL` / `KEYCLOAK_REALM` | derived / `mcp` | upstream Keycloak everything is proxied to |
| `OAUTH_CALLBACK_PORT` | `4199` | client callback port — for the seeded `mcp-cli` it must equal the port the realm was rendered with, because Keycloak re-validates the redirect URI exactly |
| `OAUTH_CLIENT_ID` | – (DCR) | `mcp-cli` = the realm's pre-registered public client |
| `MCP_AUDIENCE` | `mcp-server` | accepted `aud` of Keycloak's access tokens |
| `MCP_RATE_LIMIT` | `1` | `0` disables the SDK auth router's per-IP limits (tests/smoke) |

## Integration notes

* **Smoke step "pre-registered mcp-cli" under a non-default `OAUTH_CALLBACK_PORT`**: with
  `OAUTH_CALLBACK_PORT=4196 npm run smoke -- 06` (used while several agents share port 4199) the
  DCR rows pass but the `mcp-cli` row fails by design — Keycloak matches `mcp-cli`'s redirect
  URIs **exactly** and the realm registered only port 4199, so the facade relays the browser to a
  Keycloak error page ("Invalid parameter: redirect_uri"). A plain `npm run smoke -- 06` (callback
  4199) passes all rows. Not a smoke-framework bug; a realm/redirect-URI fact.
* **Token store vs `OAUTH_CLIENT_ID`** (framework observation, no change needed for 06): the
  `CliOAuthProvider` store key is `sha256(serverUrl + clientName)`, so switching to
  `OAUTH_CLIENT_ID=mcp-cli` after a DCR run would silently reuse the DCR client's still-valid
  tokens for up to 15 min. 06's `client.ts` therefore derives `clientName` from `OAUTH_CLIENT_ID`,
  which gives each client identity its own store file and makes the smoke `mcp-cli` step genuinely
  exercise `mcp-cli`. Example 04's smoke step 3 asserts `whoami.clientId === 'mcp-cli'` and may hit
  this token-reuse if its client keeps a single store; consider the same `clientName` split there
  (or a per-step `MCP_AUTH_STORE_DIR`) in Phase 2.
* Dynamically registered clients live only in the facade's **memory** (and in Keycloak's realm): a
  facade restart forgets the mapping and the SDK client recovers via `invalid_client` →
  re-registration. `npm run kc:reset` clears the accumulated realm clients.
