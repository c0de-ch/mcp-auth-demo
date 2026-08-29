# 07 — Token introspection (RFC 7662): revocation you can see

Example 04's OAuth shape — Keycloak issues tokens, this server is a pure resource server with
PRM discovery — but the server validates tokens **statefully**: instead of checking the JWT
signature it asks Keycloak's introspection endpoint (authenticating as the confidential client
`mcp-server`) and caches the verdict for `INTROSPECTION_TTL_SECONDS`. Revoke a token and this
server rejects it within one cache window; a JWKS-validating server (04) accepts it until `exp`.
Full walk-through: [`docs/07-token-introspection.md`](../../docs/07-token-introspection.md).

## Run it

```bash
npm run ex:07:server                                    # terminal 1 — http://<PUBLIC_HOST>:4107/mcp
OAUTH_CLIENT_ID=mcp-cli npm run ex:07:client            # terminal 2 — browser login as alice/password
npm run ex:07:client -- --revoke                        # revoke own token (RFC 7009), watch the 401 appear
npm run ex:07:revoke -- alice                           # kill alice's Keycloak sessions (admin REST) + wait one TTL
npm run ex:07:client                                    # → exits 1: stored token now rejected with 401
```

The client is 04's OAuth client pointed at 4107, with one deliberate difference: before
connecting it probes the server with the **stored** token and exits 1 on a 401 instead of
silently refreshing/re-authorizing — otherwise the SDK would hide the revocation from you.

## Verify / break it

```bash
npx vitest run examples/07-token-introspection          # negative matrix (hermetic) + Keycloak-backed
OAUTH_CALLBACK_PORT=4199 npm run smoke -- 07            # login → revoke → client exits 1 (needs port 4199, see notes)
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT_07` / `MCP_PORT` | `4107` | server port |
| `MCP_SERVER_CLIENT_SECRET` | `mcp-server-secret-demo` (DEMO) | secret of the introspecting client `mcp-server` |
| `INTROSPECTION_TTL_SECONDS` | `10` | positive-cache TTL = worst-case revocation latency (0 = introspect every request) |
| `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` | `admin` / `admin` (DEMO) | used by `ex:07:revoke` (admin REST logout) |
| `MCP_AUDIENCE` | `mcp-server` | accepted `aud` values (defence in depth) |
| client vars | see root `.env.example` | `OAUTH_CLIENT_ID`, `OAUTH_CALLBACK_PORT`, `MCP_SERVER_URL`, … as in 04 |

Files: `server.ts` (buildApp + `IntrospectionVerifier` with positive/negative cache),
`client.ts` (OAuth client + raw probe + `--revoke`), `revoke.ts` (admin logout + TTL wait),
`server.test.ts` (the §6.7 negative matrix).

## Integration notes

* **smoke framework**: `scripts/smoke.ts` requires a `RESULT <json>` line from *every* step that
  exits 0, including the `revoke.ts` step — so `revoke.ts` prints
  `RESULT {"example":"07","revoked":"alice","waitedSeconds":11}`. If the framework ever treats
  non-client steps differently, that line can go.
* **Callback port**: the realm registers `mcp-cli` redirect URIs only for
  `OAUTH_CALLBACK_PORT`(=4199), exact match. The 07 smoke row logs in with
  `OAUTH_CLIENT_ID=mcp-cli`, so `npm run smoke -- 07` must run with the default 4199 —
  `OAUTH_CALLBACK_PORT=4197` makes Keycloak answer "Invalid parameter: redirect_uri". Parallel
  agents/smoke runs must therefore serialize on 4199 (wait and retry on `EADDRINUSE`).
* **Shared-realm side effects**: `ex:07:revoke -- alice` and this example's Keycloak-backed tests
  call `adminLogoutUser('alice'|'bob')`, which ends *all* of that user's sessions realm-wide —
  refresh tokens held by other examples' clients die too. Harmless for JWT-validating examples
  until their access token expires (15 min), but a concurrent run of another example may be
  forced through a fresh browser login. Run smoke examples sequentially (the framework already
  does).
* `client.ts` is ~75 lines, above the ~40-line convention: the raw probe and `--revoke` polling
  are the demonstration and would only be obscured by moving them elsewhere.
