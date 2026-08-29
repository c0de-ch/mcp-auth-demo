# 09 — Auth gateway / sidecar (signed identity assertion)

A **gateway** validates Keycloak tokens and serves the Protected Resource Metadata (it is the
conformant OAuth 2.1 resource server), then reverse-proxies each request to an **internal** MCP
server that has no idea what OAuth is. The bearer token stops at the gateway; the backend trusts
only a short-lived **HS256 identity assertion** the gateway signs. The trust boundary is the point.

```
client ──Bearer (Keycloak)──▶ gateway :4109 ──X-Gateway-Assertion (HS256)──▶ internal :4119
                                validate token, serve PRM,                    verify assertion,
                                strip inbound identity headers                 run the MCP tools
```

Full explanation, sequence diagram, threat model and off-the-shelf alternatives (Envoy `ext_authz`,
Traefik `forwardAuth`, oauth2-proxy, NGINX `auth_request`, Kong): [`docs/09-auth-gateway.md`](../../docs/09-auth-gateway.md).

## Files

| File | Role |
|---|---|
| `gateway.ts` | public resource server (4109): PRM + Keycloak token verify + signing reverse proxy |
| `server.ts` | internal MCP server (4119): trusts the gateway assertion, not a token |
| `assertion.ts` | the HS256 identity assertion — sign (gateway) + verify with a jti replay cache (internal) |
| `all.ts` | run both listeners in one process (`ex:09:all`) |
| `client.ts` | example 04's OAuth client, pointed at the gateway (the client can't tell the difference) |
| `server.test.ts` | the §6.9 negative matrix (hermetic + one Keycloak-backed case) |

## Run it

```bash
# one process (gateway + internal):
npm run ex:09:all
# …or split, to see two deployments:
npm run ex:09:server                 # internal MCP server on 4119 (401s any direct client)
npm run ex:09:gateway                # gateway on 4109 (needs Keycloak: npm run kc:up)

# client (headless login as alice, pre-registered public client):
MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password" \
  OAUTH_CLIENT_ID=mcp-cli OAUTH_CALLBACK_PORT=4189 npm run ex:09:client
# or point it at another machine:  npm run ex:09:client -- http://192.168.78.87:4109/mcp
```

`whoami` returns `extra.via: "gateway"` and the `sub` the gateway asserted — proof the request
crossed the boundary. Ports: `PORT_09` (4109), `PORT_09_INTERNAL` (4119). Env: `GATEWAY_INTERNAL_SECRET`
(the HS256 assertion secret — DEMO), `INTERNAL_TRUST_MODE` (`assertion` default | `network`).

## Observe it

```bash
curl -s http://192.168.78.87:4109/.well-known/oauth-protected-resource/mcp
# {"resource":"http://192.168.78.87:4109/mcp","authorization_servers":["http://192.168.78.87:8180/realms/mcp"],…}

# no token → 401 at the gateway, pointing at the PRM (no scope= — the verifier owns the scope check):
curl -si -X POST http://192.168.78.87:4109/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' | grep -i www-authenticate
# WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="http://192.168.78.87:4109/.well-known/oauth-protected-resource/mcp"

# direct to the internal port with a forged identity header and no assertion → 401, NO PRM:
curl -si -X POST http://192.168.78.87:4119/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H 'X-Forwarded-User: bob' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{…}}'
# HTTP/1.1 401 Unauthorized
# {"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized: gateway assertion required"},"id":null}
```

## Break it

`npx vitest run examples/09-auth-gateway` covers every §6.9 row: no token → 401 (PRM), wrong
audience → 401, missing scope → 403; and directly against the internal server: forged assertion
(wrong secret) → 401, expired → 401, wrong audience/issuer → 401, replayed `jti` → 401, plain
`X-Forwarded-User` without an assertion → 401. It also asserts the gateway strips the caller's
`Authorization` / `X-Forwarded-*` / inbound `X-Gateway-Assertion`, streams an SSE GET and DELETE
through with the session id preserved, and — the documented attack — that `INTERNAL_TRUST_MODE=network`
accepts a forged `X-Forwarded-User` header (admin included).

## Integration notes

- **No shared changes needed.** The example uses `createApp` / `mountMcp` / `listen`,
  `mountProtectedResourceMetadata`, `discoverKeycloak` / `createJwtVerifier` and `jose` (already a
  dependency) exactly as they are.
- **`listen({ host })` is used for the network-mode 127.0.0.1 bind.** `src/shared/http.ts`'s
  `listen()` already accepts `host` (its doc comment names example 09), so the internal server binds
  `127.0.0.1` in `INTERNAL_TRUST_MODE=network` and `0.0.0.0` otherwise via the shared helper — no
  private `http.createServer` was required despite the task brief's note.
- **Gateway → internal hop is loopback** (`http://127.0.0.1:4119/mcp`, overridable via
  `GATEWAY_INTERNAL_URL`): a sidecar talks to its co-located backend over loopback. The internal
  server still binds `0.0.0.0` in assertion mode so the smoke's direct-to-4119 probe (from
  `PUBLIC_HOST`) reaches it and gets its 401.
- **Streaming fix worth knowing:** the hand-rolled proxy calls `res.flushHeaders()` after
  `writeHead` so an SSE stream's `200 text/event-stream` head reaches the client immediately instead
  of waiting ~15 s for the first keep-alive byte (Node otherwise defers framing once
  `transfer-encoding` is stripped). This is inside the example only.
