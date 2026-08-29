# 05 — Keycloak client credentials (machine-to-machine)

The server is example 04's pure resource server (diff `server.ts` against
`../04-keycloak-resource-server/server.ts`) plus one tool, `service_only`, that authorizes on the
**client identity** (`azp` allow-list) instead of scopes or roles. The client is a workload: no
browser, no redirect, no user — `ClientCredentialsProvider` (shared secret, `client_secret_basic`)
or `PrivateKeyJwtProvider` (RFC 7523 signed assertion) fetch the token straight from Keycloak's
token endpoint. Full walk-through: [`docs/05-keycloak-client-credentials.md`](../../docs/05-keycloak-client-credentials.md).

## Run it

```bash
npm run kc:up                                   # once — Keycloak + realm mcp (+ kc:keys for the jwt client)
npm run ex:05:server                            # terminal 1 — http://<PUBLIC_HOST>:4105/mcp
npm run ex:05:client                            # terminal 2 — mcp-service, client_secret_basic
npm run ex:05:client -- --auth private-key-jwt  #            — mcp-service-jwt, signed JWT assertion
npm run ex:05:client -- http://192.168.78.87:4105/mcp   # from another LAN machine (or MCP_SERVER_URL)
```

Expected: `whoami.clientId` = `mcp-service` (or `mcp-service-jwt`), roles `[mcp-user]`,
`admin_only` denied, `service_only` ok, and the last line
`RESULT {"example":"05",…,"adminOnly":"denied","extra":{"auth":"…","serviceOnly":"ok"}}`.

## Verify / break it

```bash
npx vitest run examples/05-keycloak-client-credentials    # hermetic + Keycloak-backed matrix
npm run smoke -- 05                                       # end-to-end on the real port

# 401 challenge without a token (the discovery entry point):
curl -si -X POST http://192.168.78.87:4105/mcp -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}' | head -3

# wrong secret → Keycloak answers 401 unauthorized_client (auth() rejects with UnauthorizedClientError):
curl -si -u mcp-service:wrong -d 'grant_type=client_credentials&scope=mcp:tools' \
  http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token | head -1
```

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT_05` / `MCP_PORT` | `4105` | server port |
| `MCP_SERVICE_CLIENT_SECRET` | `mcp-service-secret-demo` (DEMO) | secret of Keycloak client `mcp-service` |
| `MCP_ALLOWED_CLIENTS` | `mcp-service,mcp-service-jwt` | client ids (`azp`) allowed to call `service_only` |
| `MCP_AUDIENCE` | `mcp-server` | accepted `aud` values (comma list) |
| `MCP_SERVER_URL` / argv | `http://<PUBLIC_HOST>:4105/mcp` | URL the client dials |

The `--auth private-key-jwt` variant needs `keycloak/.generated/mcp-service-jwt.key`
(`npm run kc:keys`, run automatically by `kc:up`); its test is skipped when the key is absent.

## Integration notes

* **Live-realm deviations from design §6.5** (tests assert the live behaviour, deviations
  commented in `server.test.ts`):
  1. Service-account tokens DO carry `preferred_username` (`service-account-mcp-service`) because
     the realm's `mcp:tools` scope has a username mapper — `whoami.extra.username` is not
     `undefined` as §6.5 predicted.
  2. Wrong secret → Keycloak 26.7.2 answers `unauthorized_client` (SDK: **UnauthorizedClientError**),
     not `invalid_client`; an **unknown** client id yields `invalid_client`/InvalidClientError.
     Both classes are asserted in separate tests.
  3. Requesting `scope=mcp:tools mcp:admin` as `mcp-service`: Keycloak filters `mcp:admin` out of
     the `scope` claim **at issuance** (role scope mapping `mcp:admin → mcp-admin`, the service
     account lacks the role) — the token never contains it, `admin_only` denied either way. This
     also makes design §6.4/§7.2's "alice's token contains `mcp:admin` in scope" stale (verified:
     alice does not get it, bob does) — relevant for example 04's docs.
* `--auth private-key-jwt` is implemented for real (the realm import of `mcp-service-jwt` works;
  grant verified end-to-end), not docs-only as design §2 hedged.
* `buildApp` overrides include `resourceUrl` (tests must advertise the ephemeral `127.0.0.1` URL
  in the PRM, or the SDK client's RFC 8707 resource check rejects it) and `allowedClients`.
* `MCP_ALLOWED_CLIENTS` is a new (05-only) env knob; `.env.example` is frozen — integrator may
  want to add it under "Example-specific".
* Suggested smoke additions for the 05 row (scripts/smoke.ts is frozen): assert
  `extra.serviceOnly === 'ok'`, and a stretch step `{ args: ['--auth', 'private-key-jwt'], expect: clientId mcp-service-jwt }`.
