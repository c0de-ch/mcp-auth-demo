# 05 — Machine-to-machine: Keycloak `client_credentials`

**Directory:** `examples/05-keycloak-client-credentials` · **Port:** 4105 · **Authorization server:** Keycloak (realm `mcp`) · **Keycloak:** yes
**Spec grade:** **CONFORMANT** — MCP authorization (2025-06-18 → 2025-11-25) on the resource-server side: RFC 9728 Protected Resource Metadata, `WWW-Authenticate … resource_metadata`, RFC 8414/OIDC discovery, Bearer tokens per RFC 6750; the grant itself is OAuth 2.1 client credentials (RFC 6749 §4.4) with `client_secret_basic` or `private_key_jwt` (RFC 7523 §2.2) client authentication. *PARTIAL* in the same way as example 04: Keycloak ignores the RFC 8707 `resource` parameter the SDK sends (`aud` stays the logical `mcp-server`).

A workload — a cron job, a backend service, another agent — calls an MCP server as **itself**, not
on behalf of a user. There is no browser, no redirect, no consent screen and no refresh token:
the client authenticates to Keycloak's token endpoint directly and gets a short-lived access token
for a **service account**. The server is byte-for-byte example 04's pure resource server
(`git diff` the two `server.ts` files) — which is the point: *a resource server verifies tokens,
it neither knows nor cares which grant minted them.* The one addition is a `service_only` tool that
authorizes on the **client identity** (`azp` allow-list) — a third axis next to scopes and roles.

## When to use it

* Server-to-server and agent-to-server calls with no human in the loop (schedulers, pipelines,
  monitoring, one backend consuming another team's MCP tools).
* You already run an IdP: the secret/key lives in the IdP and your deployment env, tokens are
  short-lived, revocation = disable the client — far better than a static API key (example 01).
* The caller's identity is *the workload itself* and tools should be gated on that identity.

## When not

* A human's data or permissions are involved → authorization-code + PKCE (example 04) so the token
  carries the *user*; or the on-behalf-of chain (example 10). Client-credentials tokens have no
  user consent behind them — never treat the service account as "any user".
* The SDK's embedded AS (example 03) is the issuer: its `/token` only implements
  `authorization_code`/`refresh_token`; `client_credentials` → `400 unsupported_grant_type`
  ([docs/sdk-notes.md](sdk-notes.md)). M2M needs an external AS.
* You cannot protect a secret/private key at the caller (browser or desktop distribution) — that
  is a public client; use PKCE.

## Happy path

```mermaid
sequenceDiagram
    autonumber
    participant W as Workload (client.ts)
    participant RS as MCP server :4105 (pure RS)
    participant KC as Keycloak :8180 (realm mcp)
    W->>RS: POST /mcp (initialize, no token)
    RS-->>W: 401 · WWW-Authenticate: Bearer resource_metadata="…/.well-known/oauth-protected-resource/mcp"
    W->>RS: GET /.well-known/oauth-protected-resource/mcp
    RS-->>W: { resource, authorization_servers: [realm issuer], scopes_supported }
    W->>KC: GET /.well-known/oauth-authorization-server/realms/mcp
    KC-->>W: AS metadata (token_endpoint, auth methods, grants)
    W->>KC: POST /token · grant_type=client_credentials&scope=mcp:tools<br/>Authorization: Basic mcp-service:secret — or client_assertion=&lt;signed JWT&gt; (RFC 7523)
    KC-->>W: { access_token, expires_in: 900 } — aud=mcp-server, azp=mcp-service, NO refresh_token
    W->>RS: POST /mcp (initialize) · Authorization: Bearer …
    RS->>RS: verify signature (realm JWKS), iss, aud, exp; effective scopes
    RS-->>W: 200 + mcp-session-id
    W->>RS: tools/call · whoami / add ok · admin_only denied · service_only ok
```

The demo client short-circuits the first 401 by calling `auth(provider, { serverUrl })` eagerly —
same discovery chain, but a wrong secret fails *before* `connect()` with a typed error. Left to
itself, the SDK transport performs exactly the diagram: 401 → discovery → grant → replay.

## How the code does it

**Server** (`examples/05-keycloak-client-credentials/server.ts`) — the auth wiring is example 04's,
see [04-keycloak-resource-server.md](04-keycloak-resource-server.md) for the line-by-line story:

```ts
const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
  resourceUrl,                                     // http://<PUBLIC_HOST>:4105/mcp — canonical
  authorizationServers: [metadata.issuer],         // the realm; discovered once at startup
  scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN],     // SEP-835: what discovering clients request
  resourceName: '05-keycloak-client-credentials',
});
const verifier = await createKeycloakVerifier({ metadata, requiredScopes: [SCOPE_TOOLS], … });
mountMcp(app, { createServer, auth: requireBearerAuth({ verifier, resourceMetadataUrl }) });
```

The diff against 04 is the `service_only` tool, registered on the shared demo server:

```ts
server.registerTool('service_only', { … }, async (extra) => {
  const clientId = extra.authInfo?.clientId;        // = the VERIFIED token's azp claim
  return clientId !== undefined && allowed.includes(clientId)   // MCP_ALLOWED_CLIENTS
    ? { content: [{ type: 'text', text: `service ok: client ${clientId} is allow-listed` }] }
    : { isError: true, content: [{ type: 'text', text: `forbidden_client: …` }] };
});
```

Three independent authorization axes now exist, and they do not substitute for each other:

| Axis | Claim | Gate | alice (user) | bob (admin user) | mcp-service |
|---|---|---|---|---|---|
| scope — what the client was granted | `scope` | verifier `requiredScopes` / `admin_only` | `mcp:tools` | `mcp:tools mcp:admin` | `mcp:tools` |
| role — what the user may do | `realm_access.roles` | `keycloakEffectiveScopes()` | denied | **admin ok** | denied |
| client — which workload is calling | `azp` | `service_only` allow-list | denied | denied | **service ok** |

**Client** (`examples/05-keycloak-client-credentials/client.ts`) — the SDK ships both M2M providers
in `@modelcontextprotocol/sdk/client/auth-extensions.js`:

```ts
new ClientCredentialsProvider({ clientId: 'mcp-service',
  clientSecret: env('MCP_SERVICE_CLIENT_SECRET'), scope: 'mcp:tools' })
// --auth private-key-jwt:
new PrivateKeyJwtProvider({ clientId: 'mcp-service-jwt',
  privateKey: readFileSync('keycloak/.generated/mcp-service-jwt.key', 'utf8'),
  algorithm: 'RS256', jwtLifetimeSeconds: 60, scope: 'mcp:tools' })
…
await auth(provider, { serverUrl });               // eager grant — token errors before connect()
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
```

SDK mechanics worth knowing ([docs/sdk-notes.md](sdk-notes.md) has the full list):

* `auth()` goes **non-interactive purely because `provider.redirectUrl` is falsy** — it then calls
  `provider.prepareTokenRequest(provider.clientMetadata.scope)`. The scope you configured on the
  provider is what is requested; the 401 challenge / PRM scopes (SEP-835) are *ignored* for this path.
* Keycloak advertises `client_secret_basic` in `token_endpoint_auth_methods_supported`, so the SDK
  authenticates with HTTP **Basic**; `PrivateKeyJwtProvider` instead sets
  `client_assertion(_type)` via `addClientAuthentication` — signed per request, `aud` = the issuer.
* Tokens live **in memory only** and there is **no refresh token** (`refresh_expires_in: 0` above):
  expiry is discovered on the next 401, which triggers exactly **one** new grant; a second 401
  right after a successful grant throws `StreamableHTTPError 401` (circuit breaker — see Break it).

`whoami` then reports (captured, trimmed — note the identity is a *service account*):

```json
{"clientId":"mcp-service","scopes":["mcp:tools"],
 "extra":{"sub":"47f4afb5-a47f-44e8-804a-644947ff52e0",
          "username":"service-account-mcp-service","roles":["mcp-user"],
          "claims":{"iss":"http://192.168.78.87:8180/realms/mcp","aud":"mcp-server",
                    "azp":"mcp-service","scope":"mcp:tools","typ":"Bearer","…":"…"}}}
```

(Keycloak materializes a hidden user `service-account-<clientId>` per service account; the realm's
`mcp:tools` scope carries a username mapper, so `preferred_username` is present here too.)

## Run it

```bash
npm run kc:up            # once: Keycloak on http://<PUBLIC_HOST>:8180 + realm mcp (+ generates the jwt key pair)
npm run ex:05:server     # terminal 1
npm run ex:05:client     # terminal 2 — add: -- http://192.168.78.87:4105/mcp from another machine
npm run ex:05:client -- --auth private-key-jwt
```

Client output (captured):

```
connecting to http://192.168.78.87:4105/mcp as mcp-service (client_credentials, client-secret-basic)
tools        -> whoami, add, admin_only, service_only
whoami       -> {"clientId":"mcp-service","scopes":["mcp:tools"],…}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
service_only -> service ok: client mcp-service is allow-listed
RESULT {"example":"05",…,"adminOnly":"denied","extra":{"auth":"client-secret-basic","serviceOnly":"ok"}}
```

The `--auth private-key-jwt` run is identical except `clientId":"mcp-service-jwt"` and
`extra.auth: "private-key-jwt"`.

## Observe it

The discovery entry point — a 401 that names the PRM (no `scope=`: SEP-835 wiring, the PRM's
`scopes_supported` drives interactive clients; this M2M client uses its configured scope anyway):

```console
$ curl -si -X POST http://192.168.78.87:4105/mcp \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="http://192.168.78.87:4105/.well-known/oauth-protected-resource/mcp"

$ curl -s http://192.168.78.87:4105/.well-known/oauth-protected-resource/mcp
{"resource":"http://192.168.78.87:4105/mcp","authorization_servers":["http://192.168.78.87:8180/realms/mcp"],
 "scopes_supported":["mcp:tools","mcp:admin"],"resource_name":"05-keycloak-client-credentials","bearer_methods_supported":["header"]}
```

The grant itself — client authentication is HTTP Basic on the **token endpoint** (this is the
whole flow; compare with 04's authorize/consent/callback dance):

```console
$ curl -s -u "mcp-service:$MCP_SERVICE_CLIENT_SECRET" \
    -d 'grant_type=client_credentials&scope=mcp:tools' \
    http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token
{"access_token":"eyJhbGciOiJSUzI1NiIs…","expires_in":900,"refresh_expires_in":0,
 "token_type":"Bearer","not-before-policy":0,"scope":"mcp:tools"}
```

Calling the MCP endpoint with it — POST needs `Accept: application/json, text/event-stream` AND
`Content-Type: application/json` or you get 406/415 before auth is even looked at:

```console
$ curl -si -X POST http://192.168.78.87:4105/mcp -H "Authorization: Bearer $TOKEN" \
    -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' -d "$INIT"
HTTP/1.1 200 OK
content-type: text/event-stream
mcp-session-id: <uuid>

event: message
data: {"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{"listChanged":true}},"serverInfo":{"name":"05-keycloak-client-credentials","version":"0.1.0"}},"jsonrpc":"2.0","id":1}
```

## Break it

Every row is a test in `server.test.ts` (hermetic rows run without Keycloak):

| Attack / mistake | What happens (captured) |
|---|---|
| no token | `401` + `WWW-Authenticate: Bearer error="invalid_token" … resource_metadata="…"` (no `scope=`) |
| garbage/expired/foreign token | `401` `error_description="JWT rejected: <static reason>"` — e.g. `JWT rejected: ERR_JWS_INVALID` |
| wrong secret | Keycloak: `401 {"error":"unauthorized_client","error_description":"Invalid client or Invalid client credentials"}` → `auth()` retries once (SDK invalidates credentials), then rejects with **`UnauthorizedClientError`**; an **unknown** client id yields `invalid_client` → **`InvalidClientError`** |
| token without `mcp:tools` | `403` `error="insufficient_scope", error_description="missing scope: mcp:tools"` (static string, still no `scope=`) |
| service requests `mcp:admin` | Keycloak **withholds the scope at issuance**: the client scope `mcp:admin` maps realm role `mcp-admin`, which `service-account-mcp-service` lacks — the token's `scope` stays `mcp:tools`; `admin_only` denied. (Same policy `keycloakEffectiveScopes()` re-enforces at verification, for IdPs that do not filter.) |
| user token calls `service_only` | tool error `forbidden_client: service_only requires one of: mcp-service, mcp-service-jwt` — alice/bob's `azp` (`mcp-cli`/`mcp-test`) is not allow-listed, whatever their scopes/roles |
| stale cached token | next request 401 → the provider runs **exactly one** new `client_credentials` grant (asserted with a fetch spy) and replays the request |
| grants keep yielding rejected tokens | the transport's **circuit breaker**: after one successful re-grant a second consecutive 401 throws `StreamableHTTPError: … Server returned 401 after successful authentication` — one grant total, the token endpoint is not hammered |
| stolen token replayed at another API | `aud` is pinned to `mcp-server`: example 10's downstream API (aud `downstream-api`) rejects it, and this server rejects exchanged/downstream tokens — audience is the blast-radius limiter |

## Threat model notes

* **The secret is the identity.** `client_secret_basic` sends `base64(id:secret)` on every grant —
  demo-only over plain HTTP; production needs TLS, a secret store (not argv, not the repo, not
  logs — this client reads it from the environment and never prints it), and rotation. Anyone
  holding the secret *is* `mcp-service` until you rotate or disable the client in Keycloak.
* **`private_key_jwt` removes the shared secret.** The private key never travels: Keycloak stores
  only the public key, each grant sends a fresh short-lived signed assertion (60 s here, with
  `jti`), so a captured token request does not yield a reusable long-term credential and the
  key can be rotated via JWKS. This is the recommended M2M client authentication; mTLS (example
  08) is the transport-level sibling.
* **No user, no consent.** The token represents the workload. Do not launder user actions through
  a service account — audit trails collapse onto `service-account-mcp-service`. When a user is
  involved, use example 04 (their token) or example 10 (exchange, acting on-behalf-of).
* **Least privilege by construction:** the service account holds role `mcp-user` only, so even a
  compromised secret cannot reach `admin_only`; `aud=mcp-server` keeps the token useless anywhere
  else; 900 s expiry bounds the replay window (no refresh token to steal).
* **Client identity is verified data:** `service_only` trusts `azp` because the JWT signature,
  `iss` and `aud` were verified first — an allow-list on unverified input would be decoration.

## Variations and links

* **`StaticPrivateKeyJwtProvider`** (same SDK module): a pre-built assertion minted by an external
  signer (HSM, vault) — the process never sees the key.
* **`client_secret_post`** exists for AS's without Basic support; Keycloak supports both, the SDK
  picks Basic per the metadata. Third-party AS quirks: see "client auth" in [docs/sdk-notes.md](sdk-notes.md).
* **Workload identity** (SPIFFE, cloud metadata credentials, Kubernetes service-account JWT
  federation): replaces the static secret with platform-attested identity — `docs/patterns.md`.
* Related examples: [04](04-keycloak-resource-server.md) (same server, human flow) ·
  07 (introspection: revocation without waiting for `exp`) · 08 (mTLS as the credential) ·
  10 (token exchange: service acting for a user).
* Realm details (clients `mcp-service`, `mcp-service-jwt`, scope/role mappings): `keycloak/README.md`.
