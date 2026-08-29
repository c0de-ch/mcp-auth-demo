# 04 — Keycloak as the authorization server, MCP as a pure resource server

**Directory:** `examples/04-keycloak-resource-server` · **Port:** 4104 · **Authorization server:**
Keycloak (realm `mcp`, issuer `http://<PUBLIC_HOST>:8180/realms/mcp`) · **Keycloak:** yes ·
**Spec grade:** **CONFORMANT** on the MCP side — RFC 9728 Protected Resource Metadata,
`WWW-Authenticate` with `resource_metadata`, RFC 8414/OIDC AS discovery, RFC 7591 Dynamic Client
Registration, PKCE S256, RFC 8707 `resource` sent, SEP-835 scope selection; **PARTIAL** overall —
Keycloak *ignores* the `resource` parameter (`aud` stays the logical `mcp-server`), and this demo
runs the whole flow over plain HTTP, which the spec forbids outside a lab.

This is the architecture the MCP authorization spec recommends: the MCP server is **only** a
resource server. It answers exactly two auth questions — *"where do tokens come from?"* (one
static metadata document) and *"is this token valid for me?"* (offline JWT verification against
the realm's JWKS). It never sees a password, never issues or stores a token, holds no client
secrets, and adds two small pieces on top of the [baseline server](00-baseline-no-auth.md): a PRM
route and a bearer-token middleware. Everything interactive — login page, consent, MFA, session
management, client registration — is Keycloak's problem, which is precisely the point.

## When to use it

* You have (or want) a real IdP: central users/groups, SSO, MFA, consent, token lifetimes,
  audit — and the MCP server should stay a stateless verifier that scales horizontally.
* Off-the-shelf MCP clients must connect with **zero prior setup**: the 401 → PRM → discovery →
  DCR chain lets the SDK client bootstrap itself from nothing but the server URL.
* You want per-request authorization decisions derived from token claims (scopes, roles) rather
  than from network position or shared secrets.

**When not:** no IdP and no appetite for one — use an [API key](01-api-key.md) (01) or
[self-issued JWTs](02-jwt-local.md) (02); the MCP server itself must be the AS —
[embedded AS](03-oauth-embedded-as.md) (03); machine-to-machine only —
[client credentials](05-keycloak-client-credentials.md) (05); the IdP cannot be reconfigured and
clients must not see it — [OAuth facade](06-oauth-proxy-keycloak.md) (06); revocation must be
visible in seconds — [introspection](07-token-introspection.md) (07), because a JWT verifier
accepts a revoked token until `exp` (see the threat model below).

## The happy path

```mermaid
sequenceDiagram
    autonumber
    participant B as Browser (user)
    participant C as MCP client (CLI)
    participant RS as MCP server :4104 (resource server)
    participant AS as Keycloak :8180 (authorization server)

    C->>RS: POST /mcp (initialize, no token)
    RS-->>C: 401 WWW-Authenticate: Bearer …<br/>resource_metadata="…/.well-known/oauth-protected-resource/mcp"
    C->>RS: GET /.well-known/oauth-protected-resource/mcp
    RS-->>C: { resource, authorization_servers:[issuer],<br/>scopes_supported:[mcp:tools, mcp:admin] }
    C->>AS: GET /.well-known/oauth-authorization-server/realms/mcp
    AS-->>C: AS metadata (endpoints, PKCE S256, registration_endpoint)
    C->>AS: POST /clients-registrations/openid-connect (RFC 7591 DCR)
    AS-->>C: 201 { client_id: <uuid>, token_endpoint_auth_method: none }
    C->>B: open authorization URL (PKCE S256, state,<br/>scope=mcp:tools mcp:admin, resource=http://…:4104/mcp)
    B->>AS: login alice/password → consent
    AS-->>B: 302 http://127.0.0.1:4199/callback?code=…&state=…
    B->>C: loopback listener receives the code (state checked)
    C->>AS: POST /token (code + code_verifier + resource)
    AS-->>C: { access_token (RS256, aud=mcp-server), refresh_token }
    C->>RS: POST /mcp (initialize, Authorization: Bearer …)
    Note over RS: verify signature via realm JWKS,<br/>iss, aud, exp, scope ⊇ [mcp:tools],<br/>mcp:admin only with realm role mcp-admin
    RS-->>C: 200 + mcp-session-id → tools work
```

## How the code does it

The server is the baseline plus ~25 auth lines
([`server.ts`](../examples/04-keycloak-resource-server/server.ts)):

```ts
export async function buildApp(overrides: Overrides = {}): Promise<Express> {
  // The real server discovers the realm once at startup; tests inject { issuer, jwks } and stay offline.
  const metadata = overrides.metadata ?? (overrides.issuer ? offlineMetadata(overrides.issuer) : await discoverKeycloak());
  const resourceUrl = publicUrl(PORT); // canonical — must equal what clients dial AND the PRM `resource`
  const app = createApp();

  // RFC 9728: the ONLY metadata a pure resource server serves. No
  // /.well-known/oauth-authorization-server mirror — that document belongs to the issuer's origin.
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [metadata.issuer],
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN], // SEP-835: this is what DCR clients will request
    resourceName: '04-keycloak-resource-server',
  });

  // issuer + JWKS from discovery, audience `mcp-server`, required scope enforced HERE (403),
  // effective scopes = token scopes minus mcp:admin unless the user has the mcp-admin realm role.
  const verifier = await createKeycloakVerifier({
    metadata,
    requiredScopes: [SCOPE_TOOLS],
    audience: overrides.audience,
    jwks: overrides.jwks,
  });

  mountMcp(app, {
    createServer: () => createDemoServer({ name: '04-keycloak-resource-server' }),
    // Deliberately NO requiredScopes here (SEP-835, see below): the 401/403 carry
    // resource_metadata but no scope=, so clients follow the PRM's scopes_supported.
    auth: requireBearerAuth({ verifier, resourceMetadataUrl }),
  });
  return app;
}
```

Three decisions worth copying:

* **`metadataHandler` only, never `mcpAuthMetadataRouter`** — the SDK's convenience router also
  mirrors the AS document at `<rs-origin>/.well-known/oauth-authorization-server`, which RFC 8414
  reserves for the issuer's origin; the SDK client never needs the mirror (it follows the PRM's
  `authorization_servers`). See `src/shared/prm.ts`.
* **One canonical URL.** `publicUrl(PORT)` produces `http://<PUBLIC_HOST>:4104/mcp` and that exact
  string is the PRM `resource`, the URL clients dial, and the `resource=` the client sends. The
  SDK client hard-fails discovery when these disagree ([sdk-notes](sdk-notes.md)).
* **Verifier errors are the contract.** `createJwtVerifier` throws only `InvalidTokenError` (→ 401
  + header) / `InsufficientScopeError` (→ 403 + header) with **static** messages, and a JWKS
  outage becomes `ServerError` (→ 500 *without* `WWW-Authenticate`) so clients do not start
  re-authorizing because the IdP is down.

The client ([`client.ts`](../examples/04-keycloak-resource-server/client.ts)) is
`CliOAuthProvider` + `connectWithOAuth()` from `src/shared/client/oauth-cli.ts`: the SDK performs
discovery, DCR, PKCE and the token exchange; the provider persists tokens/registration under
`.mcp-auth/` (mode 0600) and runs the loopback callback listener.

`whoami` then reports (real output, alice through a dynamically registered client):

```json
{
  "clientId": "57e6904a-daa1-4b9f-a77a-7a1b025b721f",
  "scopes": ["mcp:tools"],
  "expiresAt": 1787993915,
  "extra": {
    "sub": "0c04e3c8-dc79-4428-b649-a224a21be629",
    "username": "alice",
    "roles": ["mcp-user"],
    "claims": { "iss": "http://192.168.78.87:8180/realms/mcp", "aud": "mcp-server",
                "azp": "57e6904a-daa1-4b9f-a77a-7a1b025b721f", "scope": "mcp:tools",
                "preferred_username": "alice", "realm_access": { "roles": ["mcp-user"] }, "…": "…" }
  }
}
```

`clientId` is the DCR uuid (`azp`), `scopes` are the *effective* scopes the tools consult, and
`extra.claims.aud` is the logical audience — not the URL, because Keycloak ignored the `resource`
parameter (below).

## Run it

```bash
npm run kc:up          # once; kc:status prints the issuer
npm run ex:04:server   # terminal 1
npm run ex:04:client   # terminal 2 — browser opens: alice/password (or bob/password), consent
```

First run: DCR + browser + consent → `RESULT {"example":"04",…,"adminOnly":"denied"}`, exit 0.
Second run: stored tokens (refreshed when expired) — no browser, no callback listener. `--logout`
wipes the store. `OAUTH_CLIENT_ID=mcp-cli` switches to the pre-registered public client (no DCR,
no consent screen; callback port must stay 4199 — the only one registered in the realm). Bob:
`OAUTH_CLIENT_ID=mcp-cli EXPECT_ADMIN=ok npm run ex:04:client` → `adminOnly=ok`.

LAN: run the client anywhere (`npm run ex:04:client -- http://192.168.78.87:4104/mcp`); if the
*browser* lives on another machine than the client, set `OAUTH_REDIRECT_HOST=<client's LAN IP>`
so the redirect URI is reachable — the realm has `http://<PUBLIC_HOST>:4199/callback` registered
for exactly this (see [lan-testing](lan-testing.md)).

## The wire: one complete authorization, as captured

Everything below is a real capture from the dev box (a logging `fetch` inside the SDK transport;
tokens and one-time codes truncated). This is the 2025-06-18/2025-11-25 MCP authorization flow as
implemented by SDK 1.30.0 — compare [spec-background](spec-background.md).

**1 — the client tries without credentials; the 401 names the PRM (and no `scope` — SEP-835):**

```http
POST http://192.168.78.87:4104/mcp
accept: application/json, text/event-stream
content-type: application/json
{"method":"initialize","params":{…},"jsonrpc":"2.0","id":0}

HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header",
  resource_metadata="http://192.168.78.87:4104/.well-known/oauth-protected-resource/mcp"
```

**2 — RFC 9728 Protected Resource Metadata (this server's only metadata):**

```http
GET http://192.168.78.87:4104/.well-known/oauth-protected-resource/mcp
mcp-protocol-version: 2025-11-25

HTTP/1.1 200 OK
access-control-allow-origin: *
{"resource":"http://192.168.78.87:4104/mcp",
 "authorization_servers":["http://192.168.78.87:8180/realms/mcp"],
 "scopes_supported":["mcp:tools","mcp:admin"],
 "resource_name":"04-keycloak-resource-server",
 "bearer_methods_supported":["header"]}
```

**3 — AS metadata.** The issuer has a path (`/realms/mcp`), so the SDK probes
`/.well-known/oauth-authorization-server/realms/mcp` first — Keycloak 26 answers **200** on the
first try (it also serves the OIDC document at `/realms/mcp/.well-known/openid-configuration`):

```http
GET http://192.168.78.87:8180/.well-known/oauth-authorization-server/realms/mcp
accept: application/json
mcp-protocol-version: 2025-11-25

HTTP/1.1 200 OK
{"issuer":"http://192.168.78.87:8180/realms/mcp",
 "authorization_endpoint":"…/realms/mcp/protocol/openid-connect/auth",
 "token_endpoint":"…/realms/mcp/protocol/openid-connect/token",
 "jwks_uri":"…/realms/mcp/protocol/openid-connect/certs",
 "registration_endpoint":"…/realms/mcp/clients-registrations/openid-connect",
 "code_challenge_methods_supported":["plain","S256"], …6.5 KB total}
```

**4 — RFC 7591 Dynamic Client Registration** (anonymous — the realm's DCR policies allow scopes
`mcp:tools mcp:admin offline_access`, force consent, and cap registrations at 200; `openid` would
be rejected):

```http
POST http://192.168.78.87:8180/realms/mcp/clients-registrations/openid-connect
content-type: application/json
{"client_name":"mcp-auth-demo cli","redirect_uris":["http://127.0.0.1:4199/callback"],
 "grant_types":["authorization_code","refresh_token"],"response_types":["code"],
 "token_endpoint_auth_method":"none","scope":"mcp:tools mcp:admin"}

HTTP/1.1 201 Created
{"client_id":"a2492632-48bc-404c-9487-72b2498bb7af","token_endpoint_auth_method":"none",
 "registration_client_uri":"…/clients-registrations/openid-connect/a2492632-…",
 "registration_access_token":"<one per client — manage/delete the registration>", …}
```

Note the requested `scope` is `mcp:tools mcp:admin` — taken from the PRM, not from any client
configuration (SEP-835, next section).

**5 — the authorization request** (printed by the client, opened in the browser; PKCE + `state`
+ `resource`):

```
http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/auth?response_type=code
  &client_id=57e6904a-daa1-4b9f-a77a-7a1b025b721f
  &code_challenge=YcKrKbNwkmI_9ExsPw3Jh8jPhYYGUudoZZYDIMatduU&code_challenge_method=S256
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A4199%2Fcallback
  &state=baabcc774faf0865ab19aca06e4c2e89
  &scope=mcp%3Atools+mcp%3Aadmin
  &resource=http%3A%2F%2F192.168.78.87%3A4104%2Fmcp
```

The user logs in (`alice` / `password`), approves the consent screen ("Use MCP tools on your
behalf"), and Keycloak redirects to `http://127.0.0.1:4199/callback?code=…&state=…`. The client's
loopback listener (started *before* the browser opened) checks `state` and hands the code back.

**6 — RFC 8707 in, Keycloak shrugs: the code → token exchange.** The client dutifully repeats
`resource=`; Keycloak ignores it and binds the audience via the realm's scope mappers instead:

```http
POST http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token
content-type: application/x-www-form-urlencoded
grant_type=authorization_code&code=3e13931b-0b8…&code_verifier=4OcNPk911pW.…
  &redirect_uri=http%3A%2F%2F127.0.0.1%3A4199%2Fcallback
  &resource=http%3A%2F%2F192.168.78.87%3A4104%2Fmcp
  &client_id=57e6904a-daa1-4b9f-a77a-7a1b025b721f

HTTP/1.1 200 OK
{"access_token":"eyJhbGciOiJSUzI1NiIs…(987 chars)","expires_in":900,
 "refresh_token":"eyJhbGciOiJIUzUxMiIs…","token_type":"Bearer","scope":"mcp:tools"}
```

The access token's payload: `iss=http://192.168.78.87:8180/realms/mcp`, **`aud="mcp-server"`**
(from the `mcp:tools` scope's audience mapper — *not* the requested resource URL), `azp=<DCR
uuid>`, `scope="mcp:tools"`, `preferred_username=alice`, `realm_access.roles=["mcp-user"]`. This
is the PARTIAL in the spec grade: a strict RFC 8707 deployment would mint `aud=
http://192.168.78.87:4104/mcp` per resource; with one logical audience, every MCP example of this
repo shares one token audience (and `MCP_AUDIENCE` lets a deployment accept URL audiences instead
— see [patterns](patterns.md) for strict resource indicators on other IdPs).

**7 — the retry, now authenticated; a session is born:**

```http
POST http://192.168.78.87:4104/mcp
accept: application/json, text/event-stream
authorization: Bearer eyJhbGciOiJSUzI1NiIs…(987 chars)
content-type: application/json
{"method":"initialize", …}

HTTP/1.1 200 OK
content-type: text/event-stream
mcp-session-id: 0fed2c8a-83c2-4d26-b85f-5d0fb777a5fd
```

Every later request carries the Bearer token *and* `mcp-session-id` (the middleware re-verifies
the token on each request; the session is additionally bound to alice's `sub`). A second client
run skips all of the above — stored tokens, silent refresh at the token endpoint when expired, no
browser, no listener.

## Observe it with curl

Streamable HTTP is strict: a POST needs `Accept: application/json, text/event-stream` **and**
`Content-Type: application/json`, or you get 406/415 before auth even runs.

```bash
BASE=http://192.168.78.87:4104
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'

curl -si -X POST $BASE/mcp -H 'Accept: application/json, text/event-stream' \
     -H 'Content-Type: application/json' -d "$INIT"          # → the 401 of step 1, verbatim
curl -s $BASE/.well-known/oauth-protected-resource/mcp | jq  # → the PRM of step 2
curl -s -o /dev/null -w '%{http_code}\n' \
     $BASE/.well-known/oauth-authorization-server            # → 404: a pure RS mirrors nothing

# A real user token without a browser (mcp-test is a TEST-ONLY password-grant client):
TOKEN=$(curl -s -X POST http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=mcp-test&username=alice&password=password&scope=mcp:tools' \
  | jq -r .access_token)
curl -si -X POST $BASE/mcp -H 'Accept: application/json, text/event-stream' \
     -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d "$INIT" \
  | grep -i mcp-session-id                                   # → a session id: you are in
```

## SEP-835: who decides which scopes the client asks for

The SDK client resolves the scope for **both** DCR and the authorization request in this order:

1. `scope="…"` from the 401's `WWW-Authenticate`, if present;
2. else the PRM's `scopes_supported`, joined;
3. else the provider's `clientMetadata.scope`.

That order is why this server wires the required scope into the **verifier** and *not* into
`requireBearerAuth({ requiredScopes })`: the middleware would copy its list into every 401/403 as
`scope="mcp:tools"`, every client would request exactly `mcp:tools` — and bob could never obtain
`mcp:admin` through the browser flow (the SDK's one-shot 403 upscoping is a different, narrower
path). With no `scope=` on the challenge, rule 2 applies and the PRM drives the request:
`scope=mcp:tools mcp:admin` — visible in steps 4 and 5 of the trace above.

Both users therefore *ask* for `mcp:admin`. Who gets it is decided twice:

* **At issuance (Keycloak):** the `mcp:admin` client scope carries a role scope mapping to the
  realm role `mcp-admin`. bob holds it → his token has `scope="… mcp:admin"` and
  `realm_access.roles=[…, "mcp-admin"]`. alice does not → Keycloak silently leaves `mcp:admin`
  out of her token. **Scope = what the client was granted; role = what the user may do.**
* **At verification (this server):** `keycloakEffectiveScopes()` recomputes the effective list and
  drops `mcp:admin` from any token whose `realm_access.roles` lacks `mcp-admin` — defence in
  depth, proven in the hermetic tests with a locally minted token that *does* carry the scope
  without the role. A resource server should enforce its own scope/role agreement rather than
  trust AS configuration it does not control.

The tools then consult exactly one thing, `authInfo.scopes` — so `admin_only` is a tool-level
`isError` for alice and a success for bob, with the identical server code.

A subtlety for CLI authors: the scope-selection rules mean a resource server can *steer* clients
via its PRM. Advertise only `mcp:tools` and even admins get user-level tokens; advertise
`offline_access` and the SDK adds `prompt=consent` to every authorization request.

## Break it

Each of these is a vitest case in
[`server.test.ts`](../examples/04-keycloak-resource-server/server.test.ts) (hermetic rows run
against an injected TEST-NET issuer + local JWKS — no Keycloak needed); the responses below are
real captures.

| Attack / mistake | Response |
|---|---|
| no token | `401` + `WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header", resource_metadata="…"` |
| `Authorization: Bearer garbage` | `401 … error_description="JWT rejected: ERR_JWS_INVALID"` |
| tampered token (claims upgraded to admin, signature kept) | `401 … "JWT rejected: bad signature"` |
| token minted by another issuer | `401 … "JWT rejected: wrong issuer"` |
| `aud: ["account"]` (a Keycloak token for a different audience) | `401 … "JWT rejected: wrong audience"` |
| expired token | `401 … "JWT rejected: token expired"` |
| valid token without `mcp:tools` | `403` + `WWW-Authenticate: Bearer error="insufficient_scope", error_description="missing scope: mcp:tools"` (static; no `scope=` param — hermetic only, because `mcp:tools` is a default client scope every realm token for this audience carries) |
| alice calls `admin_only` | `200`, but the tool returns `isError`: `insufficient_scope: admin_only requires scope mcp:admin` |
| bob's token on alice's `mcp-session-id` | `403 {"error":{"code":-32000,"message":"Forbidden: session belongs to a different principal"}}` |
| `GET /.well-known/oauth-authorization-server` on :4104 | `404` — a pure RS never impersonates its AS |
| Keycloak down mid-flight, JWKS unreachable | `500` (no `WWW-Authenticate`) — deliberately *not* a 401, so clients do not loop through re-authorization while the IdP is out |

Tamper reproduction (third row):

```bash
H=$(cut -d. -f1 <<<"$TOKEN"); S=$(cut -d. -f3 <<<"$TOKEN")
P=$(cut -d. -f2 <<<"$TOKEN" | base64 -d 2>/dev/null \
  | jq -c '.scope="mcp:tools mcp:admin" | .realm_access.roles=["mcp-user","mcp-admin"]' \
  | base64 -w0 | tr '+/' '-_' | tr -d '=')
curl -si -X POST $BASE/mcp -H 'Accept: application/json, text/event-stream' \
  -H 'Content-Type: application/json' -H "Authorization: Bearer $H.$P.$S" -d "$INIT" | head -2
# HTTP/1.1 401 Unauthorized
# WWW-Authenticate: Bearer error="invalid_token", error_description="JWT rejected: bad signature", resource_metadata="…"
```

## Threat model notes

**What this pattern gives you**

* **Audience binding.** `aud` must contain `mcp-server`: tokens minted for other audiences (the
  `downstream-api` tokens of [example 10](10-token-exchange-downstream.md), plain `account`
  tokens, other realms) are rejected with `wrong audience`. A leaked MCP token is likewise
  useless at APIs that check *their* audience. One logical audience is coarser than per-URL
  RFC 8707 audiences — all MCP examples in this repo share it — which is exactly the trade
  documented in [patterns](patterns.md) ("strict resource indicators").
* **Issuer pinning.** `iss` is compared against one configured string; `KC_HOSTNAME` pins what
  Keycloak writes, `env.ts` derives the identical value, and the compose file makes them agree
  from every LAN machine. A look-alike IdP or a second realm cannot mint acceptable tokens.
* **Offline verification with rotation.** `createRemoteJWKSet` caches the realm's keys and
  re-fetches on an unknown `kid`, so Keycloak key rotation is picked up without restarts; a JWKS
  outage degrades to 500s, never to "anyone gets in" or to client re-auth storms.
* **No secrets on the RS.** Nothing to steal from the MCP server but its own availability: no
  client secrets, no password hashes, no signing keys (contrast 03, which holds all three).
* **Session ≠ authentication.** Every request re-verifies the token *and* the session is bound to
  the initializing subject: an observed `mcp-session-id` is worthless without that user's valid
  token (the 403 above), and GET/DELETE sit behind the same middleware as POST.
* **Header-injection hygiene.** Everything interpolated into `WWW-Authenticate` is a static
  string — `jose` error text (which quotes attacker-controlled token headers) never reaches it.

**What it does not give you**

* **Revocation latency.** Signature validation cannot see revocation: after `kc:down`-style
  session kills or `revokeToken()`, a stolen access token keeps working until `exp` (15 min in
  this realm; Keycloak's default is 60 s). If minutes matter, validate statefully —
  [example 07](07-token-introspection.md) shows RFC 7662 introspection with a TTL cache and the
  same realm, and demonstrates the revocation becoming visible immediately.
* **Transport security.** Plain HTTP means bearer tokens, codes and passwords cross the LAN in
  cleartext, and the spec's HTTPS requirements are waived via
  `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL`. Lab only; [lan-testing](lan-testing.md) sketches
  the TLS upgrade path.
* **Sender constraining.** A bearer token is a bearer token: anyone holding it is alice. DPoP
  (RFC 9449) and mTLS-bound tokens (RFC 8705) are documented in [patterns](patterns.md);
  [example 08](08-mtls.md) shows the transport-level variant.
* **Open DCR.** Anonymous registration is deliberately open here (consent required, allowed
  scopes capped, `max-clients` 200). Registration does not grant access — a registered client
  still needs a user to log in and consent — but production realms should re-enable the Trusted
  Hosts policy ([keycloak.md](keycloak.md) has the hardened variant).

## Variations

* **Pre-registered client** (`OAUTH_CLIENT_ID=mcp-cli`): no DCR, no consent (the realm client is
  trusted), fixed redirect URIs — the usual shape for a first-party CLI. An
  `OAUTH_CLIENT_SECRET` would make it a confidential client; the realm's `mcp-cli` is public
  (PKCE only), which OAuth 2.1 considers the right default for native apps.
* **Other IdPs.** Everything here is plain OAuth: point `KEYCLOAK_URL`/`MCP_AUDIENCE` (and the
  PRM's `authorization_servers`) at any issuer whose JWTs carry your audience. Auth0 (`audience`
  parameter), Entra ID (app-ID URI audiences), Okta and the per-IdP DCR/discovery quirks are
  compared in [keycloak.md](keycloak.md).
* **Same pattern, other stacks:** [example 11](11-python-mcp-keycloak.md) is this exact server in
  Python (official `mcp` SDK, identical PRM shape, same realm); [example 05](05-keycloak-client-credentials.md)
  swaps the browser for `client_credentials`; [example 09](09-auth-gateway.md) moves the verifier
  into a gateway in front of an unmodified server.
* **What the SDK quietly does for you** — discovery order and fallbacks, the 401-vs-403 retry
  rules, one-shot upscoping, refresh semantics, `resource` propagation — is catalogued with file
  references in [sdk-notes.md](sdk-notes.md).
