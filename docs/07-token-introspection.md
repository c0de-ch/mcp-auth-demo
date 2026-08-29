# 07 — Token introspection (RFC 7662)

**Directory:** `examples/07-token-introspection` · **Port:** 4107 (`PORT_07`) ·
**Authorization server:** Keycloak (`http://<PUBLIC_HOST>:8180/realms/mcp`) · **Keycloak:** yes ·
**Spec grade: CONFORMANT** — OAuth 2.1 resource server with *stateful* token validation: MCP
authorization (2025-06-18 → 2025-11-25) discovery via `WWW-Authenticate` + RFC 9728 Protected
Resource Metadata, token validation per RFC 7662 (introspection), revocation per RFC 7009 and the
Keycloak admin API. The client is exactly example 04's client — from the outside, only the
server's *reaction to revocation* differs.

Example 04 validates tokens **statelessly**: fetch the JWKS once, check the signature and claims
locally. Fast, no runtime dependency on the AS — but a revoked token stays "valid" until `exp`.
This example makes the opposite trade: the server treats the token as an opaque string and asks
Keycloak on every request — *"is this token active, and what does it grant?"* — authenticating as
the confidential client `mcp-server` (client_secret_basic). Keycloak consults its **live session
state**, so ending a session (logout, revocation, admin action) is visible on the very next
uncached request. A TTL cache (`INTROSPECTION_TTL_SECONDS`, default 10 s) bounds the extra
latency and AS load; the same TTL is exactly the worst-case revocation delay.

## When to use it

* **Revocation must take effect in seconds**, not "when the token expires": admin kicks a user,
  a leaked token is killed, a device is unenrolled.
* The AS issues **opaque tokens** (random strings, Keycloak "lightweight" tokens, most GitHub/
  Google-style API tokens): there is nothing to validate locally, introspection is the *only*
  option.
* You want the AS to remain the single source of truth about token state (audit, central policy),
  and the RS to hold no key material.

## When not

* **Latency and availability budget**: every uncached request costs one AS round trip, and the RS
  *fails closed* when the AS is down (500, see below). JWKS validation (04) keeps working through
  an AS outage.
* High-throughput APIs where the AS would become the bottleneck — or pay for it with a longer TTL
  and accept the revocation delay; at that point 04 with short-lived tokens is usually simpler.
* The middle grounds are worth knowing: short-lived JWTs + refresh (04), gateway-side
  introspection once per connection (09), or hybrid "JWT locally + introspect only sensitive
  operations" (docs-only, see `docs/patterns.md`).

## Happy path (and what revocation changes)

```mermaid
sequenceDiagram
    participant C as MCP client (04's client)
    participant RS as MCP server :4107 (RS)
    participant KC as Keycloak :8180 (AS)

    C->>RS: POST /mcp (initialize, no token)
    RS-->>C: 401 WWW-Authenticate: Bearer resource_metadata="…/oauth-protected-resource/mcp"
    C->>RS: GET /.well-known/oauth-protected-resource/mcp
    RS-->>C: { authorization_servers: [Keycloak], scopes_supported: [mcp:tools, mcp:admin] }
    C->>KC: discovery → authorize (PKCE, browser login) → token
    KC-->>C: access_token (a JWT — but nobody here parses it)
    C->>RS: POST /mcp (Authorization: Bearer <token>)
    RS->>KC: POST /token/introspect  (Basic mcp-server:secret, token=<token>)
    KC-->>RS: { active: true, aud: "mcp-server", scope, username, exp, realm_access, … }
    Note over RS: cache verdict for min(exp, INTROSPECTION_TTL_SECONDS)
    RS-->>C: 200 (tools run; whoami shows the introspection claims)
    C->>RS: further requests within the TTL
    Note over RS: cache hit — no round trip
    rect rgb(250, 235, 235)
    Note over KC: revocation: RFC 7009 /revoke, or admin "logout user"
    C->>RS: same token, after the TTL window
    RS->>KC: POST /token/introspect
    KC-->>RS: { active: false }
    RS-->>C: 401 Bearer error="invalid_token", error_description="token inactive"
    Note over C,KC: example 04 would still answer 200 with this token — until exp
    end
```

## How the code does it

The verifier lives in `examples/07-token-introspection/server.ts` (the resource server never
parses the token — a lint test asserts the file does not import `jose`). The core:

```ts
async verifyAccessToken(token: string): Promise<AuthInfo> {
  const key = createHash('sha256').update(token).digest('hex');    // cache key: never the raw token
  let response: IntrospectionResponse;
  try {
    response = await this.lookup(key, token);                      // cached, single-flight per token
  } catch (error) {
    console.error('[introspection] endpoint unavailable:', …);
    throw new ServerError('introspection unavailable');            // 500, NO WWW-Authenticate: fail closed
  }
  if (response.active !== true) throw new InvalidTokenError('token inactive');           // → 401
  const aud = Array.isArray(response.aud) ? response.aud : … ? [response.aud] : [];
  if (!this.options.audience.some((a) => aud.includes(a)))
    throw new InvalidTokenError('wrong audience');                 // defence in depth      → 401
  const authInfo = authInfoFromPayload(response, token, keycloakEffectiveScopes);
  if (typeof authInfo.expiresAt !== 'number')                      // RFC 7662: exp is OPTIONAL
    authInfo.expiresAt = Math.floor(Date.now() / 1000) + Math.max(this.options.ttlSeconds, 1);
  const missing = this.options.requiredScopes.filter((s) => !authInfo.scopes.includes(s));
  if (missing.length > 0) throw new InsufficientScopeError(headerSafe(`missing scope: ${missing.join(' ')}`)); // → 403
  return authInfo;
}
```

and the wiring is 04's, with the verifier swapped:

```ts
const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
  resourceUrl, authorizationServers: [issuer],
  scopesSupported: ['mcp:tools', 'mcp:admin'], resourceName: '07-token-introspection',
});
const verifier = new IntrospectionVerifier({ clientSecret: env('MCP_SERVER_CLIENT_SECRET'), metadata });
mountMcp(app, { createServer: …, auth: requireBearerAuth({ verifier, resourceMetadataUrl }) });
```

Points that matter:

* **Cache semantics.** Positive verdicts live until `min(exp, now + INTROSPECTION_TTL_SECONDS)`;
  `active:false` is remembered for 2 s (so a garbage-token flood does not become a Keycloak
  flood); an *outage* is never cached. Concurrent requests with the same token share one
  in-flight introspection call. The cache maps `sha256(token)` → verdict; the raw token is never
  stored or logged (the server logs the 8-char hash prefix at most).
* **Fail closed, and blame ourselves.** A failed introspection call — Keycloak down, or a wrong
  `MCP_SERVER_CLIENT_SECRET` — is *not the client's fault*: the server answers
  `500 {"error":"server_error","error_description":"introspection unavailable"}` **without**
  `WWW-Authenticate`. With a 401 the SDK client would discard its perfectly fine token and drag
  the user through re-authorization loops against an AS that is not answering.
* **SEP-835 scope selection.** `requireBearerAuth` gets *no* `requiredScopes`, so the 401 carries
  no `scope=` and the SDK client requests what the PRM advertises (`mcp:tools mcp:admin`); the
  verifier itself enforces `mcp:tools` (403 `missing scope: mcp:tools`) and
  `keycloakEffectiveScopes()` keeps `mcp:admin` only for users with the `mcp-admin` realm role.
* **The response is a claims set.** Keycloak's introspection answer carries the same fields as
  the JWT payload (`sub`, `username`, `client_id`, `azp`, `scope`, `exp`, `realm_access`, …), so
  it goes through the same `authInfoFromPayload()` mapping as 04 — `whoami` output is
  indistinguishable from 04's, plus `claims.active: true`:

```json
{"clientId":"mcp-cli","scopes":["profile","mcp:tools","email"],"expiresAt":1787993985,
 "extra":{"sub":"0c04e3c8-…","username":"alice","email":"alice@example.com","roles":["mcp-user"],
          "claims":{"iss":"http://192.168.78.87:8180/realms/mcp","aud":"mcp-server","azp":"mcp-cli",
                    "scope":"profile mcp:tools email","client_id":"mcp-cli","username":"alice","active":true,…}}}
```

## Run it

```bash
npm run kc:up                                  # once: Keycloak + realm "mcp"
npm run ex:07:server                           # terminal 1
OAUTH_CLIENT_ID=mcp-cli npm run ex:07:client   # terminal 2: browser opens, log in as alice / password
```

Server (terminal 1):

```
[07-token-introspection] listening on 0.0.0.0:4107
[07-token-introspection] MCP endpoint: http://192.168.78.87:4107/mcp   (PUBLIC_HOST 192.168.78.87 — env)
POST /mcp 401 3.2ms
[introspection] token 1d8f2399 → active (cached 10.0s)
POST /mcp 200 41.5ms
POST /mcp 200 1.2ms                            ← cache hits: no [introspection] line
```

Client (terminal 2) — identical to 04 apart from the port:

```
tools        -> whoami, add, admin_only
whoami       -> {"clientId":"mcp-cli","scopes":["profile","mcp:tools","email"],…,"extra":{…,"username":"alice",…}}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
RESULT {"example":"07","tools":["add","admin_only","whoami"],…,"adminOnly":"denied"}
```

LAN variant: run the client from another machine with
`MCP_SERVER_URL=http://192.168.78.87:4107/mcp` (the PRM tells it where Keycloak is), and
`OAUTH_REDIRECT_HOST=<that machine's address>` if the browser runs there too — see
`docs/lan-testing.md`.

## Observe it

What the server does behind the scenes, by hand. Get a test token (password grant, test-only
client `mcp-test`), then introspect it exactly like the server does:

```bash
TOKEN=$(curl -s http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token \
  -d grant_type=password -d client_id=mcp-test -d username=alice -d password=password \
  -d scope=mcp:tools | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -s -u mcp-server:mcp-server-secret-demo \
  http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token/introspect -d "token=$TOKEN"
```

```json
{"exp":1787994066,"iss":"http://192.168.78.87:8180/realms/mcp","aud":"mcp-server",
 "sub":"0c04e3c8-…","azp":"mcp-test","realm_access":{"roles":["mcp-user"]},
 "scope":"profile mcp:tools email","client_id":"mcp-test","username":"alice","active":true}
```

Use the token against the MCP endpoint (Streamable HTTP needs both `Accept` values and the JSON
`Content-Type` — 406/415 otherwise):

```bash
curl -si -X POST http://192.168.78.87:4107/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# → HTTP/1.1 200 OK, mcp-session-id: …   — and the server log shows one [introspection] line
```

Without a token, the discovery entry point (this is what the SDK client parses):

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header",
                  resource_metadata="http://192.168.78.87:4107/.well-known/oauth-protected-resource/mcp"
```

```bash
curl -s http://192.168.78.87:4107/.well-known/oauth-protected-resource/mcp
# {"resource":"http://192.168.78.87:4107/mcp","authorization_servers":["http://192.168.78.87:8180/realms/mcp"],
#  "scopes_supported":["mcp:tools","mcp:admin"],"resource_name":"07-token-introspection","bearer_methods_supported":["header"]}
```

(No `/.well-known/oauth-authorization-server` on this origin — that document belongs to the
issuer; the server answers 404 there. See `docs/sdk-notes.md` on why the SDK's metadata router
is not used.)

## Break it — revocation, live

**1. RFC 7009: the client revokes its own token** (`npm run ex:07:client -- --revoke`, after a
normal login). The client revokes at Keycloak, then polls the server with the *same* token:

```
revoked the access token at Keycloak (RFC 7009, client mcp-cli); polling the server with the same token…
401 after 9.5s (cache TTL): Bearer error="invalid_token", error_description="token inactive",
    resource_metadata="http://192.168.78.87:4107/.well-known/oauth-protected-resource/mcp"
RESULT {…,"extra":{"revoked":{"afterSeconds":9.5,…}}}
```

9.5 s = what remained of the 10 s cache window — **the TTL is the revocation latency**. By hand:

```bash
curl -s http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/revoke \
  -d client_id=mcp-test -d "token=$TOKEN" -w '%{http_code}\n'      # 200
curl -s -u mcp-server:mcp-server-secret-demo \
  http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/token/introspect -d "token=$TOKEN"
# {"active":false}         ← immediately, though the JWT's exp is ~15 min away
```

**2. Admin kills the user's sessions** (`npm run ex:07:revoke -- alice` → Keycloak admin REST
"logout", then waits `INTROSPECTION_TTL_SECONDS + 1` so the cached verdict is gone). The next
client run:

```
$ npm run ex:07:client
stored token rejected by the resource server: 401 Bearer error="invalid_token", error_description="token inactive", …
revoked or expired — an introspecting server sees this immediately; a JWKS server (04) would accept a revoked token until exp.
tokens forgotten; run the client again to log in afresh.
$ echo $?        # 1
```

The client deliberately probes with the stored token *raw* and exits 1 — with the plain SDK flow
the 401 would trigger refresh → `invalid_grant` (the session is gone) → a fresh browser login,
and you would never see the revocation happen. `npm run smoke -- 07` scripts exactly this
sequence and *expects* the exit 1.

**3. The contrast.** The same revoked token, presented to a JWKS-validating server: accepted
until `exp`. `server.test.ts` pins this down in one test — after `adminLogoutUser('alice')` the
introspection server answers 401 while `createKeycloakVerifier()` (04's verifier, same realm,
same token) still resolves:

```ts
expectOAuth401(after.response, …);                       // 07: "token inactive"
const jwksVerifier = await createKeycloakVerifier();     // 04's validation
await expect(jwksVerifier.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({ clientId: 'mcp-test' });
```

(Live version: start `npm run ex:04:server` and replay the revoked token against
`http://<PUBLIC_HOST>:4104/mcp` — 200 until `exp`.)

**4. The rest of the negative matrix** (`npx vitest run examples/07-token-introspection`, all
hermetic against a stubbed `introspect`):

| Case | Response |
|---|---|
| `active: false` | 401 `invalid_token` `"token inactive"` + `resource_metadata` |
| active, but `aud` lacks `mcp-server` | 401 `"wrong audience"` (Keycloak already answers `active:false` here — the check still runs: defence in depth) |
| active, scope `profile email` only | 403 `insufficient_scope` `"missing scope: mcp:tools"` (no `scope=` parameter — SEP-835) |
| introspection call throws (AS down, wrong `MCP_SERVER_CLIENT_SECRET`) | **500** `server_error` `"introspection unavailable"`, **no** `WWW-Authenticate`, never cached |
| two requests within the TTL | one introspection call |
| `INTROSPECTION_TTL_SECONDS=0` | every request introspects |
| two garbage tokens within 2 s | one introspection call (negative cache) |
| positive entry with `exp` sooner than the TTL | re-introspected after `exp` (cache never outlives the token) |
| bob's token on alice's session | 403 (session ↔ subject binding, as everywhere) |

## Threat-model notes

* **Cache TTL = revocation latency.** Every second of `INTROSPECTION_TTL_SECONDS` is a second a
  revoked token keeps working. 0 gives instant revocation at one AS round trip per request;
  10 s absorbs the demo's per-session bursts. Pick per API sensitivity; the negative cache (2 s)
  only shields Keycloak from invalid-token floods and never delays *granting* access.
* **The introspection credential is a real secret.** `MCP_SERVER_CLIENT_SECRET` lets anyone ask
  Keycloak about any token (a token-validity oracle, and the responses carry PII claims). Ship it
  like a DB password: env/secret store, rotation, never in client-side config. The demo value is
  public — rotate before any real use.
* **Audience check stays, even though Keycloak enforces it.** Keycloak answers `active:false`
  when the introspecting client is not in the token's `aud` (verified — that is *why* `mcp-server`
  must be in `aud`). The verifier still checks `aud` itself: another AS, or a future realm
  change, must not silently turn every valid-for-someone token into access here (audience
  confusion / confused deputy).
* **Fail closed is a DoS trade.** When Keycloak is down, this server answers 500 to everyone —
  by design (accepting tokens unvalidated would be worse). If that is unacceptable, cache
  longer, or move to 04's model and revoke by rotating signing keys (which logs *everyone* out).
* **Tokens remain bearer tokens.** Introspection changes *validation*, not *possession*: anyone
  holding the string can use it until revoked — and this demo runs plain HTTP on the LAN, so
  treat every token in it as public. Sender-constraining (mTLS, DPoP) is a different axis — see
  `08-mtls` and `docs/patterns.md`.
* What this approach *adds* over 04: near-real-time central kill switch, opaque-token support,
  AS-side audit of every validation. What it does *not* add: client authentication, transport
  security, or protection from a compromised RS (which holds an introspection credential).

## Variations and links

* **Opaque tokens**: flip Keycloak's client to lightweight/opaque access tokens and *nothing here
  changes* — that is the point of stateful validation. 04 would stop working entirely.
* **Introspect at the edge**: example `09-auth-gateway` moves validation in front of the server;
  doing the introspection there centralizes the credential and the cache.
* **Hybrid**: validate the JWT locally (04) *and* introspect only state-changing calls —
  docs-only pattern, `docs/patterns.md`.
* Related examples: [`04-keycloak-resource-server`](04-keycloak-resource-server.md) (the
  stateless twin), [`10-token-exchange-downstream`](10-token-exchange-downstream.md) (the same
  `mcp-server` client identity used for RFC 8693).
* SDK behaviour referenced here (401 handling, refresh-on-invalid_grant, PRM rules):
  [`docs/sdk-notes.md`](sdk-notes.md). Spec background: RFC 7662 (introspection), RFC 7009
  (revocation), RFC 9728 (PRM), `docs/spec-background.md`.
