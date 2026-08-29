# 02 — Self-issued JWT verified via a JWKS URL

**Directory:** `examples/02-jwt-local` · **Ports:** 4102 (MCP server), 4192 (local issuer) ·
**Authorization server:** a local *token vending endpoint* (not an OAuth AS) · **Keycloak:** no ·
**Spec grade:** OUTSIDE-SPEC — a self-issued token with no authorization-server metadata and no
discovery. It does exercise the token-validation half of the spec properly: RFC 7519 JWT / RFC 7515
JWS (RS256), RFC 7517 JWK Set, RFC 6750 bearer tokens, and an RFC 8707-style **exact audience**
restriction enforced on the resource-server side.

This is the first example with a real, verifiable **identity**. A tiny issuer signs a JWT that
states who the caller is (`sub`, `preferred_username`) and what they may do (`scope`), and the MCP
server verifies it **offline** against the issuer's published public key. Nothing but the issuer's
private key can mint a token the server will accept, and the server never has to call the issuer per
request — it just needs the JWKS. Example 04 keeps this exact verifier and swaps the toy issuer for
Keycloak plus the OAuth discovery machinery this example deliberately omits.

## When to use

* A single service (or a few) that you also operate the token issuer for, on a trusted network, and
  you want **claims-based** authorization (identity + scopes) without standing up a full IdP.
* Machine-to-machine calls where a signed, short-lived, audience-bound token is enough and an
  interactive login is not needed.
* As the mental model for "how JWT verification works" before adding an external AS (04) or
  introspection (07).

## When not to use

* Anytime a real IdP is available — use **04** (Keycloak as AS, MCP server as pure resource server).
  Self-issuing tokens means you own key management, rotation and revocation yourself.
* When you need **immediate revocation**: a JWT is valid until it expires. Use short TTLs plus
  introspection (**07**) if you must cut access mid-token.
* When clients must **discover** how to authenticate: this example intentionally sends no Protected
  Resource Metadata, so an OAuth client cannot bootstrap from a 401. That is the whole point of 04.

## Happy path

```mermaid
sequenceDiagram
    participant C as Client (client.ts)
    participant I as Local issuer (issuer.ts, :4192)
    participant S as MCP server (server.ts, :4102)

    Note over I: on startup, load/generate the RS256 key pair<br/>publish the public half at /.well-known/jwks.json
    C->>I: POST /token (username=alice&password=…)
    I-->>C: { access_token: <RS256 JWT>, token_type: Bearer }
    C->>S: POST /mcp  initialize<br/>Authorization: Bearer <jwt>
    S->>I: GET /.well-known/jwks.json  (once, then cached by jose)
    I-->>S: { keys: [ RSA public JWK ] }
    Note over S: verify signature, iss, exact aud, exp, nbf;<br/>require scope mcp:tools; derive effective scopes
    S-->>C: 200 + mcp-session-id
    C->>S: tools/call whoami / add / admin_only  (same bearer)
    S-->>C: results (admin_only ok only if the token carries mcp:admin)
```

## How the code does it

**The verifier (server.ts).** The whole auth surface is one middleware. The required scope goes on
the verifier; `requireBearerAuth` gets *only* `{ verifier }` — no `requiredScopes` and no
`resourceMetadataUrl`, because there is no authorization server to point a client at:

```ts
// examples/02-jwt-local/server.ts
const verifier = createJwtVerifier({
  issuer,                       // http://<PUBLIC_HOST>:4192  (exact string match on `iss`)
  audience,                     // http://<PUBLIC_HOST>:4102/mcp  (exact string match on `aud`)
  jwks,                         // http://<PUBLIC_HOST>:4192/.well-known/jwks.json  (fetched once, cached)
  requiredScopes: [SCOPE_TOOLS], // -> 403 insufficient_scope "missing scope: mcp:tools"
});

const app = createApp();
mountMcp(app, {
  createServer: () => createDemoServer({ name: '02-jwt-local' }),
  auth: requireBearerAuth({ verifier }), // no resourceMetadataUrl: nothing to discover
});
```

`createJwtVerifier` (`src/shared/jwt.ts`) wraps `jose.jwtVerify`, which checks the signature against
the JWKS key selected by `kid`, plus `iss`, `aud` and time claims (`exp`/`nbf`/`iat`) with a 5-second
clock tolerance. Every failure is turned into an `InvalidTokenError` (→ 401) with a **static**
reason string, or `InsufficientScopeError` (→ 403); a JWKS that cannot be fetched becomes a 500
(`ServerError`) so clients do not treat *our* outage as a reason to re-authorize. See
`docs/sdk-notes.md` for why those error classes and static messages matter.

**The issuer (issuer.ts).** Not an OAuth server — it owns a key and hands out tokens:

```ts
// examples/02-jwt-local/issuer.ts  (abridged)
app.get('/.well-known/jwks.json', (_req, res) => res.json({ keys: [keys.publicJwk] }));

app.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
  const user = demoUsers()[username];               // alice -> mcp:tools ; bob -> mcp:tools mcp:admin
  if (!user || user.password !== password) return res.status(401).json({ error: 'invalid_credentials' });
  const token = await mintToken({ sub: username, username, scope: user.scope, roles: user.roles, ttlSec });
  res.json({ access_token: token, token_type: 'Bearer', expires_in: ttlSec });
});
```

`mintToken` signs `{ scope, preferred_username, realm_access.roles, iss, aud, sub, iat, exp }` with
RS256 and the key's `kid`. The audience it stamps is the server's canonical `/mcp` URL, so the
`aud` the server checks and the token the issuer mints are built from the same `publicUrl()` value.

**The client (client.ts)** is the baseline client plus a static header — exactly like example 01,
except the token is fetched from the issuer first:

```ts
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
});
```

**What `whoami` returns** (the server's view of the verified token — the raw token is never echoed):

```json
{
  "clientId": "alice",
  "scopes": ["mcp:tools"],
  "expiresAt": 1787993692,
  "resource": "http://192.168.78.87:4102/mcp",
  "extra": {
    "sub": "alice",
    "username": "alice",
    "roles": ["mcp-user"],
    "claims": { "scope": "mcp:tools", "preferred_username": "alice", "iss": "…:4192", "aud": "…:4102/mcp", "exp": 1787993692 }
  }
}
```

bob's token instead carries `"scope":"mcp:tools mcp:admin"` and `roles:["mcp-user","mcp-admin"]`, so
`admin_only` succeeds. Because this example uses the default effective-scopes rule (the token's
`scope` *is* the authority), whoever the issuer trusts with `mcp:admin` gets it — the issuer, not a
role mapper, is the policy point. Contrast 04, which passes `keycloakEffectiveScopes` so a realm
role gates `mcp:admin` regardless of the granted scope.

## Run it

Three terminals (issuer, server, client). From another LAN machine, point the client at this box:

```bash
npm run ex:02:issuer                 # http://<PUBLIC_HOST>:4192  (JWKS + /token)
npm run ex:02:server                 # http://<PUBLIC_HOST>:4102/mcp
npm run ex:02:client                 # alice
npm run ex:02:client -- http://192.168.78.87:4102/mcp     # from a laptop on the LAN
DEMO_USER=bob EXPECT_ADMIN=ok npm run ex:02:client        # bob -> admin_only ok
```

Server banner and a successful alice run (trimmed real output):

```
[02-jwt-local] verifying iss=http://192.168.78.87:4192 aud=http://192.168.78.87:4102/mcp via JWKS http://192.168.78.87:4192/.well-known/jwks.json
[02-jwt-local] MCP endpoint: http://192.168.78.87:4102/mcp   (PUBLIC_HOST 192.168.78.87 — env)

tools        -> whoami, add, admin_only
whoami       -> {"clientId":"alice","scopes":["mcp:tools"],...,"extra":{"sub":"alice","username":"alice",...}}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
RESULT {"example":"02",...,"whoami":{...},"add":"5","adminOnly":"denied"}
```

## Observe it

Streamable HTTP is strict about headers: a `POST /mcp` needs both
`Accept: application/json, text/event-stream` and `Content-Type: application/json`. Get a token from
the issuer, then drive the server by hand:

```bash
TOKEN=$(curl -s -X POST http://192.168.78.87:4192/token -d 'username=alice&password=password' \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')

curl -s -D - -o /dev/null -X POST http://192.168.78.87:4102/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# -> HTTP/1.1 200 OK
#    mcp-session-id: 3f36cbaa-…            (and NO WWW-Authenticate header)
```

The public verification key is just a GET:

```bash
curl -s http://192.168.78.87:4192/.well-known/jwks.json
# -> {"keys":[{"kty":"RSA","n":"y2wx2OUX…","e":"AQAB","kid":"844d1b60-…","alg":"RS256","use":"sig"}]}
```

No token → the resource server's 401. Note there is **no** `resource_metadata` and **no** `scope`
parameter — there is nothing to discover:

```bash
curl -s -D - -o /dev/null -X POST http://192.168.78.87:4102/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"c","version":"0"}}}'
# -> HTTP/1.1 401 Unauthorized
#    WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header"
```

## Break it

`mint.ts` prints one token per invocation (only the token reaches stdout, so `TOKEN=$(…)` works).
Each line below is also a row of `server.test.ts`. Feed the token to the same `curl` and read the
`WWW-Authenticate` header:

| Command | Server response |
|---|---|
| `ex:02:mint -- --sub alice --ttl -60` | `401  error_description="JWT rejected: token expired"` |
| `ex:02:mint -- --sub alice --nbf 120` | `401  error_description="JWT rejected: claim nbf check_failed"` |
| `ex:02:mint -- --sub alice --iss http://evil:4192` | `401  error_description="JWT rejected: wrong issuer"` |
| `ex:02:mint -- --sub alice --aud http://192.168.78.87:9999/mcp` | `401  error_description="JWT rejected: wrong audience"` |
| `ex:02:mint -- --sub alice --aud http://192.168.78.87:4102/mcp/` | `401  wrong audience` (a trailing slash is a *different* audience) |
| `ex:02:mint -- --sub alice --alg none` | `401  error_description="JWT rejected: ERR_JOSE_NOT_SUPPORTED"` |
| `ex:02:mint -- --sub alice --alg HS256` | `401` (algorithm confusion: jose picks the RS256 key by `kid` and refuses HS256) |
| `ex:02:mint -- --sub alice --tamper` | `401  error_description="JWT rejected: bad signature"` |
| `ex:02:mint -- --sub alice --kid nope` | `401  error_description="JWT rejected: no matching signing key"` |
| `ex:02:mint -- --sub alice --scope email` | `403  error_description="missing scope: mcp:tools"` |

Real captured headers for three of them:

```
WWW-Authenticate: Bearer error="invalid_token", error_description="JWT rejected: token expired"
WWW-Authenticate: Bearer error="invalid_token", error_description="JWT rejected: ERR_JOSE_NOT_SUPPORTED"
WWW-Authenticate: Bearer error="insufficient_scope", error_description="missing scope: mcp:tools"
```

Two failures deliberately do **not** happen here: a token whose `aud` names *another* server is
rejected (audience confusion is the attack an exact `aud` check stops), and the error strings are
fixed vocabulary — a crafted token header can never inject quotes or CRLF into the response header
(see `docs/sdk-notes.md`).

## Threat model notes

* **The issuer is a demo token vending endpoint, not an OAuth authorization server.** It has no
  `client_id`, no PKCE, no consent, no discovery document and no client registration; `POST /token`
  trusts a username/password and returns a token. It exists only to own a signing key and publish a
  JWKS. Do not model a production AS on it — that is examples 03 (embedded AS) and 04 (Keycloak).
* **Plain HTTP on the LAN.** Tokens and the demo password cross the wire in cleartext. A JWT is a
  *bearer* credential: anyone who captures it can replay it until it expires. Real deployments must
  use TLS for both the issuer and the MCP server, and keep TTLs short. See `docs/lan-testing.md`.
* **No revocation.** The server verifies tokens offline, so a leaked or misissued token is valid
  until `exp`. The mitigation here is a short TTL (default 300 s). If you need to cut access
  immediately, add introspection (example 07) — you trade an offline check for an online one.
* **Exact-audience policy (RFC 8707 spirit).** The server requires `aud` to equal its one canonical
  `/mcp` URL byte-for-byte — a different port, host or even a trailing slash fails. This is what
  stops a token minted for another service from being replayed against this one (audience/"confused
  deputy" confusion). Because the issuer, the server's `aud` check and the URL clients dial are all
  built from the same `publicUrl()` value, they cannot silently drift apart.
* **Signature and algorithm.** Verification is RS256 against a key selected by `kid` from the JWKS;
  `alg: none` and HS256-with-the-public-key (the classic algorithm-confusion attacks) are both
  refused because jose matches the key type to the JWKS entry. The private key is generated once and
  stored `0600` under `.mcp-auth/` (git-ignored); it never leaves the issuer except to sign.
* **Key rotation.** `npm run ex:02:issuer -- --rotate` generates a fresh key pair and publishes a new
  JWKS. Because jose caches a remote JWKS (`cacheMaxAge`, ~10 min by default) and only refetches on
  an *unknown* `kid`, a running server keeps accepting tokens from the retired key until its cache
  expires or it restarts — so rotate by first adding the new key, letting caches pick it up, then
  retiring the old one (or restart the server for an immediate cutover). `server.test.ts` verifies
  that once the JWKS serves only the new key, a token from the old key is rejected
  (`no matching signing key`).
* **Scope is set by the issuer, not a role mapper.** This example trusts the issuer's `scope` claim
  directly (no `effectiveScopes` hook), so the issuer is the sole authority on who gets `mcp:admin`.
  Example 04 instead gates `mcp:admin` behind a Keycloak realm role via `keycloakEffectiveScopes`.

## Variations and links

* **Add an authorization server:** `docs/04-keycloak-resource-server.md` is this verifier plus
  Protected Resource Metadata and Keycloak — the spec-recommended shape. The 401 there *does* carry
  `resource_metadata` and `scope` so an OAuth client can discover and log in.
* **Simpler still:** `docs/01-api-key.md` (a shared secret, no signature, no claims).
* **Baseline transport, sessions and the Host allow-list:** `docs/00-baseline-no-auth.md`.
* **SDK behaviour relied on here** (error-class mapping, mandatory `expiresAt`, static header
  strings, no-`resource_metadata` 401, JWKS-unreachable → 500): `docs/sdk-notes.md`.
* **Other token patterns:** introspection for revocation (`docs/07-token-introspection.md`),
  token exchange to call a downstream API on the user's behalf (`docs/10-token-exchange-downstream.md`).
