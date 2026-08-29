# `src/shared` — code every example builds on

Small, readable modules; each example's `server.ts` / `client.ts` should stay under ~40 lines.
**Frozen after Phase 0** (see `docs/design.md` §10): example agents own only `examples/NN-*/**` and
`docs/NN-*.md`; a shared change you need goes into your README's "Integration notes".

## Import-order rule (read this first)

```ts
import { port, publicUrl } from '../../src/shared/env.ts';   // ALWAYS the first import
import { ... } from '@modelcontextprotocol/sdk/server/auth/router.js';
```

`env.ts` loads the **repo-root** `.env` (whatever the current directory is; existing process.env
values win) and sets `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL ??= '1'`.
The SDK's `server/auth/router.js` reads that variable **once, when the module is evaluated**, and
refuses `http://192.168.x.x` issuers otherwise. ES modules evaluate in import order, so `env.ts`
first is what makes it work. Every shared module also imports `env.ts` first, so the rule holds no
matter which shared module an entrypoint imports first — but keep it explicit in your own files:
`tests/conventions.test.ts` fails when any `examples/**/*.ts`, `scripts/*.ts` or shared module
starts with another import.

Other conventions (also enforced by `tests/conventions.test.ts`): SDK imports always use sub-paths
ending in `.js` (`@modelcontextprotocol/sdk/server/mcp.js`, …); local imports use `.ts` extensions
(tsx / Node type stripping); every server binds `0.0.0.0`; every URL comes from `env.ts` — no
`http://localhost` in server-side code (mark a URL-parse base with `// loopback-ok`); every
`examples/*/client.ts` ends with `process.exit(printResult(...))`; bearer error messages are static
strings or go through `headerSafe()`.

## Modules

### `env.ts`

| Export | Purpose |
|---|---|
| `env(name, fallback?)` | string env var, throws when missing without fallback |
| `port(name, fallback)` | numeric env var validated as a port |
| `publicHost()` | `PUBLIC_HOST` or the first non-loopback IPv4 (`publicHostSource()` says which) |
| `publicUrl(port, path = '/mcp', scheme = 'http')` | the canonical `http://<PUBLIC_HOST>:<port><path>` (no trailing slash); `scheme: 'https'` only for the mTLS example |
| `REPO_ROOT` | absolute path of the repository (token store, `.env`, certificates) |
| `keycloak()` | `{ baseUrl, realm, issuer, discoveryUrl, jwksUri, tokenEndpoint, authorizationEndpoint, introspectionEndpoint, registrationEndpoint }` from `KEYCLOAK_URL` / `KEYCLOAK_REALM` |
| `isMain(import.meta)` | true when the file is the script being run (lets tests import `server.ts` without starting it) |

### `tools.ts`

`createDemoServer({ name, version? })` → `McpServer` with `whoami`, `add`, `admin_only`.
Helpers: `requireScope(authInfo, scope)`, `formatAuthInfo(authInfo)`, constants `SCOPE_TOOLS`,
`SCOPE_ADMIN`. An example that needs one extra tool registers it on the returned server.

**Effective-scopes contract.** Tools consult exactly one thing: `extra.authInfo.scopes`. Verifiers
are responsible for putting the *effective* scopes there — what the client was granted **and** what
the user is allowed to do. Example: `keycloakEffectiveScopes()` keeps `mcp:admin` only when the
token's `realm_access.roles` contains `mcp-admin`. Because policy lives in the verifier, every
example shares the same tools and can be compared 1:1.

### `http.ts`

| Export | Purpose |
|---|---|
| `createApp({ allowedHosts?, log? })` | Express 5 app: request log (stderr, `MCP_LOG=0` silences), Host-header validation **before** the body parser (403 for hosts other than `PUBLIC_HOST`, `localhost`, `127.0.0.1`, `[::1]`, `MCP_ALLOWED_HOSTS` — all compared lower-case), `express.json()`, `GET /healthz`, JSON-RPC error handler |
| `mountMcp(app, { path?, createServer, auth?, stateless?, sessionIdleMs? })` | Streamable HTTP endpoint. Stateful (default): one transport + server per session, `auth` middleware on POST/GET/DELETE, session bound to the initializing subject (403 on mismatch), cleanup on DELETE/close/idle (`sessionIdleMs`, default 30 min, 0 disables; a session with an open GET stream is never swept). Non-JSON `Content-Type` → 415. Stateless: new transport + server per POST, GET/DELETE → 405 |
| `listen(app, { port, name, path?, host?, server? })` | appends the JSON 404 fallback + error handler, then `app.listen(port, host ?? '0.0.0.0')` + banner with the canonical URL; `server` lets example 08 pass an `https.createServer(tls, app)`, `host: '127.0.0.1'` is for example 09's internal server. Call it last |
| `jsonRpcErrorHandler`, `notFoundHandler` | the error middleware (invalid JSON → 400 `-32700`, other body-parser errors → their status `-32600`, anything else → 500 `-32603`, logged to stderr, never echoed) and the JSON 404 for unknown routes. `createApp`, `mountMcp`, `listen` and `startTestServer` append them so they are last no matter what you mount |
| `subjectOf(authInfo)` | `extra.sub` or `clientId` — the identity a session is bound to |
| `allowedHostnames(extra?)` | the Host allow-list `createApp` uses |

The SDK's `createMcpExpressApp()` is intentionally not used: its defaults (`127.0.0.1`,
localhost-only Host check) reject LAN clients.

### `jwt.ts`

| Export | Purpose |
|---|---|
| `createJwtVerifier({ issuer, audience, jwks, requiredScopes?, effectiveScopes?, clockToleranceSec? })` | `OAuthTokenVerifier` for `requireBearerAuth`. `jwks` may be a JWKS URL (remote, cached), a JWK Set, a single JWK or a `CryptoKey`/`KeyObject`. Token failures → `InvalidTokenError` (401, message says *expired / wrong issuer / wrong audience / bad signature / no matching key*); missing required scope → `InsufficientScopeError` (403); **JWKS unreachable / timeout / malformed → `ServerError`** (500 without `WWW-Authenticate` — the client must not start re-authorizing because *our* IdP is down) |
| `authInfoFromPayload(payload, token, effectiveScopes?)` | `AuthInfo { token, clientId: azp ?? client_id ?? sub, scopes, expiresAt: exp, resource: first URL-shaped aud, extra: { sub, username, email, roles, claims } }`; `username` is `preferred_username` (OIDC) or `username` (RFC 7662 introspection), so example 07 can reuse it on an introspection response unchanged |
| `keycloakEffectiveScopes(payload)` | token scopes, minus `mcp:admin` unless role `mcp-admin` |
| `tokenScopes(payload)` | the raw `scope` (or `scp`) claim as a list |
| `describeJoseError(error)`, `isKeyRetrievalError(error)` | **fixed-vocabulary** reason for a `jose` failure; whether a failure is about fetching keys rather than the token |
| `headerSafe(text)` | strips quotes, backslashes and control characters — applied to every message that ends up in `WWW-Authenticate` |

Why the error classes matter: `requireBearerAuth` maps only `InvalidTokenError`/`InsufficientScopeError`
to 401/403 **with** `WWW-Authenticate`; `ServerError` to 500 without it; any other exception also
becomes a 500. `expiresAt` (seconds) is mandatory for the same middleware — API-key style verifiers
must synthesise one.

Why the messages are static: `bearerAuth.js` interpolates the error message into
`WWW-Authenticate: Bearer error="…", error_description="<message>"` **without escaping**. `jose`
quotes strings from the *unverified* token header in some of its messages, so copying
`error.message` would let a crafted token inject quotes — or CR/LF, which makes `res.set()` throw
and turns the 401 into a 500. Never put request-derived text into these errors.

### `prm.ts` — RFC 9728 Protected Resource Metadata (pure resource servers: 04, 05, 07, 09, 10)

| Export | Purpose |
|---|---|
| `mountProtectedResourceMetadata(app, { resourceUrl, authorizationServers, scopesSupported?, resourceName?, bearerMethodsSupported? })` | serves the PRM document (GET/OPTIONS, CORS `*`) at `/.well-known/oauth-protected-resource<path>` and returns that URL for `requireBearerAuth({ resourceMetadataUrl })`. Mount before `mountMcp()` |
| `resourceMetadataUrl(resourceUrl)` | the path-aware well-known URL (`getOAuthProtectedResourceMetadataUrl`) |
| `protectedResourceMetadata(options)` | the JSON document itself |

Deliberately **not** `mcpAuthMetadataRouter`: that router also mirrors the AS document at
`<rs-origin>/.well-known/oauth-authorization-server`, which RFC 8414 reserves for the issuer's
origin; the SDK client never needs the mirror. Examples 03 and 06 use `mcpAuthRouter` because
there the MCP origin *is* the authorization server.

### `keycloak.ts` — the Keycloak-backed examples' plumbing

| Export | Purpose |
|---|---|
| `KC` | realm vocabulary: `clients.{cli,test,service,serviceJwt,server,downstream}`, `scopes.{tools,admin,downstream}`, `audience` (`mcp-server`), `roles.{user,admin}` |
| `audiences()` | `MCP_AUDIENCE` (comma list) or `['mcp-server']` |
| `discoverKeycloak(issuer?)` | the realm's OpenID discovery document (loose `OAuthMetadataSchema`, keeps `jwks_uri`, `introspection_endpoint`, `revocation_endpoint`, `registration_endpoint`, `end_session_endpoint`), asserts S256, cached per issuer |
| `createKeycloakVerifier({ metadata?, requiredScopes?, audience?, jwks? })` | `createJwtVerifier` wired with issuer + JWKS from discovery, `audiences()` and `keycloakEffectiveScopes` |
| `introspect(token, { clientId, clientSecret, metadata?, tokenTypeHint?, fetchFn? })` | RFC 7662 → `{ active, sub?, username?, client_id?, scope?, aud?, exp?, realm_access?, … }`; Keycloak answers `active: true` only when the introspecting client is in `aud` |
| `exchangeToken({ subjectToken, audience, scope?, clientId, clientSecret, metadata?, fetchFn? })` | RFC 8693 standard token exchange → `OAuthTokens`; Keycloak needs `scope=downstream-api` too, otherwise `invalid_request` |
| `revokeToken(token, { clientId, clientSecret?, tokenTypeHint?, metadata? })` | RFC 7009 |
| `adminLogoutUser(username)` | admin REST (`KC_ADMIN_USER`/`KC_ADMIN_PASSWORD`): ends all sessions → introspection turns `active: false` while JWT verifiers still accept the token until `exp` |
| `basicAuth(clientId, secret)`, `KeycloakError { status, error, error_description }` | helpers; every non-2xx OAuth response throws `KeycloakError` |

### Scope selection (SEP-835) — read this before wiring an OAuth example

The SDK client picks the scope it requests (for DCR **and** the authorization request) in this
order (`client/auth.js`): **`scope` from the 401's `WWW-Authenticate`** → PRM `scopes_supported` →
`clientMetadata.scope`. `requireBearerAuth({ requiredScopes })` puts its list into *both* the 401
and the 403 challenge as `scope="…"`. Consequences, verified against Keycloak with the browser driver:

| Wiring | 401 header | Client requests | Effect |
|---|---|---|---|
| `requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'] })` | `scope="mcp:tools"` | `mcp:tools` only | least privilege; **bob can never obtain `mcp:admin` through the browser flow** (runtime step-up via 403 `insufficient_scope` is docs-only in v0.1) |
| `createKeycloakVerifier({ requiredScopes: ['mcp:tools'] })` + `requireBearerAuth({ verifier, resourceMetadataUrl })` and PRM `scopesSupported: ['mcp:tools', 'mcp:admin']` | no `scope` | `mcp:tools mcp:admin` (from the PRM) | bob → `admin_only` ok; alice's token also *contains* `mcp:admin` but `keycloakEffectiveScopes()` drops it (no role); a token without `mcp:tools` → 403 `insufficient_scope` with `error_description="missing scope: mcp:tools"` (no `scope=` parameter) |

The smoke expectation table (bob → admin ok via browser in 03/04/06/07…) assumes the **second**
wiring for Keycloak examples; use the first only where a fixed minimal scope is the point.

### `client/oauth-cli.ts`

`CliOAuthProvider` — the SDK `OAuthClientProvider` for command-line clients:

* options `{ serverUrl, scope = 'mcp:tools', clientName?, staticClient?, redirectHost?, callbackPort?, storeDir? }`;
  `staticClient` (or `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET`) skips Dynamic Client Registration
  — an **empty** `OAUTH_CLIENT_SECRET` means "public client" (the SDK would otherwise send an empty
  `client_secret_basic`). Never put `openid` in `scope`: Keycloak's anonymous DCR policy rejects it
  and MCP does not use id_tokens.
* redirect URI `http://<redirectHost>:<callbackPort>/callback` (`OAUTH_REDIRECT_HOST` default
  `127.0.0.1`, `OAUTH_CALLBACK_PORT` default 4199). Register the *same host string* at the AS —
  `localhost` and `127.0.0.1` do not cross-match.
* persists client registration, tokens, PKCE verifier and `state` in
  `<MCP_AUTH_STORE_DIR | .mcp-auth>/<sha256(serverUrl+clientName)[:16]>.json` (mode 0600, git-ignored)
* `redirectToAuthorization(url)` (awaited by the SDK) **starts the loopback listener first**, then
  prints the URL and calls `openBrowser(url)`: `MCP_BROWSER_CMD` (e.g.
  `python3 scripts/browser-login.py --user alice --password password`) is spawned with the URL as
  its last argument and its output on stderr; otherwise `xdg-open`/`open`/`start`; nothing with
  `MCP_NO_BROWSER=1`. Nothing is bound when stored tokens work, so a second run never touches the
  callback port.
* `waitForCallback({ timeoutMs = 5 min })` → the authorization code. A callback is accepted only
  when its `state` equals the one the provider issued; anything else (no state issued yet, wrong
  state) is answered 400 and ignored — the listener keeps waiting for the real redirect. An
  `error` callback rejects; its text goes to stderr, never into the HTML page. Timeout, cancel and
  errors all close the listener and clear the timer, so the process can exit.
* `startCallbackListener()`, `cancelCallback()`, `callbackListening`, `expectedState()`,
  `clearTokens()`, `clearAll()`

`connectWithOAuth({ serverUrl, provider, clientName?, clientVersion?, timeoutMs? })` → `{ client, transport }`
does the whole dance: connect → on `UnauthorizedError` (the SDK already called
`redirectToAuthorization`) wait for the callback → `transport.finishAuth(code)` → connect again with
a **new** transport (the SDK closes the failed one). Second run: stored tokens (refresh token
included) are used, no browser opens, no listener starts, and the process exits as soon as the
client is closed.

`handleLogoutFlag(provider)` implements `--logout`; `clearTokens(provider)` forgets tokens only.

### `client/run.ts`

| Export | Purpose |
|---|---|
| `createClient(name, version?)` | an SDK `Client` |
| `serverUrlArg(defaultUrl, argv?)` | first positional CLI argument → `MCP_SERVER_URL` → the example's `publicUrl(PORT)` |
| `runDemo(client, { expectAdmin?, print? })` | lists tools, calls `whoami`, `add(2,3)`, `admin_only`, prints a compact report, returns `{ tools, whoami, add, adminOnly }` (each `{ name, isError, text, json? }`) |
| `printResult(example, result, extra?)` | prints the **last stdout line** `RESULT {"example","tools","whoami","add","adminOnly":"ok"\|"denied","extra"}` and returns the exit code: 0, or 2 when `EXPECT_ADMIN=ok\|denied` disagrees. Every client ends with `process.exit(printResult('NN', result))` after `terminateSession()` + `close()`; `scripts/smoke.ts` parses the line (`parseResultLine`) |
| `callTool`, `toolOutcome` | one tool call flattened to `{ isError, text, json? }` |

Human-readable output goes to stdout, diagnostics (connection messages, browser driver output) to
stderr; exit 1 on any error.

### `testing.ts`

| Export | Purpose |
|---|---|
| `startTestServer(app)` | ephemeral port on 127.0.0.1 → `{ baseUrl, server, close() }` (appends the 404/error handlers like `listen()`) |
| `freePort()` | an unused 127.0.0.1 port (for callback listeners in tests) |
| `rawRequest(url, { method?, headers?, body? })` | `node:http` request (Node's `fetch` ignores a custom `Host`, this does not) |
| `mcpPost(url, jsonRpc, headers?)` | POST with the mandatory `Accept`/`Content-Type` |
| `initializeSession(url, headers?)` | → `{ sessionId, response }` |
| `rawCallTool(url, sessionId, name, args?, headers?)` | raw `tools/call` → `{ response, result?, error? }` |
| `connectClient(url, { headers?, authProvider?, name? })` | SDK client → `{ client, transport, close() }` |
| `callTool(client, name, args?)` | → `{ name, isError, text, json? }` |
| `wwwAuthenticate(res)` | parses the Bearer challenge → `{ scheme, error, error_description, scope, resource_metadata }` |
| `expectOAuth401(res, { resourceMetadata?, scope?, error? })` | asserts status 401 + challenge fields; `resourceMetadata: false` asserts it is absent (01/02) |
| `testKeyPair(alg?)` | RS256/ES256 key pair with `kid` → `{ privateKey, publicJwk, jwks, kid, alg }` |
| `mintLocalJwt({ key, kid?, alg?, issuer, audience, sub?, scope?, roles?, expiresIn?, azp?, username?, extraClaims? })` | a Keycloak-shaped token signed locally (hermetic negative matrices) |
| `decodeJwtPayload(token)` | payload without verification (inspecting claims in tests) |
| `spawnExample(script, env?, { readyUrl?, timeoutMs?, args?, port? })` | runs `tsx <script>` (or `uv run … python <script>.py`) from the repo root, waits for `readyUrl` (default `<publicUrl(port)>/healthz`) → `{ child, stdout(), stderr(), exited, stop() }` |
| `waitForHttp(url, { timeoutMs?, okStatus? })` | polls until the URL answers |
| `isKeycloakUp()` | discovery document reachable within 2 s (logs `skipped: Keycloak not reachable at …` once); with `REQUIRE_KEYCLOAK=1` it throws instead |
| `keycloakPasswordToken({ username, password, scope?, clientId = 'mcp-test' })` | password grant — tests only (`mcp-cli` refuses it) |
| `keycloakClientCredentials({ clientId, clientSecret, scope? })` | client credentials grant |

Keycloak-dependent tests: `const up = await isKeycloakUp(); describe.skipIf(!up)(…)`.
`npm test` skips them when Keycloak is down; `npm run test:kc` (CI) fails instead.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/kc.sh up\|down\|reset\|logs\|status\|wait\|keys\|render` | Keycloak lifecycle; `keys` generates the `private_key_jwt` key pair (`keycloak/.generated/`, git-ignored); `reset` re-imports the realm after a template change |
| `scripts/browser-login.py <url>` | headless Playwright driver for the Keycloak / embedded-AS login (+ consent) pages; used through `MCP_BROWSER_CMD` |
| `scripts/smoke.ts` (`npm run smoke [-- 00 04] [--no-keycloak] [--keep]`) | end-to-end matrix on the real ports: spawns servers, runs the clients with the browser driver, parses `RESULT` lines, runs the headline negative probe, writes `test-results/smoke-*.json` |
| `scripts/gen-certs.sh` (`npm run ex:08:certs`) | demo PKI for the mTLS example (`OUT_DIR`, `PUBLIC_HOST` overridable) |

## Ports

| Example | Port | Env override |
|---|---|---|
| 00 baseline | 4100 | `PORT_00` / `MCP_PORT` |
| 01 … 11 | 4101 … 4111 (`docs/design.md` §3) | `PORT_<nn>` / `MCP_PORT` |
| 02 issuer / 09 internal / 10 downstream | 4192 / 4119 / 4190 | `PORT_02_ISSUER` / `PORT_09_INTERNAL` / `PORT_10_DOWNSTREAM` |
| OAuth callback listener (client side) | 4199 | `OAUTH_CALLBACK_PORT` |
| Keycloak | 8180 | `KEYCLOAK_PORT` |

## Environment variables

| Variable | Default | Used by |
|---|---|---|
| `PUBLIC_HOST` | first non-loopback IPv4 | every URL (`publicUrl`, `keycloak`, callback URLs) |
| `KEYCLOAK_URL` | `http://<PUBLIC_HOST>:<KEYCLOAK_PORT>` | `keycloak()` |
| `KEYCLOAK_PORT` | `8180` | `keycloak()`, `scripts/kc.sh` |
| `KEYCLOAK_REALM` | `mcp` | `keycloak()` |
| `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` | `admin` / `admin` (DEMO) | `adminLogoutUser()`, compose |
| `MCP_AUDIENCE` | `mcp-server` | `audiences()` → `createKeycloakVerifier` |
| `MCP_ALLOWED_HOSTS` | – | extra Host header values (comma list) |
| `MCP_LOG` | `1` | `0` silences the request log |
| `MCP_RATE_LIMIT` | `1` | `0` disables the SDK auth router's rate limits (set by vitest + smoke) |
| `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` | `1` (set by `env.ts`) | SDK issuer check — demo only |
| `MCP_SERVER_URL` | example's `publicUrl(PORT)` | `serverUrlArg()` in every client |
| `EXPECT_ADMIN` | – | `ok` / `denied` → `printResult()` exit code 2 on mismatch |
| `OAUTH_CALLBACK_PORT` | `4199` | `CliOAuthProvider` |
| `OAUTH_REDIRECT_HOST` | `127.0.0.1` | `CliOAuthProvider` redirect URI host |
| `OAUTH_CLIENT_ID` / `OAUTH_CLIENT_SECRET` | – (DCR) | `CliOAuthProvider` static (pre-registered) client |
| `MCP_AUTH_STORE_DIR` | `<repo>/.mcp-auth` | `CliOAuthProvider` token store |
| `MCP_BROWSER_CMD` | – | `openBrowser()`: command that receives the authorization URL |
| `MCP_NO_BROWSER` | – | `1` prints the authorization URL only |
| `REQUIRE_KEYCLOAK` | – | `1` → `isKeycloakUp()` throws instead of skipping (`npm run test:kc`) |
| `MCP_API_KEYS`, `MCP_API_KEY`, `MCP_TOKEN`, `DEMO_USER`, `DEMO_PASSWORD`, `MCP_SERVICE_CLIENT_SECRET`, `MCP_SERVER_CLIENT_SECRET`, `INTROSPECTION_TTL_SECONDS`, `GATEWAY_INTERNAL_SECRET`, `MTLS_CLIENT` | see `.env.example` | examples 01 / 02 / 05 / 07 / 08 / 09 / 10 |

## Known limitations (by design, for a demo)

* **Sessions are in-memory** — one process, no sharing, gone on restart. Idle sessions are swept
  after `sessionIdleMs` (default 30 min) unless their GET notification stream is open; use
  `stateless: true` behind a load balancer.
* **Subject binding uses `extra.sub` only** (falling back to `clientId`). Two clients acting for the
  same user may reuse each other's session id; there is no privilege impact because
  `extra.authInfo` is re-derived from the token on every request.
* **One callback port per machine.** Two example clients that both need a browser login at the same
  time collide on `OAUTH_CALLBACK_PORT`; run them one after another (cached-token runs do not bind
  the port at all). `scripts/smoke.ts` runs examples sequentially for this reason.
* **Dynamically registered Keycloak clients** (default in 03/04/06) only receive the realm's default
  DCR scopes (`basic` + `mcp:tools`): their tokens carry no `preferred_username` / `realm_access`,
  so `whoami.extra.username` is undefined and `keycloakEffectiveScopes()` can never grant
  `mcp:admin` to them. Use the pre-registered `mcp-cli` client (`OAUTH_CLIENT_ID=mcp-cli`) when you
  need admin. Anonymous DCR also leaves a client behind in the realm per machine; `npm run kc:reset`
  cleans up.
* `listen()` is plain HTTP; example 08 (mTLS) builds its own `https.Server` and passes it in.
* The request log includes the query string (`/authorize?state=…` in 03/06) — fine for a demo,
  trim it in production.
