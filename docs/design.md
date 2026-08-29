# mcp-auth-demo — design (synthesis of three independent architecture proposals)

Status: **decided**. This document is the single source of truth for the implementation phase.
An implementer of one example needs only this file plus the SDK notes in `docs/sdk-notes.md`.
Everything marked **(verified)** was checked on the dev box on 2026-08-29 against the installed
`@modelcontextprotocol/sdk` 1.30.0, the running `mcp-auth-demo-keycloak` container
(Keycloak 26.7.2, host port 8180, realm imported from the current template), Python `mcp` 2.1.1
resolved by `uv`, Python Playwright 1.61 with cached Chromium, and the existing scaffold on branch
`feat/keycloak-shared`.

Repo root: `<repo>` (public repo `c0de-ch/mcp-auth-demo`, MIT).
Dev box LAN IP: `192.168.78.87` (= `PUBLIC_HOST` in the local `.env`).

---

## 0. What already exists (baseline for every implementer)

The scaffold on `feat/keycloak-shared` already contains, tested and type-checked (**verified**:
`npm run typecheck` clean, 15/15 tests green):

| Path | State | Keep? |
|---|---|---|
| `package.json` (single package, `tsx`, `vitest` 4, TS 7, `ex:00:*`, `kc:*` scripts) | committed/modified | keep; Phase 0 adds all remaining scripts + `undici` |
| `tsconfig.json` (`NodeNext`, `allowImportingTsExtensions`, `noEmit`) | committed | keep |
| `vitest.config.ts` (`pool: forks`, `fileParallelism: false`, 30 s timeouts) | untracked | keep; Phase 0 adds `env: { MCP_RATE_LIMIT: '0' }` |
| `.env.example`, `.gitignore`, `.editorconfig`, `LICENSE`, `README.md` (WIP stub) | committed | keep; Phase 0 extends `.env.example` |
| `.github/workflows/ci.yml` (typecheck, Keycloak via compose, `npm test`) | untracked | keep; Phase 3 adds Python + Playwright + smoke |
| `keycloak/docker-compose.yml`, `keycloak/realm-mcp.template.json`, `keycloak/README.md`, `scripts/kc.sh` | committed | keep; Phase 0 applies the realm deltas in §7.3 |
| `src/shared/env.ts` | untracked | keep as is (API in §5.1) |
| `src/shared/http.ts` (`createApp`, `mountMcp`, `listen`, `subjectOf`, `allowedHostnames`) | untracked | keep as is |
| `src/shared/tools.ts` (`createDemoServer`, `requireScope`, `formatAuthInfo`, `SCOPE_TOOLS`, `SCOPE_ADMIN`) | untracked | keep as is |
| `src/shared/jwt.ts` + `jwt.test.ts` (`createJwtVerifier`, `keycloakEffectiveScopes`, `authInfoFromPayload`, `tokenScopes`, `describeJoseError`) | untracked | keep as is |
| `src/shared/testing.ts` (`startTestServer`, `rawRequest`, `mcpPost`, `initializeSession`, `rawCallTool`, `connectClient`, `callTool`, `toolOutcome`, `isKeycloakUp`, `keycloakPasswordToken`, `keycloakClientCredentials`, `MCP_HEADERS`) | untracked | keep; Phase 0 adds helpers (§5.7) |
| `src/shared/client/run.ts` (`createClient`, `runDemo`) and `src/shared/client/oauth-cli.ts` (`CliOAuthProvider`, `connectWithOAuth`, `openBrowser`, `handleLogoutFlag`) | untracked | keep; Phase 0 adds `printResult` and `MCP_BROWSER_CMD` |
| `examples/00-baseline-no-auth/{server,client,server.test}.ts` | untracked | keep — it is the reference implementation of the conventions in §4 |
| `docs/plan.md` | committed | superseded by this document; Phase 3 replaces its body with a pointer + the final catalog |

Rule for the parallel phase: **`src/shared/**`, `package.json`, `vitest.config.ts`, `.env.example`,
`keycloak/**`, `scripts/**` are frozen after Phase 0.** An example agent that believes it needs a
shared change writes the need into its example README under "Integration notes" and works around
it locally; the integrator applies shared changes in Phase 3.

---

## 1. Judgement of the three proposals

Scale 1–5 per criterion: coverage of distinct approaches / feasibility with SDK 1.30.0 / DX /
security rigor / verifiability.

| Lens | Cov. | Feas. | DX | Sec. | Verif. | Notes |
|---|---|---|---|---|---|---|
| Spec purist | 5 | 3 | 3 | 4 | 5 | Best spec framing (CONFORMANT / PARTIAL / OUTSIDE-SPEC / LEGACY labels, discovery traces, metadataHandler-only PRM, docs-only catalog). Over-scoped: 13 runnable examples, CIMD hosted over a dev-CA HTTPS server, seven `audience:exNN` Keycloak scopes and a per-example realm blow-up, ROPC harness client, scope-gate middleware, session binding — each is right in isolation, together they double the realm surface and the shared code. Some realm details admittedly unverified. |
| DX pragmatist | 4 | 5 | 5 | 3 | 4 | Cleanest developer story (two files per example, `git diff` against the baseline, one logical audience, verified Keycloak gotchas: no `${env}` in realm imports, `basic` scope for `sub`, `openid` rejected by the DCR policy, exact ClientRegistrationPolicy keys, resource-indicators feature breaks the SDK client). Renumbers the catalog against the existing scaffold; weaker rejection-path coverage; `mcp-test` direct-grant client is the right call. |
| Security engineer | 4 | 4 | 4 | 5 | 5 | Strongest threat models and negative-test matrices, hermetic testing idea, header-injection observation on `bearerAuth.js`, verified token-exchange/introspection audience rules, compatible with the existing scaffold and its numbering. Chose `fastmcp` for the Python twin (pins `mcp<2`; the official SDK is the better teaching choice); the full FakeAS is more shared code than the parallel phase should depend on. |

**Winner: the security engineer's structure** (it matches the scaffold's numbering, the realm and
the shared modules that already exist), **with the DX pragmatist's single-audience realm and
two-file examples, and the spec purist's docs discipline** (spec grade per page, metadataHandler-only
PRM on pure resource servers, discovery traces, the docs-only pattern catalog).

---

## 2. Decisions

| Question | Decision | Reasoning |
|---|---|---|
| Catalog size | **12 runnable examples, `00`–`11`** | Upper bound of the brief; the scaffold, `.env.example` and the realm README already reference this numbering. |
| Token exchange (10) | **Implement** | **(verified)** on the running realm: `mcp-server` (attribute `standard.token.exchange.enabled=true`) exchanged alice's token for `aud=downstream-api, azp=mcp-server, sub=<alice>`; requires `scope=downstream-api` in the request (without it Keycloak answers `invalid_request: Requested audience not available: downstream-api`) and `mcp-server` in the subject token's `aud` (provided by the `mcp:tools` scope's audience mapper). |
| Introspection (07) | **Implement** | **(verified)** `POST …/token/introspect` with `mcp-server` Basic auth returns `active:true, aud:"mcp-server", scope, username`. Keycloak only answers `active:true` when the introspecting client is in the token audience — which the realm already guarantees. Demonstrates the revocation-latency trade-off against 04. |
| Python twin (11) | **Implement with the official `mcp==2.1.1`**, not `fastmcp` | **(verified)** `mcp.server.MCPServer(token_verifier=…, auth=AuthSettings(issuer_url, resource_server_url, required_scopes))`, `TokenVerifier.verify_token → AccessToken(token, client_id, scopes, expires_at, resource, subject, claims)`, `create_protected_resource_routes`, `streamable_http_app(host=…)`, `mcp.client.auth.OAuthClientProvider` and `streamable_http_client` all exist. `fastmcp` 3.4.7 pins `mcp<2` (all three proposals agree) and hides the mechanics; it is mentioned in the docs page as a variation. |
| stdio baseline | **Docs-only** (`docs/patterns.md` §"stdio", with a complete 30-line listing) | The spec itself says stdio servers SHOULD NOT implement HTTP authorization; the comparison is about HTTP auth. It costs one docs section, not an example slot. |
| Audience model for Keycloak examples | **One logical audience `mcp-server`** (existing realm), verifier accepts a list via `MCP_AUDIENCE` | Keycloak ignores RFC 8707 `resource` **(verified**: `resource=http://192.168.78.87:4104/mcp` on the token request leaves `aud="mcp-server"`), and the experimental `resource-indicators` feature rejects unregistered resources (DX + security both verified `invalid_target`). Per-example URL audiences would add seven scopes + port-dependent mappers to the realm for little teaching value. Example 02 shows the strict URL-audience form; `docs/patterns.md` documents strict RFC 8707. Cross-example isolation is still demonstrated where it matters: MCP tokens are rejected by the downstream API (aud `downstream-api`) and exchanged tokens are rejected by MCP servers. |
| PRM on pure resource servers | `metadataHandler` at the path-aware PRM URL **only** (`src/shared/prm.ts`); no `mcpAuthMetadataRouter` | `mcpAuthMetadataRouter` unconditionally mirrors the AS document at `<rs-origin>/.well-known/oauth-authorization-server` **(verified** in `router.js`), which contradicts RFC 8414 issuer/URL matching. The SDK client never needs the mirror (it reads `authorization_servers` from the PRM). `mcpAuthRouter` (03, 06) still serves both, correctly, because there the MCP origin *is* the AS. |
| Client registration default | **DCR by default** in 03/04/06 (`OAUTH_CLIENT_ID=mcp-cli` switches to the pre-registered public client) | Shows the full spec flow with no prior relationship; the provider persists the registration under `.mcp-auth/` so one client is created per machine, not per run. **(verified)** anonymous DCR on the realm returns a public client with `scope: mcp:tools`; `openid` is rejected by the Allowed Client Scopes policy (`insufficient_scope`). |
| CIMD (SEP-991) | Docs-only | Needs an HTTPS-hosted metadata document (`isHttpsUrl` on the client) and Keycloak's experimental `cimd` feature; not demonstrable on a plain-HTTP LAN. |
| Runtime step-up (HTTP 403 `insufficient_scope` on `tools/call`) | Docs-only in v0.1 | Tools return `isError` for missing scope (existing `tools.ts` contract). The 403-upscoping path is described with the exact header in `docs/patterns.md`; it can become a shared middleware later. |
| private_key_jwt (05 variant) | **Stretch** inside 05 (`--auth private-key-jwt`); realm carries `mcp-service-jwt`; docs page covers it either way | Keycloak attribute name for the imported public key (`jwt.credential.public.key`) is unverified; if the realm import rejects it, 05 ships the shared-secret grant only and the variant stays documented. |
| Test tokens without a browser | Dedicated **`mcp-test`** public client with the password grant (test-only), `mcp-cli` gets `directAccessGrantsEnabled=false` | Keeps the story "mcp-cli is a public PKCE client" honest. The ROPC grant is removed from OAuth 2.1 and is labelled test-only everywhere. |
| Hermetic vs Keycloak-backed tests | Both: every JWT example's `buildApp()` accepts `{ issuer, jwks, audience }` overrides so negative matrices run with in-process `jose` keys; positive paths and AS-dependent flows use Keycloak with `describe.skipIf(!(await isKeycloakUp()))` | CI already runs Keycloak; a full FakeAS is more shared code than the parallel phase should wait for. |
| Browser automation | Python Playwright (`scripts/browser-login.py`), invoked by the client through `MCP_BROWSER_CMD` | Playwright 1.61 + Chromium already cached; the `webapp-testing` skill prescribes Python Playwright; no 300 MB Node browser download. |
| mTLS client | `undici` (`Agent` + undici's own `fetch`) passed as the transport `fetch` option | Node's global `fetch` has no certificate option; mixing Node's bundled undici with an npm `Agent` is version-fragile. `undici` is added in Phase 0. |
| Rate limits of the SDK auth router | Enabled by default; `MCP_RATE_LIMIT=0` disables (set in `vitest.config.ts` and by smoke) | Demo traffic never trips 50 req / 15 min; test loops do. |

---

## 3. Final catalog and port plan

Taken host ports **(verified with `ss`)**: 22 53 631 3002 3100 3200 5432 5433 6379 7233 8080 **8180 (our Keycloak, already running)** 9000 9001 9090 9091 9110 11434 18181 18443 45299. Nothing below collides. Every port is overridable; defaults are what the realm template and smoke use.

| # | Directory | Approach | Category / spec grade | Keycloak? | Port (env) | Extra ports | Effort |
|---|---|---|---|---|---|---|---|
| 00 | `examples/00-baseline-no-auth` | Unauthenticated Streamable HTTP pair — the reference diff base | baseline (auth is OPTIONAL in MCP) | no | 4100 `PORT_00` | – | S (done) |
| 01 | `examples/01-api-key` | Static API key as Bearer secret; hashed key table, per-key scopes | shared secret (OUTSIDE-SPEC; RFC 6750 syntax only) | no | 4101 `PORT_01` | – | S |
| 02 | `examples/02-jwt-local` | Self-issued RS256 JWT verified via a JWKS URL served by a tiny local issuer; strict URL audience | self-issued token (OUTSIDE-SPEC: no AS/discovery) | no | 4102 `PORT_02` | issuer 4192 `PORT_02_ISSUER` | M |
| 03 | `examples/03-oauth-embedded-as` | MCP server **is** the OAuth 2.1 AS: `mcpAuthRouter`, login+consent pages, DCR, PKCE, refresh rotation, revocation | OAuth 2.1, AS co-located (CONFORMANT) | no | 4103 `PORT_03` | – | L |
| 04 | `examples/04-keycloak-resource-server` | **Spec-recommended pattern**: Keycloak AS, MCP server = pure RS (PRM + JWKS) | OAuth 2.1, external AS (CONFORMANT on the MCP side; PARTIAL: Keycloak ignores `resource`) | yes | 4104 `PORT_04` | – | M |
| 05 | `examples/05-keycloak-client-credentials` | M2M: service account, `client_credentials` (client_secret_basic; private_key_jwt as stretch) | OAuth 2.1 M2M (CONFORMANT) | yes | 4105 `PORT_05` | – | S/M |
| 06 | `examples/06-oauth-proxy-keycloak` | MCP server as OAuth facade (`ProxyOAuthServerProvider`), DCR passthrough | OAuth 2.1 proxied AS (TRANSITIONAL) | yes | 4106 `PORT_06` | – | M |
| 07 | `examples/07-token-introspection` | RFC 7662 introspection with TTL cache; revocation visible immediately | OAuth 2.1 stateful validation (CONFORMANT) | yes | 4107 `PORT_07` | – | M |
| 08 | `examples/08-mtls` | Mutual TLS: certificate = credential; `req.auth` set without bearer | transport-level (OUTSIDE-SPEC) | no | 4108 `PORT_08` (https) | – | M |
| 09 | `examples/09-auth-gateway` | Gateway validates tokens + serves PRM, reverse-proxies with a signed identity assertion to an internal server | infrastructure trust boundary | yes | 4109 `PORT_09` | internal 4119 `PORT_09_INTERNAL` | M |
| 10 | `examples/10-token-exchange-downstream` | On-behalf-of: RFC 8693 exchange (Keycloak v2) to call a downstream API as the user | OAuth 2.1 delegation (CONFORMANT; PARTIAL: `audience=` client id) | yes | 4110 `PORT_10` | downstream 4190 `PORT_10_DOWNSTREAM` | L |
| 11 | `examples/11-python-mcp-keycloak` | Python twin of 04 with the official `mcp` 2.1.1; TS client unchanged | language twin / interop (CONFORMANT) | yes | 4111 `PORT_11` | – | M |

Other ports: Keycloak **8180** (`KEYCLOAK_PORT`; container 8080; management 9000 stays inside the
bridge network — never `network_mode: host`, host 9000 is taken). Client-side OAuth callback
listener **4199** (`OAUTH_CALLBACK_PORT`; registered in the realm for `localhost`, `127.0.0.1` and
`PUBLIC_HOST`). Vitest always uses ephemeral ports (`startTestServer` → `listen(0)`), so tests and
running demos coexist. Reserved: 4112–4118, 4191, 4193–4198.

---

## 4. Conventions every example follows

### 4.1 Files per example

```
examples/NN-slug/
  server.ts        exports buildApp(overrides?) and PORT; listens only when isMain(import.meta)
  client.ts        ≤ 40 lines: builds transport/provider, runs runDemo, prints the RESULT line
  server.test.ts   vitest: positive path + the negative matrix of §6 (hermetic where possible,
                   describe.skipIf(!(await isKeycloakUp())) for Keycloak-backed parts)
  README.md        run / verify / break-it commands, env table, link to docs/NN-slug.md
  <extra>.ts       only for a separate role: issuer.ts (02), provider.ts + pages.ts (03),
                   gateway.ts + all.ts (09), downstream.ts + all.ts (10), server.py/client.py/pyproject.toml (11)
  certs/           08 only, generated, git-ignored
```

### 4.2 Import order (structural)

First import of every `server.ts`, `client.ts`, `*.test.ts` and any extra entrypoint is
`import { … } from '../../src/shared/env.ts'` (or the bare `import '../../src/shared/env.ts'`).
`env.ts` runs `dotenv/config` and sets `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` **before**
`@modelcontextprotocol/sdk/server/auth/router.js` is evaluated — that module reads the flag once at
load time and otherwise throws `Issuer URL must be HTTPS` for `http://192.168.x.x`.
`tests/conventions.test.ts` (Phase 0) fails the build when any entrypoint violates this.

### 4.3 `buildApp` signature

```ts
export const PORT = port('PORT_NN', 41NN);
export interface Overrides { /* example-specific; JWT examples: issuer?, jwks?, audience?, requiredScopes? */ }
export function buildApp(overrides?: Overrides): Express            // sync when no discovery is needed
export async function buildApp(overrides?: Overrides): Promise<Express> // Keycloak examples (discovery at startup)
if (isMain(import.meta)) await listen(await buildApp(), { port: PORT, name: 'NN-slug' });
```

Tests call `startTestServer(await buildApp({ …test keys… }))`. `listen()` binds `0.0.0.0` and prints
the canonical URL built from `PUBLIC_HOST`.

### 4.4 Client output contract (consumed by `scripts/smoke.ts`)

Human-readable lines from `runDemo()` on stdout, all diagnostics on **stderr**, and as the **last
stdout line** `RESULT <json>` produced by `printResult()` (§5.6):

```
RESULT {"example":"04","tools":["add","admin_only","whoami"],"whoami":{…},"add":"5","adminOnly":"ok"|"denied","extra":{…}}
```

Exit code 0 when the demo completed; 2 when `EXPECT_ADMIN` (`ok|denied`) was set and did not match;
1 on any error. Every client accepts `MCP_SERVER_URL` (or argv[2]) to point at another machine.

### 4.5 Naming

Example dirs `NN-kebab-slug`; env vars `UPPER_SNAKE`; ports `PORT_NN[_ROLE]`; Keycloak clients
`mcp-cli`, `mcp-test`, `mcp-service`, `mcp-service-jwt`, `mcp-server`, `downstream-api`; scopes
`mcp:tools`, `mcp:admin`, `downstream-api`; users `alice`, `bob`; realm roles `mcp-user`,
`mcp-admin`; tools `whoami`, `add`, `admin_only` (+ at most one example-specific tool).
Server `name` = `NN-slug`. Demo credentials are always labelled `DEMO` in `.env.example`.

### 4.6 Security hygiene every example keeps

* Never log a token, code, secret or `Authorization` header; log `sha256(token).slice(0,8)` at most.
* Verifiers throw only `InvalidTokenError` (→ 401 + `WWW-Authenticate`) or `InsufficientScopeError`
  (→ 403); a plain `Error` becomes a 500 without the header and silently breaks client discovery.
* Error messages passed to those errors are **static strings** — `bearerAuth.js` interpolates
  `error.message` unescaped into the `WWW-Authenticate` header **(verified)**.
* `AuthInfo.expiresAt` is mandatory (seconds); API keys / certs synthesise it.
* The session↔principal binding in `mountMcp` stays on (a token of another subject on an existing
  session → 403).

---

## 5. Shared modules — exact API

Paths are absolute from the repo root. "exists" = present on `feat/keycloak-shared` today;
"add" = Phase 0 work. Nothing else goes into `src/shared` during the parallel phase.

### 5.1 `src/shared/env.ts` (exists, unchanged)

```ts
export function env(name: string, fallback?: string): string          // trims; throws when missing and no fallback
export function port(envName: string, fallback: number): number
export function detectLanAddress(): string | undefined                 // first non-internal IPv4
export function publicHostSource(): 'env' | 'auto-detected' | 'fallback'
export function publicHost(): string                                   // PUBLIC_HOST || LAN IPv4 || '127.0.0.1'
export function publicUrl(portNumber: number, path = '/mcp'): string   // http://<host>:<port><path>, no trailing slash
export interface KeycloakEndpoints { baseUrl; realm; issuer; discoveryUrl; jwksUri; tokenEndpoint; authorizationEndpoint; introspectionEndpoint; registrationEndpoint }
export function keycloak(): KeycloakEndpoints                          // from KEYCLOAK_URL | http://<host>:<KEYCLOAK_PORT|8180>, KEYCLOAK_REALM|mcp
export function isMain(meta: ImportMeta): boolean
```
Side effects at import: `dotenv/config`; `process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL ??= '1'`.

### 5.2 `src/shared/http.ts` (exists, unchanged)

```ts
export function subjectOf(authInfo: AuthInfo | undefined): string | undefined   // extra.sub ?? clientId
export function allowedHostnames(extra?: string[]): string[]                    // PUBLIC_HOST, localhost, 127.0.0.1, [::1], MCP_ALLOWED_HOSTS
export function createApp(opts?: { allowedHosts?: string[]; log?: boolean }): Express
   // express.json(1mb) · stderr request log (MCP_LOG=0 disables) · hostHeaderValidation · GET /healthz → {ok:true}
export function mountMcp(app: Express, opts: { path?: string /* '/mcp' */; createServer: () => McpServer; auth?: RequestHandler | RequestHandler[]; stateless?: boolean }): void
   // stateful sessions (Map<sessionId,{transport,server,subject}>), POST/GET/DELETE guarded by `auth`,
   // initialize-only first POST (400 otherwise), unknown session 404 -32001, foreign subject 403,
   // handleRequest(req,res,req.body); stateless mode: transport+server per POST, GET/DELETE 405
export function listen(app: Express, opts: { port: number; name: string; path?: string }): Promise<http.Server>  // binds 0.0.0.0, prints banner
```

### 5.3 `src/shared/tools.ts` (exists, unchanged)

```ts
export const SCOPE_TOOLS = 'mcp:tools'; export const SCOPE_ADMIN = 'mcp:admin';
export function requireScope(authInfo: AuthInfo | undefined, scope: string): boolean
export function formatAuthInfo(authInfo: AuthInfo | undefined): Record<string, unknown>   // token omitted; {anonymous:true} when absent
export function createDemoServer(opts: { name: string; version?: string }): McpServer
   // whoami → formatAuthInfo(extra.authInfo); add({a,b}); admin_only → ok iff scopes ⊇ ['mcp:admin'] else isError 'insufficient_scope: …'
```
Contract: tools look only at `extra.authInfo.scopes`; the verifier computes *effective* scopes
(e.g. `keycloakEffectiveScopes` keeps `mcp:admin` only for users with realm role `mcp-admin`).
An example that needs one extra tool registers it on the returned `McpServer` in its own `server.ts`.

### 5.4 `src/shared/jwt.ts` (exists, unchanged)

```ts
export type JwksSource = string | URL | JSONWebKeySet | JWK | CryptoKey | KeyObject
export interface JwtVerifierOptions { issuer: string; audience: string | string[]; jwks: JwksSource; requiredScopes?: string[]; effectiveScopes?: (p: JWTPayload) => string[]; clockToleranceSec?: number /* 5 */ }
export function createJwtVerifier(o: JwtVerifierOptions): OAuthTokenVerifier   // jose jwtVerify(iss, aud, clockTolerance); every failure → InvalidTokenError('JWT rejected: <static reason>'); missing required scope → InsufficientScopeError
export function tokenScopes(p: JWTPayload): string[]                            // `scope` (space-separated) or `scp` array
export function keycloakEffectiveScopes(p: JWTPayload): string[]
export function authInfoFromPayload(p: JWTPayload, token: string, eff?): AuthInfo // clientId = azp ?? client_id ?? sub; expiresAt = exp; resource = first URL-shaped aud; extra = {sub, username, email, roles, claims}
export function describeJoseError(e: unknown): string
```
Note for implementers: the jose `algorithms` allow-list is not exposed; RS256 from Keycloak and
RS256/ES256 local keys are what the examples use. `alg:none` and HS256-with-public-key attacks are
rejected by jose's key-type checks (test it in 02).

### 5.5 `src/shared/prm.ts` (add)

```ts
export interface PrmOptions { resourceUrl: string; authorizationServers: string[]; scopesSupported?: string[]; resourceName?: string; bearerMethodsSupported?: string[] /* ['header'] */ }
export function protectedResourceMetadata(o: PrmOptions): OAuthProtectedResourceMetadata   // { resource, authorization_servers, scopes_supported, resource_name, bearer_methods_supported }
export function mountProtectedResourceMetadata(app: Express, o: PrmOptions): string
   // app.use(`/.well-known/oauth-protected-resource${pathname of resourceUrl}`, metadataHandler(doc)) — path-aware per RFC 9728,
   // NO /.well-known/oauth-authorization-server mirror; returns resourceMetadataUrl(o.resourceUrl)
export function resourceMetadataUrl(resourceUrl: string): string   // = getOAuthProtectedResourceMetadataUrl(new URL(resourceUrl))
```
Used by 04, 05, 07, 09 (gateway), 10. 03/06 use `mcpAuthRouter` instead. Test: `src/shared/prm.test.ts`.

### 5.6 `src/shared/client/run.ts` (exists; add `printResult`)

```ts
export function createClient(name: string, version = '0.1.0'): Client
export interface ToolOutcome { name: string; isError: boolean; text: string; json?: unknown }
export function callTool(client: Client, name: string, args?: Record<string, unknown>): Promise<ToolOutcome>   // moved here from testing.ts (testing.ts re-exports it)
export function toolOutcome(name: string, result: CallToolResult): ToolOutcome
export interface DemoResult { tools: string[]; whoami: ToolOutcome; add: ToolOutcome; adminOnly: ToolOutcome }
export function runDemo(client: Client, opts?: { expectAdmin?: boolean; print?: (line: string) => void }): Promise<DemoResult>
// add:
export function printResult(example: string, result: DemoResult, extra?: Record<string, unknown>): number
   // prints `RESULT {"example","tools","whoami":whoami.json??whoami.text,"add":add.text,"adminOnly":"ok"|"denied","extra"}` on stdout;
   // returns the exit code per §4.4 using process.env.EXPECT_ADMIN ('ok'|'denied'|unset)
```

### 5.7 `src/shared/client/oauth-cli.ts` (exists; one addition)

```ts
export class CliOAuthProvider implements OAuthClientProvider {
  constructor(o: { serverUrl: string; scope?: string /* 'mcp:tools' */; clientName?: string; staticClient?: { client_id; client_secret? } /* default: env OAUTH_CLIENT_ID/OAUTH_CLIENT_SECRET */; redirectHost?: string /* env OAUTH_REDIRECT_HOST | '127.0.0.1' */; callbackPort?: number /* env OAUTH_CALLBACK_PORT | 4199 */; storeDir?: string /* env MCP_AUTH_STORE_DIR | <repo>/.mcp-auth (add the env knob in Phase 0) */ })
  get redirectUrl(): string                       // http://<redirectHost>:<callbackPort>/callback
  get clientMetadata(): OAuthClientMetadata       // public client, token_endpoint_auth_method 'none', grant_types code+refresh
  state(); clientInformation(); saveClientInformation(); tokens(); saveTokens(); saveCodeVerifier(); codeVerifier(); invalidateCredentials()
  redirectToAuthorization(url: URL): void         // prints "==> Authorization required…", then openBrowser(url) unless MCP_NO_BROWSER=1
  waitForCallback(o?: { timeoutMs? }): Promise<string>   // loopback listener (127.0.0.1, or 0.0.0.0 when redirectHost is not loopback); validates state
  cancelCallback(); expectedState(); clearTokens(); clearAll(); readonly storeFile
}
export function openBrowser(url: string): void    // add: if MCP_BROWSER_CMD is set, spawn `sh -c "$MCP_BROWSER_CMD '<url>'"` (detached, stdio inherit → stderr) instead of xdg-open/open
export function handleLogoutFlag(provider: CliOAuthProvider, argv?: string[]): boolean   // `--logout` wipes the store
export function connectWithOAuth(o: { serverUrl: string; provider: CliOAuthProvider; clientName?; clientVersion?; timeoutMs? }): Promise<{ client: Client; transport: StreamableHTTPClientTransport }>
   // connect → on UnauthorizedError wait for the callback → transport.finishAuth(code) → NEW transport → connect
```
Store file: `.mcp-auth/<sha256(serverUrl+clientName)[0:16]>.json`, mode 0600, git-ignored.

### 5.8 `src/shared/keycloak.ts` (add)

```ts
export const KC = { clients: { cli: 'mcp-cli', test: 'mcp-test', service: 'mcp-service', serviceJwt: 'mcp-service-jwt', server: 'mcp-server', downstream: 'downstream-api' }, scopes: { tools: 'mcp:tools', admin: 'mcp:admin', downstream: 'downstream-api' }, audience: 'mcp-server', roles: { user: 'mcp-user', admin: 'mcp-admin' } } as const
export function audiences(): string[]                                   // env MCP_AUDIENCE (comma list) | [KC.audience]
export async function discoverKeycloak(issuer = keycloak().issuer): Promise<OAuthMetadata>
   // GET <issuer>/.well-known/openid-configuration parsed with the LOOSE OAuthMetadataSchema (keeps jwks_uri, introspection_endpoint,
   // revocation_endpoint, registration_endpoint, end_session_endpoint); asserts code_challenge_methods_supported ⊇ ['S256']; cached per issuer
export function createKeycloakVerifier(o?: { metadata?: OAuthMetadata; requiredScopes?: string[]; audience?: string[] }): Promise<OAuthTokenVerifier>
   // = createJwtVerifier({ issuer: metadata.issuer, audience: audience ?? audiences(), jwks: metadata.jwks_uri, requiredScopes, effectiveScopes: keycloakEffectiveScopes })
export function basicAuth(clientId: string, secret: string): string     // 'Basic …'
export async function introspect(token: string, o: { clientId: string; clientSecret: string; metadata?: OAuthMetadata; fetchFn?: typeof fetch }): Promise<IntrospectionResponse>  // { active, sub?, username?, client_id?, scope?, aud?, exp?, realm_access?, … }
export async function exchangeToken(o: { subjectToken: string; audience: string; scope?: string; clientId: string; clientSecret: string; metadata?: OAuthMetadata; fetchFn? }): Promise<OAuthTokens>
   // grant_type=urn:ietf:params:oauth:grant-type:token-exchange, subject_token_type=…:access_token, requested_token_type=…:access_token; throws KeycloakError{error,error_description,status} on non-2xx
export async function revokeToken(token: string, o: { clientId: string; clientSecret?: string; tokenTypeHint?: 'access_token'|'refresh_token'; metadata? }): Promise<void>   // RFC 7009 revocation_endpoint
export async function adminLogoutUser(username: string): Promise<void>  // admin REST (KC_ADMIN_USER/PASSWORD, realm master) → DELETE all sessions of the user; used by 07's revoke script and tests
```
Test: `src/shared/keycloak.test.ts` (Keycloak-backed, skipIf) — discovery issuer equals `keycloak().issuer`, introspection of a `mcp-test` token is active, exchange works with scope.

### 5.9 `src/shared/testing.ts` (exists; additions)

Existing exports stay (`callTool`/`toolOutcome`/`ToolOutcome` are re-exported from `client/run.ts`, where they now live). Changes/additions:

```ts
export function keycloakPasswordToken(o: { username; password; scope?: 'mcp:tools'; clientId?: 'mcp-test' }): Promise<OAuthTokens>   // default client becomes mcp-test
export function keycloakClientCredentials(o: { clientId; clientSecret; scope? }): Promise<OAuthTokens>                               // unchanged
// add:
export function decodeJwtPayload(token: string): JWTPayload
export function wwwAuthenticate(res: RawResponse | Response): { scheme?: string; error?: string; error_description?: string; scope?: string; resource_metadata?: string }
export function expectOAuth401(res: RawResponse, o?: { resourceMetadata?: string; scope?: string; error?: string /* 'invalid_token' */ }): void   // status 401 + header fields
export async function mintLocalJwt(o: { key: CryptoKey; kid?: string; alg?: 'RS256'|'ES256'; issuer; audience; sub?; scope?; roles?; expiresIn?: string; azp?; extraClaims? }): Promise<string>
export async function testKeyPair(alg?: 'RS256'|'ES256'): Promise<{ privateKey: CryptoKey; publicJwk: JWK; jwks: JSONWebKeySet }>
export function spawnExample(script: string, env?: Record<string, string>, o?: { readyUrl?: string; timeoutMs?: number }): Promise<{ child: ChildProcess; stdout: () => string; stderr: () => string; stop(): Promise<void> }>
   // spawns `tsx <script>` (or `uv run …` when script ends with .py) with cwd=repo root; resolves when readyUrl answers 200 (default <publicUrl>/healthz)
export function waitForHttp(url: string, o?: { timeoutMs?; okStatus?: number[] }): Promise<void>
export function freePort(): Promise<number>
```

### 5.10 `scripts/` (add in Phase 0)

* `scripts/browser-login.py` — Python Playwright driver. Usage:
  `browser-login.py [--user alice] [--password password] [--screenshot-dir test-results] <authorization-url>`.
  Opens the URL headless, waits for `networkidle`, then loops: if `#username` is visible fill
  `#username`/`#password` and click `#kc-login, button[type=submit]` (first visible); if
  `input[name=accept], #approve` is visible click it; stop when the page URL starts with
  `http://<127.0.0.1|localhost|PUBLIC_HOST>:<OAUTH_CALLBACK_PORT>/callback` or the body contains
  "Authorized"; on any failure save `page.content()` + screenshot to `--screenshot-dir` and exit 1.
  **(verified)** Keycloak 26.7.2 login form ids: `#kc-form-login`, `#username`, `#password`,
  `#kc-login` (`name="login"`); consent page: `input[name=accept]#kc-login` (implementer re-checks
  on first DCR run). The embedded AS (03) uses the same ids.
* `scripts/smoke.ts` — §8.
* `scripts/gen-certs.sh` — 08 PKI (openssl 3.5 **(verified installed)**), also usable by tests via a temp dir.
* `scripts/kc.sh` — existing; add: `keys` sub-command generating `keycloak/.generated/mcp-service-jwt.{key,pub}` (RSA 2048, PEM) and exporting `MCP_SERVICE_JWT_PUBLIC_KEY` (base64 DER, single line) to the realm render; `up` calls it when the key is missing.
* `tests/conventions.test.ts` — import-order guard; every `examples/*/client.ts` calls `printResult`; no `localhost` string in server-side URLs of `src/` and `examples/**/server*.ts` except the loopback redirect/host allow-list constants.

### 5.11 `package.json` scripts (final, written in Phase 0)

```
typecheck · test · test:kc (REQUIRE_KEYCLOAK=1 vitest run — skipped suites become failures) · smoke (tsx scripts/smoke.ts)
ex:00:server ex:00:client
ex:01:server ex:01:client
ex:02:issuer ex:02:mint ex:02:server ex:02:client
ex:03:server ex:03:client
ex:04:server ex:04:client
ex:05:server ex:05:client
ex:06:server ex:06:client
ex:07:server ex:07:client ex:07:revoke
ex:08:certs  ex:08:server ex:08:client
ex:09:gateway ex:09:server ex:09:all ex:09:client
ex:10:downstream ex:10:server ex:10:all ex:10:client
ex:11:server (uv run --project examples/11-python-mcp-keycloak python server.py) ex:11:client ex:11:client:py
kc:up kc:down kc:reset kc:logs kc:status kc:keys
```
Dependencies added: `undici` (08). Dev: none new (Playwright is Python).

### 5.12 `.env.example` (final list)

```
PUBLIC_HOST=192.168.1.10            # LAN IP/hostname of this box; auto-detected when empty; never localhost
KEYCLOAK_PORT=8180  KEYCLOAK_REALM=mcp  KEYCLOAK_URL=  (derived)  KC_ADMIN_USER=admin  KC_ADMIN_PASSWORD=admin   # DEMO
OAUTH_CALLBACK_PORT=4199  OAUTH_REDIRECT_HOST=   (127.0.0.1; set to PUBLIC_HOST when the browser runs on another machine)
OAUTH_CLIENT_ID=  OAUTH_CLIENT_SECRET=   (empty = Dynamic Client Registration; mcp-cli = pre-registered)
MCP_SERVER_URL=   (clients: override the server URL)   MCP_BROWSER_CMD=   MCP_NO_BROWSER=   EXPECT_ADMIN=   MCP_AUTH_STORE_DIR=
MCP_AUDIENCE=mcp-server   MCP_ALLOWED_HOSTS=   MCP_LOG=1   MCP_RATE_LIMIT=1
PORT_00..PORT_11 (4100..4111)  PORT_02_ISSUER=4192  PORT_09_INTERNAL=4119  PORT_10_DOWNSTREAM=4190
MCP_API_KEYS="demo-api-key-alice:alice:mcp:tools;demo-api-key-bob:bob:mcp:tools mcp:admin"   # 01 server, DEMO
MCP_API_KEY=demo-api-key-alice                                                             # 01 client, DEMO
MCP_TOKEN=            # 02 client (optional; otherwise fetched from the issuer)   DEMO_USER=alice DEMO_PASSWORD=password
MCP_SERVICE_CLIENT_SECRET=mcp-service-secret-demo   MCP_SERVER_CLIENT_SECRET=mcp-server-secret-demo   # DEMO
INTROSPECTION_TTL_SECONDS=10   GATEWAY_INTERNAL_SECRET=gateway-internal-secret-demo   MTLS_CLIENT=alice
```

---

## 6. Per-example specifications

Common to all: `buildApp()` per §4.3, `createDemoServer({ name })` for the tools, `mountMcp({ auth })`,
`listen()` on `0.0.0.0`, client ends with `process.exit(printResult(...))` after
`transport.terminateSession()` + `client.close()`. "Negative matrix" rows are vitest cases; "Smoke"
rows are what `scripts/smoke.ts` runs. Every docs page (`docs/NN-slug.md`) follows the template in §9.

### 6.0 `00-baseline-no-auth` — done

Reference. Keep as is. Its docs page (already drafted by the scaffold author) explains Streamable
HTTP, sessions, the Host allow-list, `extra.authInfo` being `undefined`, and why `admin_only` is
always denied here (no identity at all — the problem statement).

### 6.1 `01-api-key` — static API key (S)

**Server** (`server.ts`, ~70 lines): `ApiKeyVerifier implements OAuthTokenVerifier` built from
`MCP_API_KEYS` (`key:principal:scope scope;…`; default = the two DEMO keys). Table stores
`{ sha256(key) → { principal, scopes } }`; `verifyAccessToken` hashes the presented token, compares
with `crypto.timingSafeEqual` against **every** entry (constant work, no early exit), throws
`InvalidTokenError('unknown API key')` otherwise, returns `AuthInfo { token, clientId: principal,
scopes, expiresAt: now + 3600 (synthesised — the SDK insists), extra: { sub: principal, kind: 'api-key' } }`.
`mountMcp({ auth: requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'] }) })` — **no**
`resourceMetadataUrl` (nothing to discover; the 401 header must not advertise a PRM).
Extra route none. Docs: why keys are hashed at rest, rotation = two active keys, why the
`Authorization: Bearer` form (RFC 6750 §2.1) and not `X-API-Key`/query string, and that an API key
cannot participate in PRM/AS discovery.

**Client** (`client.ts`): `new StreamableHTTPClientTransport(url, { requestInit: { headers: { Authorization: `Bearer ${env('MCP_API_KEY')}` } } })`
(SDK client recipe 2a). Catch `StreamableHTTPError` with `code === 401` and print
"API key rejected" (without an `authProvider` the SDK throws `StreamableHTTPError`, not
`UnauthorizedError` — say so in the docs).

**Negative matrix**: no header → 401 + `WWW-Authenticate: Bearer error="invalid_token"` **without**
`resource_metadata`; unknown key → 401; known key with one char changed → 401; `Bearer  key`
(double space) → 401 (SDK splits on a single space); alice key → `whoami.extra.sub === 'alice'`,
`admin_only` isError; bob key → `admin_only` ok; key removed from the table at runtime
(`buildApp({ keys })` with a mutable table) → next request 401; unit: the compare path calls
`timingSafeEqual` for every entry (spy) and never `===`. **Smoke**: server + client with the
default key → `whoami.extra.sub === 'alice'`, `adminOnly: denied`; `MCP_API_KEY=demo-api-key-bob EXPECT_ADMIN=ok`.

### 6.2 `02-jwt-local` — self-issued JWT via JWKS URL (M)

**Issuer** (`issuer.ts`, port `PORT_02_ISSUER` 4192): on first start generates an RS256 key pair
into `.mcp-auth/02-issuer-keys.json` (`{ kid, privateJwk, publicJwk }`, mode 0600) or loads it;
exports `loadIssuerKeys()`, `mintToken({ sub, scope, roles?, ttlSec = 300, audience = publicUrl(PORT_02), issuer = publicUrl(PORT_02_ISSUER, '/'), alg? })`
and `buildIssuerApp()` serving `GET /.well-known/jwks.json` (public JWK with `kid`, `alg`, `use`)
and `POST /token` (form `username`/`password` against the demo users `alice`/`password` →
`{ access_token, token_type: 'Bearer', expires_in }`; bob gets `scope: 'mcp:tools mcp:admin'`,
alice `'mcp:tools'`). It is **not** OAuth — the docs call it "a demo token vending endpoint" and
contrast it with 03/04. `npm run ex:02:mint -- --sub alice [--scope "mcp:tools mcp:admin"] [--ttl -60] [--aud http://…] [--alg none]`
prints a token for the break-it section (negative variants use a separate signing routine so the
issuer's own key handling stays clean).

**Server** (`server.ts`, port 4102): `createJwtVerifier({ issuer: publicUrl(PORT_02_ISSUER, '/'), audience: publicUrl(PORT_02) /* exact canonical MCP URL — strict RFC 8707 form */, jwks: `${issuerUrl}/.well-known/jwks.json`, requiredScopes: ['mcp:tools'] })`;
`buildApp({ issuer?, audience?, jwks? })` for hermetic tests. `requireBearerAuth` **without**
`resourceMetadataUrl` (no AS to discover; docs explain this is where 04 adds PRM).

**Client** (`client.ts`): if `MCP_TOKEN` is set use it, else `POST <issuer>/token` with
`DEMO_USER`/`DEMO_PASSWORD` (default alice/password), then static bearer as in 01. `--expired`
requests a token with negative TTL (issuer honours `ttl` only when `MCP_DEMO_UNSAFE_TTL=1`,
default on for the demo) to show the 401.

**Negative matrix** (hermetic, `testKeyPair` + `mintLocalJwt`): valid → whoami `extra.sub`,
scopes; expired → 401 `error_description` contains "expired"; `nbf` in future → 401; wrong `iss` →
401; `aud` = other URL → 401; `aud` = `http://host:4102/mcp/` (trailing slash) → 401 (exact match is
the documented policy of this example); `alg: none` → 401; HS256 token signed with the public key
bytes → 401 (jose refuses); tampered payload → 401; unknown `kid` → 401 (remote JWKS refetches once,
then rejects); scope without `mcp:tools` → 403 `insufficient_scope` with `scope="mcp:tools"`;
alice → admin denied, bob → admin ok; key rotation: issuer regenerates keys (`--rotate`) → old token
401 after JWKS cache refresh. **Smoke**: `ex:02:issuer` + `ex:02:server` + `ex:02:client` (alice),
then `DEMO_USER=bob EXPECT_ADMIN=ok`.

### 6.3 `03-oauth-embedded-as` — MCP server is the AS (L)

**Server** (`server.ts` + `provider.ts` + `pages.ts`, port 4103). `provider.ts`:
`DemoAuthorizationServer implements OAuthServerProvider`:
* `clientsStore`: `Map` pre-seeded with public client `mcp-cli` (`redirect_uris` =
  `http://127.0.0.1:4199/callback`, `http://localhost:4199/callback`, `http://<PUBLIC_HOST>:4199/callback`,
  `token_endpoint_auth_method: 'none'`) + `registerClient` (DCR; the SDK handler fills ids/secrets;
  `clientRegistrationOptions: { clientSecretExpirySeconds: 0 }`).
* `authorize(client, params, res)`: stores a pending request `{ client, params, csrf }` under a
  random `txn` id (5 min TTL) and `res.redirect('/login?txn=…')`.
* Own Express routes (`pages.ts`, mounted by `buildApp` **before** `mcpAuthRouter`):
  `GET /login` (form ids `#username`, `#password`, hidden `txn` + `csrf`, submit `#kc-login`),
  `POST /login` (users `alice`/`bob`, password `password`, scrypt-hashed in code, constant-time
  compare; wrong password re-renders with an error), `GET /consent` (client_name, redirect host
  shown prominently, requested scopes, `resource`; buttons `input[name=accept]#kc-login` and
  `input[name=cancel]#kc-cancel`), `POST /consent` → on accept: single-use code (random 32 bytes,
  5 min) bound to `{ clientId, redirectUri, codeChallenge, scopes, resource, sub }` →
  `302 redirect_uri?code=&state=`; on cancel → `302 redirect_uri?error=access_denied&state=`.
* `challengeForAuthorizationCode` returns the stored challenge (SDK verifies S256 locally).
* `exchangeAuthorizationCode(client, code, _v, redirectUri, resource)`: checks client binding,
  `redirectUri` equality, `resource` equality when both present; deletes the code; **code reuse →
  revokes every token issued from it** (OAuth 2.1 §4.1.2) and throws `InvalidGrantError`; issues
  opaque access token (32 random bytes hex, 15 min) + refresh token (rotated on use; reuse of an old
  refresh token revokes the family).
* `exchangeRefreshToken`: rotation as above; scopes may only narrow.
* `verifyAccessToken`: `Map` lookup → `AuthInfo { clientId, scopes, expiresAt, resource, extra: { sub } }`
  (scope `mcp:admin` granted only to bob — the consent page does not offer it to alice); unknown →
  `InvalidTokenError`.
* `revokeToken` (both token types) → `/revoke` is mounted.
`buildApp()`: `app.use(mcpAuthRouter({ provider, issuerUrl: new URL(publicUrl(PORT_03, '/')), resourceServerUrl: new URL(publicUrl(PORT_03)), scopesSupported: ['mcp:tools', 'mcp:admin'], resourceName: '03-oauth-embedded-as', clientRegistrationOptions: { clientSecretExpirySeconds: 0, rateLimit: rl }, tokenOptions: { rateLimit: rl }, authorizationOptions: { rateLimit: rl }, revocationOptions: { rateLimit: rl } }))`
with `rl = process.env.MCP_RATE_LIMIT === '0' ? false : undefined`; then
`mountMcp({ auth: requireBearerAuth({ verifier: provider, requiredScopes: ['mcp:tools'], resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(publicUrl(PORT_03))) }) })`.
Endpoints that result: `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`,
`GET|POST /authorize`, `POST /token` (form; `client_secret_post`/`none` only), `POST /register`,
`POST /revoke`, `/login`, `/consent`, `/mcp`.

**Client** (`client.ts`): `CliOAuthProvider({ serverUrl, scope: 'mcp:tools' })` + `connectWithOAuth`;
DCR by default, `OAUTH_CLIENT_ID=mcp-cli` pre-registered; `--logout`; second run refreshes silently.

**Negative matrix** (vitest, `MCP_RATE_LIMIT=0`, driven with `fetch` + a cookie jar, no browser):
AS metadata has `code_challenge_methods_supported: ['S256']`, `token_endpoint_auth_methods_supported: ['client_secret_post','none']`,
`registration_endpoint`, `revocation_endpoint`; PRM `resource === publicUrl(PORT_03)`,
`authorization_servers === [issuer]`; 401 on `/mcp` carries `resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp"`;
`/authorize` with unregistered `redirect_uri` → 400 JSON (never a redirect); loopback
`redirect_uri` on another port → accepted (RFC 8252, SDK `redirectUriMatches`); `localhost` vs
`127.0.0.1` cross-match → 400; `code_challenge_method=plain` → 302 with `error=`; scripted flow:
GET /authorize → follow to /login → POST creds → /consent → POST accept → code → POST /token with
the verifier → tokens → whoami; wrong `code_verifier` → `invalid_grant`; code reuse →
`invalid_grant` **and** the first access token now 401; refresh rotation: old refresh token →
`invalid_grant`; refresh token presented by another `client_id` → `invalid_grant`; `/revoke` →
401 afterwards; wrong password → no code issued; missing/invalid `csrf` → 400; DCR with
`token_endpoint_auth_method: 'none'` → 201 without `client_secret`; scope outside
`scopesSupported` → `invalid_scope`; full SDK round trip with a test provider whose
`redirectToAuthorization` drives the pages with `fetch` (proves `finishAuth`); rate limit: with
`MCP_RATE_LIMIT=1`, 51 `/token` posts → 429. **Smoke**: server; client with
`MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password"` → whoami
`extra.sub === 'alice'`, denied; client again (no browser: refresh); `--logout`; bob with
`EXPECT_ADMIN=ok`; `OAUTH_CLIENT_ID=mcp-cli` run.

### 6.4 `04-keycloak-resource-server` — the spec-recommended pattern (M)

**Server** (`server.ts`, port 4104):
```ts
export async function buildApp(o: { metadata?: OAuthMetadata; jwks?: JwksSource; issuer?: string; audience?: string[] } = {}) {
  const metadata = o.metadata ?? await discoverKeycloak();
  const resourceUrl = publicUrl(PORT);
  const app = createApp();
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, { resourceUrl, authorizationServers: [o.issuer ?? metadata.issuer], scopesSupported: ['mcp:tools', 'mcp:admin'], resourceName: '04-keycloak-resource-server' });
  const verifier = createJwtVerifier({ issuer: o.issuer ?? metadata.issuer, audience: o.audience ?? audiences(), jwks: o.jwks ?? metadata.jwks_uri!, requiredScopes: ['mcp:tools'], effectiveScopes: keycloakEffectiveScopes });
  mountMcp(app, { createServer: () => createDemoServer({ name: '04-keycloak-resource-server' }), auth: requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'], resourceMetadataUrl }) });
  return app;
}
```
`whoami.extra` shows `sub`, `username`, `roles`, `claims.aud === 'mcp-server'`. Docs page walks the
full discovery trace (401 → PRM → `/.well-known/oauth-authorization-server/realms/mcp` (**verified**
200 on the first probe) → DCR → authorize with `resource=` (sent, ignored) → token → retry) with real
captured headers, and explains SEP-835 scope selection (PRM `scopes_supported` drives the request,
so the client asks for `mcp:tools mcp:admin`; alice's token then *contains* `mcp:admin` in `scope`
**(verified)** but `keycloakEffectiveScopes` drops it — scope = client grant, role = user right).

**Client** (`client.ts`): `CliOAuthProvider({ serverUrl })` + `connectWithOAuth`. DCR by default
(Keycloak consent page appears — **verified** anonymous DCR works on the realm), `OAUTH_CLIENT_ID=mcp-cli`
for the pre-registered client (no consent). `OAUTH_REDIRECT_HOST=<PUBLIC_HOST>` for the
client-on-A/browser-on-B case.

**Negative matrix** — hermetic with `buildApp({ issuer: 'http://192.0.2.10:8180/realms/mcp', jwks: testJwks, audience: ['mcp-server'] })`:
401 without token carries `resource_metadata` + `scope="mcp:tools"`; PRM JSON equals
`{ resource: publicUrl, authorization_servers: [issuer], scopes_supported: […], resource_name, bearer_methods_supported: ['header'] }`
and `/.well-known/oauth-authorization-server` on the RS origin is **404** (no mirror);
`aud: ['account']` → 401 "wrong audience"; wrong `iss` → 401; expired → 401; tampered → 401;
scope `profile email` only → 403 `insufficient_scope` `scope="mcp:tools"`; alice (`mcp:tools mcp:admin`,
roles `[mcp-user]`) → admin denied; bob → ok; bob's token on alice's session → 403; the SDK client
with a test `OAuthClientProvider` performs discovery against the PRM and reaches the
`authorization_endpoint` of the stub metadata (asserts the discovery order). Keycloak-backed
(`skipIf`): `mcp-test` tokens for alice/bob → same assertions with real tokens; service-account
token (`mcp-service`) → accepted, admin denied; `discoverOAuthServerInfo(mcpUrl)` from the SDK
resolves to the Keycloak metadata. **Smoke**: DCR run with the browser driver (alice), refresh
run, `OAUTH_CLIENT_ID=mcp-cli` run, bob with `EXPECT_ADMIN=ok`.

### 6.5 `05-keycloak-client-credentials` — M2M (S, stretch M)

**Server** (`server.ts`, port 4105): identical to 04 except `name`, `PORT`, and one extra tool
`service_only` (ok only when `authInfo.clientId` ∈ `MCP_ALLOWED_CLIENTS` default `mcp-service,mcp-service-jwt` —
client-identity authorization, distinct from scope/role). Implement by importing nothing from 04:
copy the 20 lines (examples must stay self-contained; the docs page says "diff against 04").

**Client** (`client.ts`): default `new ClientCredentialsProvider({ clientId: 'mcp-service', clientSecret: env('MCP_SERVICE_CLIENT_SECRET'), scope: 'mcp:tools' })`
(**verified** Keycloak advertises `client_secret_basic` → the SDK uses Basic), eager
`await auth(provider, { serverUrl })` to surface token errors before `connect`, then
`StreamableHTTPClientTransport(url, { authProvider: provider })`. `--auth private-key-jwt`
(stretch): `new PrivateKeyJwtProvider({ clientId: 'mcp-service-jwt', privateKey: readFileSync('keycloak/.generated/mcp-service-jwt.key','utf8'), algorithm: 'RS256', jwtLifetimeSeconds: 60, scope: 'mcp:tools' })`.
Docs: no PKCE/redirect/refresh; `sub` is the service-account user; the SDK passes
`clientMetadata.scope` (not the 401 challenge) to `prepareTokenRequest`; expiry handling = next 401
triggers one re-grant (circuit breaker after that); the SDK's own embedded AS cannot serve this grant.

**Negative matrix** (Keycloak-backed, `skipIf`): whoami `clientId === 'mcp-service'`,
`extra.username === undefined`, roles `[mcp-user]`; `admin_only` denied; `service_only` ok; a user
token (alice via `mcp-test`) → `service_only` denied; wrong secret → `auth()` rejects with
`InvalidClientError` (assert class); scope `mcp:admin` requested by `mcp-service` → token has
`mcp:admin` in `scope` but role missing → admin denied; token counter: force a 401 by pointing the
provider at a fresh transport after `provider.saveTokens({ access_token: 'garbage', token_type: 'Bearer' })`
→ exactly one new `client_credentials` request (fetch spy) then success; second garbage token in a
row → `StreamableHTTPError` 401 (documents the circuit breaker). Hermetic: none beyond 04's
verifier. **Smoke**: `ex:05:client` (`EXPECT_ADMIN=denied`), stretch: `--auth private-key-jwt`.

### 6.6 `06-oauth-proxy-keycloak` — OAuth facade (M)

**Server** (`server.ts`, port 4106): `class KeycloakFacade extends ProxyOAuthServerProvider` with
`endpoints: { authorizationUrl: metadata.authorization_endpoint, tokenUrl: metadata.token_endpoint, revocationUrl: metadata.revocation_endpoint, registrationUrl: metadata.registration_endpoint }`,
`getClient: id => clients.get(id)` where `clients` is pre-seeded with the public `mcp-cli` record
(same three redirect URIs, `token_endpoint_auth_method: 'none'`) and **`clientsStore.registerClient`
is wrapped** so the JSON Keycloak returns is stored in `clients` (the SDK proxy forwards DCR but never
persists the result; `/authorize` would then fail with `invalid_client`);
`verifyAccessToken: createKeycloakVerifier({ metadata, requiredScopes: ['mcp:tools'] }).verifyAccessToken`.
`app.use(mcpAuthRouter({ provider, issuerUrl: new URL(publicUrl(PORT_06, '/')), resourceServerUrl: new URL(publicUrl(PORT_06)), scopesSupported: ['mcp:tools','mcp:admin'], … rateLimit }))`
+ `mountMcp({ auth: requireBearerAuth({ verifier: provider, requiredScopes: ['mcp:tools'], resourceMetadataUrl }) })`.
Flow (docs sequence diagram): client → PRM (`authorization_servers: [facade]`) → facade metadata
(endpoints under the facade origin, `token_endpoint_auth_methods_supported: ['client_secret_post','none']`)
→ `/register` (proxied to Keycloak anonymous DCR) → `/authorize` (SDK validates client +
redirect_uri locally, `provider.authorize` 302s to Keycloak with the same PKCE params) → Keycloak
login (+ consent for DCR clients) → **Keycloak redirects straight to the CLI callback** (the facade
is not in the callback path) → `/token` on the facade → proxied `client_secret_post`-style form
POST to Keycloak (`skipLocalPkceValidation = true`, PKCE verified upstream) → tokens verbatim.
Docs also state the limitations honestly: upstream error bodies become 500 `server_error`
(`Token exchange failed: <status>`), `resource` is forwarded and ignored, the facade's metadata
`issuer` is the facade while `iss` in tokens is Keycloak (fine for the RS, which validates
Keycloak's issuer), and the confidential-upstream variant (inject `client_secret` in overridden
`exchangeAuthorizationCode/exchangeRefreshToken`) is described but not enabled.

**Client**: the same code as 04's client pointed at 4106 — the point is that the client cannot tell.

**Negative matrix** (Keycloak-backed for flows; hermetic for metadata): PRM `authorization_servers === [facadeOrigin/]`;
facade metadata endpoints all start with the facade origin; `/authorize?client_id=unknown` → 400;
unregistered `redirect_uri` → 400 and **no upstream request** (fetch spy on the provider's
`fetch` option); `/register` through the facade returns a Keycloak `client_id`, and a subsequent
`/authorize` for it is a 302 to Keycloak; `/token` with a bogus code → 500 `server_error` (documented
SDK behaviour, asserted so a future SDK change is noticed); tokens minted via `mcp-test` are
accepted at `/mcp` (aud `mcp-server`); refresh via the facade works (`grant_type=refresh_token`
form → 200). **Smoke**: browser run (DCR) → whoami alice; second run refresh; `OAUTH_CLIENT_ID=mcp-cli` run.

### 6.7 `07-token-introspection` — RFC 7662 (M)

**Server** (`server.ts`, port 4107): `IntrospectionVerifier implements OAuthTokenVerifier`
(kept inside the example): `verifyAccessToken(token)` → cache lookup by `sha256(token)` (positive
entries until `min(exp, now + INTROSPECTION_TTL_SECONDS)`, negative entries for 2 s) → else
`introspect(token, { clientId: 'mcp-server', clientSecret: env('MCP_SERVER_CLIENT_SECRET'), metadata })`
→ `active !== true` → `InvalidTokenError('token inactive')`; `aud` must contain `mcp-server` (defence
in depth; **verified** Keycloak already answers `active:false` when the introspecting client is not
in `aud`); map `{ sub, username, client_id, scope, exp, realm_access }` through
`authInfoFromPayload(payloadLike, token, keycloakEffectiveScopes)`; network error / non-2xx →
`ServerError('introspection unavailable')` (500 without `WWW-Authenticate` — fail closed, documented
as "not the client's fault"). A lint-style test asserts `server.ts` does not import `jose` — the RS
never parses the token. `mountProtectedResourceMetadata` + `requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'], resourceMetadataUrl })`.
`buildApp({ introspect?: typeof introspect, ttlSeconds? })` for stubbing.
`scripts`: `ex:07:revoke -- alice` → `adminLogoutUser('alice')` (admin REST, DEMO admin creds) so the
next call fails within one TTL window; the docs page shows the same token still accepted by 04 until `exp`.

**Client**: 04's client at 4107 (the token is a JWT but the client never cares); `--revoke` calls
`revokeToken(accessToken, { clientId: 'mcp-cli' })` (RFC 7009 on Keycloak) then calls `whoami` again
to print the 401.

**Negative matrix**: hermetic with a stubbed `introspect`: `active:false` → 401 `invalid_token`;
active but `aud` lacks `mcp-server` → 401; active with `scope: 'email'` → 403; stub throwing → 500
`server_error` with **no** `WWW-Authenticate`; two calls within TTL → one stub invocation; TTL 0 →
two invocations; negative cache: two bad calls within 2 s → one invocation. Keycloak-backed: `mcp-test`
alice token → ok; `adminLogoutUser('alice')` → with `INTROSPECTION_TTL_SECONDS=0` the next request is
401 (and a 04-style JWKS verifier built in the same test still accepts the token — the revocation-
visibility contrast); RFC 7009 revoke of the access token → 401; wrong `MCP_SERVER_CLIENT_SECRET` →
500. **Smoke**: browser run → whoami ok; `ex:07:revoke -- alice`; client run again → exits 1 with a
401 message (smoke expects failure here).

### 6.8 `08-mtls` — mutual TLS (M)

**PKI** (`scripts/gen-certs.sh`, `npm run ex:08:certs`, output `examples/08-mtls/certs/`, git-ignored):
demo CA (`ca.crt/.key`), server cert with SAN `IP:<PUBLIC_HOST>, IP:127.0.0.1, DNS:localhost`
(`server.crt/.key`), client certs `alice` (`OU=mcp-user`), `bob` (`OU=mcp-admin`), `expired-alice`
(`-not_after` in the past — openssl 3.5 supports `-not_before/-not_after`), and `rogue-ca` +
`rogue-client` for the negative path. Script accepts `OUT_DIR` and `PUBLIC_HOST` so tests generate
into a temp dir.

**Server** (`server.ts`, port 4108, **https**): `https.createServer({ key, cert, ca, requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3' }, app)`
bound `0.0.0.0` (own `listenTls()` in the example because shared `listen()` is http-only; prints
`https://<PUBLIC_HOST>:4108/mcp`). Middleware `certAuth`: `const cert = req.socket.getPeerCertificate()`;
`req.socket.authorized` must be true; CN must be in `MTLS_ALLOWED_CN` (default `alice,bob`) else 403;
sets `req.auth = { token: cert.fingerprint256, clientId: cert.subject.CN, scopes: OU === 'mcp-admin' ? ['mcp:tools','mcp:admin'] : ['mcp:tools'], expiresAt: Date.parse(cert.valid_to) / 1000, extra: { sub: CN, issuer: cert.issuer.CN, fingerprint256, kind: 'mtls' } }`
so tools see `extra.authInfo` exactly like everywhere else; `mountMcp({ auth: certAuth })` — no
`requireBearerAuth`, `Authorization` headers are ignored. `MTLS_SOFT_FAIL=1` variant:
`rejectUnauthorized: false` + app-level 401 JSON (friendlier errors; trade-off documented).

**Client** (`client.ts`): `import { Agent, fetch as undiciFetch } from 'undici'`;
`const dispatcher = new Agent({ connect: { ca, cert, key, servername: publicHost() } })`;
`new StreamableHTTPClientTransport(new URL(`https://${publicHost()}:${PORT}/mcp`), { fetch: (u, init) => undiciFetch(u, { ...init, dispatcher }) })`.
`MTLS_CLIENT=alice|bob|expired-alice|rogue-client|none` picks the cert. Implementer verifies SSE
streaming works through undici's fetch in Node 22.22 (fallback: `node:https` Agent with a minimal
fetch shim, documented).

**Negative matrix** (certs generated into a temp dir in `beforeAll`, server on port 0): alice →
whoami `clientId === 'alice'`, admin denied; bob → admin ok; no client cert → TLS handshake error
(`ERR_SSL_*`/`ECONNRESET`, assert the request never reaches Express via a spy); `rogue-client` →
handshake error; `expired-alice` → handshake error; valid CA but CN not in `MTLS_ALLOWED_CN` → 403;
plain `http://` to the port → connection error; client trusting the wrong CA → client-side
`UNABLE_TO_VERIFY_LEAF_SIGNATURE`/`SELF_SIGNED_CERT_IN_CHAIN`; TLS 1.2 client (`maxVersion: 'TLSv1.2'`) →
rejected. **Smoke**: `ex:08:certs` if missing; server; client alice; `MTLS_CLIENT=bob EXPECT_ADMIN=ok`;
`MTLS_CLIENT=none` expected to fail.

### 6.9 `09-auth-gateway` — gateway / sidecar trust boundary (M)

**Gateway** (`gateway.ts`, port 4109, public): `createApp()` + `mountProtectedResourceMetadata`
(resource = gateway URL, AS = Keycloak) + `requireBearerAuth({ verifier: createKeycloakVerifier({ requiredScopes: ['mcp:tools'] }), resourceMetadataUrl })`
on `/mcp` (all methods), then a hand-rolled streaming reverse proxy (`node:http.request` piping both
directions, no buffering, forwards `mcp-session-id`, `mcp-protocol-version`, `accept`, `content-type`,
`last-event-id`; strips inbound `authorization`, `x-gateway-assertion`, `x-forwarded-user*`; adds
`X-Gateway-Assertion: <HS256 JWT { iss: 'mcp-gateway', aud: 'mcp-internal', sub, azp, scopes, roles, jti, exp: now+30s }>`
signed with `GATEWAY_INTERNAL_SECRET`; maps upstream connection errors to 502). Exports
`buildGatewayApp({ internalUrl, verifier?, secret? })`.

**Internal server** (`server.ts`, port 4119, **binds `0.0.0.0`** per the LAN rule — the docs explain
that in production this listener is network-isolated; `INTERNAL_TRUST_MODE=network` (opt-in) binds
`127.0.0.1` and trusts plain `X-Forwarded-User/-Scopes` headers instead, to demonstrate the attack):
middleware verifies the assertion with `jose` (`HS256`, `aud`, `exp`, `jti` replay cache of 60 s) and
sets `req.auth = { token: jti, clientId: azp, scopes, expiresAt: exp, extra: { sub, roles, via: 'gateway' } }`;
missing/invalid → 401 (no PRM: the backend is not a public resource). `mountMcp({ auth: trustGateway })`.
`all.ts` starts both listeners in one process for `npm run ex:09:all`.

**Client**: 04's client pointed at the gateway (4109) — unchanged.

**Negative matrix** (hermetic: gateway with `buildApp` JWT overrides, internal on port 0): via
gateway with a local test token → whoami `extra.via === 'gateway'`, `sub` from the assertion; no
token → 401 with `resource_metadata` pointing at the gateway PRM; wrong aud → 401; direct POST to the
internal port with `X-Forwarded-User: bob` and no assertion → 401; forged assertion (wrong secret) →
401; expired assertion → 401; assertion with `aud: 'other'` → 401; replayed assertion (same jti) →
401; inbound `X-Gateway-Assertion` from the client is stripped (spy on the internal request
headers); the internal server never sees `Authorization` (spy); SSE GET stream and DELETE round-trip
through the proxy (session id preserved); `INTERNAL_TRUST_MODE=network` → forged header accepted
(the documented attack, asserted so the warning cannot be removed silently). Keycloak-backed: alice
via `mcp-test` through the gateway → ok. **Smoke**: `ex:09:all`; browser run → whoami alice
`via: 'gateway'`; direct curl to 4119 → 401.

### 6.10 `10-token-exchange-downstream` — on-behalf-of (L)

**Downstream API** (`downstream.ts`, port 4190, plain Express, no MCP): `GET /me` guarded by
`createJwtVerifier({ issuer, audience: ['downstream-api'], jwks, requiredScopes: ['downstream-api'] })`
(hand-rolled bearer middleware or `requireBearerAuth` — either is fine) → `{ sub, azp, aud, scope, roles }`;
`/healthz`.

**MCP server** (`server.ts`, port 4110): 04's RS + tool `downstream_profile` (no input):
`const subject = extra.authInfo!.token;` → cache lookup by `sha256(subject)` → else
`exchangeToken({ subjectToken: subject, audience: 'downstream-api', scope: 'downstream-api', clientId: 'mcp-server', clientSecret: env('MCP_SERVER_CLIENT_SECRET'), metadata })`
(**verified** request shape: `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
`subject_token_type=urn:ietf:params:oauth:token-type:access_token`, `requested_token_type=…:access_token`,
`audience=downstream-api`, `scope=downstream-api`, Basic `mcp-server`) → cache until
`min(subject exp, exchanged exp)` → `GET <downstream>/me` with the exchanged token → returns
`{ via: 'token-exchange', exchanged: { aud, azp, scope }, downstream: <body> }`; Keycloak errors are
returned as `isError` with `error` + `error_description` (never the tokens). `DEMO_PASSTHROUGH=1`
registers `downstream_passthrough` which forwards the caller's token unchanged (expected 401 from
the downstream — the anti-pattern for the docs). `all.ts` runs both listeners.

**Client**: 04's client + one extra `callTool('downstream_profile')` printed under `extra.downstream`.

**Negative matrix** (Keycloak-backed for exchange; hermetic for the downstream verifier): alice via
`mcp-test` (scope `mcp:tools` → `aud` includes `mcp-server`) → `downstream_profile` returns
`sub === alice's sub`, `azp === 'mcp-server'`, `aud === 'downstream-api'`; passthrough tool → 401
from the downstream (aud); exchanged token replayed at `/mcp` → 401 (aud lacks `mcp-server`);
inbound MCP token sent to `/me` directly → 401; exchange without `scope` → Keycloak
`invalid_request` "Requested audience not available" (**verified** text; assert `error` only, the
description as `toContain('audience')`); exchange requested by `mcp-service` (flag off) → error
`toContain('not enabled')`; subject token whose `aud` lacks `mcp-server` → Keycloak error `toContain('audience')` — obtain such
a token from `mcp-test` with `scope=email` and assert `aud` is absent first (`mcp:tools` is a
*default* scope of `mcp-test`, so if `aud` is still present skip this case and cover the rule in the
docs only); cache: second
call → no second exchange (fetch spy); subject token expired → cache entry dropped. **Smoke**:
`ex:10:all`; browser run → `extra.downstream.sub` present, `azp === 'mcp-server'`.

### 6.11 `11-python-mcp-keycloak` — Python twin of 04 (M)

`pyproject.toml` (uv project; `requires-python = ">=3.12"`; deps `mcp==2.1.1`, `PyJWT[crypto]>=2.9`,
`uvicorn>=0.30`, `httpx`; dev `pytest`, `pytest-asyncio`) + `uv.lock` committed.

**Server** (`server.py`, port 4111): reads `PUBLIC_HOST`, `PORT_11`, `KEYCLOAK_URL/PORT/REALM`,
`MCP_AUDIENCE` from the environment (`python-dotenv` reading the repo-root `.env`, same precedence as
`env.ts`). `class JwksTokenVerifier(TokenVerifier)`: `PyJWKClient(jwks_uri)`,
`jwt.decode(token, key, algorithms=['RS256'], issuer=ISSUER, audience=AUDIENCES, leeway=5)` →
`AccessToken(token=token, client_id=payload.get('azp') or payload['sub'], scopes=effective_scopes(payload), expires_at=payload['exp'], subject=payload.get('sub'), claims=payload)`;
any exception → `None` (the SDK middleware turns `None` into 401 + `WWW-Authenticate` — implementer
verifies the header contains `resource_metadata`; if not, add the `RequireAuthMiddleware`/route
manually). `effective_scopes` = the same rule as `keycloakEffectiveScopes`.
`server = MCPServer('11-python-mcp-keycloak', token_verifier=verifier, auth=AuthSettings(issuer_url=ISSUER, resource_server_url=MCP_URL, required_scopes=['mcp:tools']))`;
tools `whoami`, `add`, `admin_only` reading `get_access_token()`; `app = server.streamable_http_app(host='0.0.0.0', transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=[f'{PUBLIC_HOST}:*', 'localhost:*', '127.0.0.1:*']))`;
verify `/.well-known/oauth-protected-resource/mcp` is served (else mount
`create_protected_resource_routes(resource_url=MCP_URL, authorization_servers=[ISSUER], scopes_supported=[…])`
into the Starlette app); `uvicorn.run(app, host='0.0.0.0', port=PORT)`; `GET /healthz` added.

**Clients**: `client.ts` (TypeScript, 10 lines: 04's client with the server URL defaulting to
`publicUrl(4111)`) — the interop proof; `client.py` (bonus, S): `mcp.client.auth.OAuthClientProvider(server_url, client_metadata=OAuthClientMetadata(client_name=…, redirect_uris=[callback], grant_types=[…], response_types=['code'], token_endpoint_auth_method='none', scope='mcp:tools'), storage=<JSON file under .mcp-auth/>, redirect_handler=<print + MCP_BROWSER_CMD>, callback_handler=<loopback http.server on 4199>)`
+ `streamable_http_client(url, auth=provider)`; runs the same three tools.

**Negative matrix**: `server.test.ts` spawns `uv run --project examples/11-python-mcp-keycloak python server.py`
via `spawnExample` (skipped with a message when `uv` is missing or Keycloak is down): PRM JSON
field-by-field equal to 04's shape (`resource`, `authorization_servers`, `scopes_supported`); 401
header carries `resource_metadata`; `mcp-test` alice → whoami `subject`, admin denied; bob → ok;
wrong-audience local JWT → 401; scope `email` → 403; TS SDK client full round trip with a
pre-registered `mcp-cli` + password-grant tokens injected into a test provider. `uv run pytest`:
unit tests of the verifier with in-process RSA keys (expired / iss / aud / alg none → `None`).
**Smoke**: `ex:11:server`; TS client browser run (`OAUTH_CLIENT_ID=mcp-cli`) → whoami alice;
`ex:11:client:py` (bonus) same.

---

## 7. Keycloak

### 7.1 Compose (`keycloak/docker-compose.yml`) — keep the existing file

```yaml
services:
  keycloak:
    image: quay.io/keycloak/keycloak:26.7.2
    container_name: mcp-auth-demo-keycloak
    command: ["start-dev", "--import-realm"]
    environment:
      KC_BOOTSTRAP_ADMIN_USERNAME: ${KC_ADMIN_USER:-admin}        # DEMO
      KC_BOOTSTRAP_ADMIN_PASSWORD: ${KC_ADMIN_PASSWORD:-admin}    # DEMO
      KC_HOSTNAME: http://${PUBLIC_HOST:?…}:${KEYCLOAK_PORT:-8180} # full URL → iss pinned
      KC_HOSTNAME_STRICT: "false"
      KC_HTTP_ENABLED: "true"
      KC_HEALTH_ENABLED: "true"
    ports: ["${KEYCLOAK_PORT:-8180}:8080"]
    volumes: ["./.generated/realm-mcp.json:/opt/keycloak/data/import/realm-mcp.json:ro"]
    healthcheck: bash /dev/tcp probe of 127.0.0.1:9000/health/ready (image has no curl)
```
Project name `mcp-auth-demo` (`docker compose -p`), dev-file H2 storage (5432/5433 are taken anyway;
`kc:reset` = `down -v` + re-import). No `network_mode: host` (host 9000 is taken by another
service). **Issuer consistency (verified)**: with `KC_HOSTNAME=http://192.168.78.87:8180` the
discovery document and every token's `iss` are `http://192.168.78.87:8180/realms/mcp` no matter
which address the request used; `env.ts` derives the identical string
(`keycloak().issuer`), the PRM advertises it, and clients on other LAN machines discover it from the
PRM — the only thing a tester must get right is `PUBLIC_HOST` in `.env` (`kc:status` prints the
issuer; `docs/lan-testing.md` explains). Optional `--hostname-debug=true` for troubleshooting.

### 7.2 Realm `mcp` (`keycloak/realm-mcp.template.json`, rendered by `scripts/kc.sh` — `{{PUBLIC_HOST}}`, `{{OAUTH_CALLBACK_PORT}}`, `{{MCP_SERVICE_CLIENT_SECRET}}`, `{{MCP_SERVER_CLIENT_SECRET}}`, `{{MCP_SERVICE_JWT_PUBLIC_KEY}}`)

Keycloak does **not** substitute `${env.X}` in imported realm files (verified by two proposals), hence
the render step. Existing content, all **verified live**:

| Item | Value |
|---|---|
| Realm | `sslRequired: none`, `accessTokenLifespan: 900` (Keycloak's default 60 s makes demos flaky), `ssoSessionIdleTimeout: 1800`, `bruteForceProtected: false`, `registrationAllowed: false` |
| Realm roles | `mcp-user`, `mcp-admin` (+ built-ins `offline_access`, `uma_authorization`) |
| Users (DEMO) | `alice` / `password` → `mcp-user`; `bob` / `password` → `mcp-user`, `mcp-admin`; `service-account-mcp-service` → `mcp-user`; `service-account-mcp-server` → none |
| Client scopes | built-ins `profile`, `email`, `roles` (realm roles → `realm_access.roles`), `web-origins`, `basic` (**`sub` lives here** — Keycloak 25+), `acr`, `offline_access`; **`mcp:tools`** (default; audience mapper `included.custom.audience: mcp-server`; consent text "Use MCP tools on your behalf"); **`mcp:admin`** (optional; same audience mapper); **`downstream-api`** (optional; audience mapper `downstream-api`) |
| `mcp-cli` | public, standard flow, `pkce.code.challenge.method: S256`, redirect URIs `http://localhost:{{PORT}}/callback`, `http://127.0.0.1:{{PORT}}/callback`, `http://{{PUBLIC_HOST}}:{{PORT}}/callback` (exact match — **verified** Keycloak does *not* relax loopback ports: port 5555 → "Invalid parameter: redirect_uri"), default scopes incl. `mcp:tools`, optional `mcp:admin`, `downstream-api`, `offline_access` |
| `mcp-service` | confidential, secret `{{MCP_SERVICE_CLIENT_SECRET}}` (DEMO `mcp-service-secret-demo`), service account, default `mcp:tools`, optional `mcp:admin` |
| `mcp-server` | confidential, secret `{{MCP_SERVER_CLIENT_SECRET}}` (DEMO `mcp-server-secret-demo`), service account, `standard.token.exchange.enabled: true`, optional scope `downstream-api` |
| `downstream-api` | confidential placeholder (secret `downstream-api-secret-demo`), no flows — exists as the exchange audience |
| Anonymous DCR policies | Trusted Hosts **removed** (open anonymous registration — demo; hardened variant in `docs/keycloak.md`: `trusted-hosts` component with `host-sending-registration-request-must-match: false`, `client-uris-must-match: true`, hosts `127.0.0.1, localhost, {{PUBLIC_HOST}}`); `consent-required`; `scope` (full scope disabled); `max-clients: 200`; `allowed-client-templates` with `allowed-client-scopes: [mcp:tools, mcp:admin, offline_access]` (→ `openid` rejected with `insufficient_scope`); `allowed-protocol-mappers` |
| Token claims (alice, `scope=mcp:tools mcp:admin`) | `iss=http://192.168.78.87:8180/realms/mcp`, `aud="mcp-server"`, `azp=mcp-cli`, `scope="mcp:tools email mcp:admin profile"`, `realm_access.roles=[mcp-user]`, `typ=Bearer`, `preferred_username=alice`, `sub=<uuid>` |
| Introspection | `POST …/token/introspect` with Basic `mcp-server` → `{ active: true, aud: "mcp-server", scope, username }` |
| Token exchange | `mcp-server` + `scope=downstream-api` → `aud=downstream-api, azp=mcp-server, scope=downstream-api, sub=<alice>`; without `scope` → `invalid_request: Requested audience not available: downstream-api` |
| Discovery | `/realms/mcp/.well-known/openid-configuration` **and** `/.well-known/oauth-authorization-server/realms/mcp` (both 200 → the SDK client's first probe succeeds); `grant_types_supported` includes `client_credentials`, `token-exchange`, `device_code`, `jwt-bearer`; `token_endpoint_auth_methods_supported` = `private_key_jwt, client_secret_basic, client_secret_post, tls_client_auth, client_secret_jwt`; `code_challenge_methods_supported` = `plain, S256` |
| `resource` parameter | ignored (`aud` stays `mcp-server`) — do **not** enable the experimental `resource-indicators` feature (it rejects unregistered resources with `invalid_target`, and the SDK client always sends `resource=` when a PRM exists) |

### 7.3 Realm deltas to apply in Phase 0 (then freeze)

1. **`mcp-test`** — new public client, `directAccessGrantsEnabled: true`, `standardFlowEnabled: false`,
   default scopes as `mcp-cli`, optional `mcp:admin`, `downstream-api`; description "TEST ONLY —
   password grant for headless tests, removed from OAuth 2.1". `mcp-cli` → `directAccessGrantsEnabled: false`.
   `testing.ts` default `clientId` → `mcp-test`; `keycloak/README.md` + `docs/keycloak.md` updated.
2. **`mcp-service-jwt`** (05 stretch) — confidential, `clientAuthenticatorType: "client-jwt"`,
   `attributes: { "jwt.credential.public.key": "{{MCP_SERVICE_JWT_PUBLIC_KEY}}", "token.endpoint.auth.signing.alg": "RS256" }`,
   service account with `mcp-user`, default `mcp:tools`. `scripts/kc.sh keys` generates the RSA pair into
   `keycloak/.generated/` (git-ignored) and renders the base64 DER public key. **If the import fails or
   the grant is rejected, remove the client from the template and keep the variant docs-only.**
3. Nothing else. PKCE-enforcer client policies, lightweight tokens, DPoP, CIMD, resource indicators
   are documented in `docs/keycloak.md`, not imported.

Anonymous DCR creates clients that persist in the realm (each dev machine / each test run with a
fresh `.mcp-auth/`); `kc:reset` clears them; tests that register clients delete their store file
afterwards and are limited by `max-clients: 200`.

---

## 8. Browser automation and `npm run smoke`

### 8.1 Hand-off from the client to the browser driver

`CliOAuthProvider.redirectToAuthorization()` prints the URL and calls `openBrowser(url)`; with
`MCP_BROWSER_CMD` set, `openBrowser` spawns `sh -c "$MCP_BROWSER_CMD '<url>'"` (detached; stdout/err
of the driver go to the client's stderr). Smoke and tests set
`MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password"`. Humans set
nothing (xdg-open) or `MCP_NO_BROWSER=1`. The loopback listener is already up before the redirect,
so a fast headless browser cannot beat it.

### 8.2 `scripts/browser-login.py` (Python Playwright, headless Chromium from `~/.cache/ms-playwright`)

See §5.10. Selector strategy, in order, with generous timeouts (30 s): Keycloak login
(`#username`, `#password`, `#kc-login`), Keycloak consent (`input[name=accept]`, fallback `#kc-login`
on a page containing "consent"/"Grant"), embedded AS (03) login/consent (same ids by design). Ends
when the final URL is the callback (`/callback?code=`) or an "Authorized" page is shown; on failure
writes `test-results/browser-login-<timestamp>.{png,html}` and exits 1. Other machines:
`uv run --with playwright python -m playwright install chromium` is documented in `docs/lan-testing.md`.

### 8.3 `scripts/smoke.ts` — the end-to-end matrix

`npm run smoke [-- 04 07] [--no-keycloak] [--keep]`:
1. Loads `.env` via `env.ts`; prints `PUBLIC_HOST` and the effective URLs; refuses `PUBLIC_HOST=localhost`.
2. Prerequisites: `npm run kc:status`-style issuer check (skips Keycloak examples with a clear message
   under `--no-keycloak` or when down); `ex:08:certs` when `examples/08-mtls/certs/ca.crt` is missing;
   `uv` presence for 11; Playwright import check for browser examples.
3. For each selected example, sequentially (the callback port 4199 is shared): `spawnExample()` the
   server process(es) on the **real** ports, wait for `/healthz` (https for 08), run the steps listed
   under "Smoke" in §6 with `MCP_BROWSER_CMD`, `EXPECT_ADMIN`, `MCP_RATE_LIMIT=0`, `MCP_NO_BROWSER`
   unset, a fresh `.mcp-auth/` per example (`MCP_AUTH_STORE_DIR=<tmp>` — add this env knob to
   `CliOAuthProvider.storeDir` default in Phase 0), parse the last `RESULT` line, compare with the
   expectation table, run the example's headline negative probe (raw `mcpPost` without a token →
   expected status + header shape), stop the processes.
4. Prints a pass/fail table (`example · step · expected · got · duration`), writes
   `test-results/smoke-<timestamp>.json`, exits non-zero on any failure. `--keep` leaves servers running.

Expectation table (the contract every implementer targets):

| Example | Client env | `whoami` assertion | `adminOnly` | Extra |
|---|---|---|---|---|
| 00 | – | `{anonymous:true}` | denied | `/mcp` w/o session → 400; no `WWW-Authenticate` anywhere |
| 01 | `MCP_API_KEY=demo-api-key-alice` / `…-bob` | `extra.sub` alice / bob | denied / ok | 401 header **without** `resource_metadata` |
| 02 | `DEMO_USER=alice` / `bob` | `extra.username` | denied / ok | 401 for `--expired` |
| 03 | browser (alice, then bob), refresh run, `OAUTH_CLIENT_ID=mcp-cli` | `extra.sub` | denied / ok | PRM + AS metadata at 4103; `/register` 201 |
| 04 | browser DCR (alice), refresh, `mcp-cli`, bob | `extra.username`, `clientId` = DCR uuid / `mcp-cli` | denied / ok | 401 header has `resource_metadata` + `scope`; PRM at 4104 |
| 05 | – (client_credentials) | `clientId=mcp-service` | denied | `service_only` ok; stretch `--auth private-key-jwt` |
| 06 | browser DCR, refresh, `mcp-cli` | as 04 | denied | PRM `authorization_servers=[facade]` |
| 07 | browser; then `ex:07:revoke -- alice`; client again | as 04 | denied | second run exits 1 with 401 |
| 08 | `MTLS_CLIENT=alice` / `bob` / `none` | `clientId` CN | denied / ok / (fail) | https only |
| 09 | browser via gateway | `extra.via=gateway` | denied | curl 4119 w/o assertion → 401 |
| 10 | browser | as 04 | denied | `extra.downstream.azp=mcp-server` |
| 11 | browser `OAUTH_CLIENT_ID=mcp-cli` (TS client), bonus py client | `subject`/`username` | denied | PRM shape equals 04 |

### 8.4 Tests vs smoke

`npm test` = vitest: unit + hermetic integration always; Keycloak-backed suites `describe.skipIf`.
`npm run test:kc` sets `REQUIRE_KEYCLOAK=1` so `isKeycloakUp()` failing throws instead of skipping
(CI uses this). `npm run smoke` is the only thing that opens a browser or uses the real ports.

---

## 9. Documentation plan

### 9.1 Files

```
docs/
  00-baseline-no-auth.md            (drafted)      06-oauth-proxy-keycloak.md
  01-api-key.md                                    07-token-introspection.md
  02-jwt-local.md                                  08-mtls.md
  03-oauth-embedded-as.md                          09-auth-gateway.md
  04-keycloak-resource-server.md                   10-token-exchange-downstream.md
  05-keycloak-client-credentials.md                11-python-mcp-keycloak.md
  comparison.md        the matrix (below) with prose per column and "choose … when" guidance
  spec-background.md   MCP authorization 2025-06-18 → 2025-11-25 as implemented by SDK 1.30.0: roles (client/AS/RS),
                       discovery sequence (WWW-Authenticate → RFC 9728 PRM → RFC 8414/OIDC → RFC 7591 DCR → PKCE →
                       RFC 8707 resource), SEP-835 scope selection, CIMD status, what the SDK does client- and server-side,
                       what it does not (client_credentials on the embedded AS, Basic auth at /token, DPoP, introspection server)
  threat-model.md      per threat: token leakage, replay, audience confusion, confused deputy, open redirect / redirect_uri,
                       PKCE downgrade, DCR abuse, DNS rebinding / Host, header trust behind gateways, session fixation/swap,
                       secret handling, rate limits, logging — each with "which examples demonstrate the control"
  keycloak.md          realm walk-through (every client/scope/mapper and why), admin console URLs, verified facts table (§7.2),
                       hardening (trusted hosts, PKCE enforcer policy, lightweight tokens, token lifetimes, DPoP), swapping the
                       IdP (Auth0 / Entra ID / Okta / GitHub: issuer, audience, DCR availability, token format)
  lan-testing.md       PUBLIC_HOST, the issuer-consistency rule, firewall ports (8180, 41xx, 4199), client-on-A/browser-on-B
                       (OAUTH_REDIRECT_HOST), running a client from another machine (MCP_SERVER_URL), Playwright on other hosts,
                       the plain-HTTP warning and how to add TLS
  patterns.md          docs-only patterns (§9.3)
  glossary.md          AS, RS, PRM, DCR, PKCE, resource indicator, audience, scope vs role, opaque vs JWT, introspection,
                       token exchange, sender-constrained, CIMD, session, Streamable HTTP terms
  plan.md              replaced by: status, the final catalog table, link to this design's decisions (kept for history)
```

### 9.2 Per-approach page template (`docs/NN-slug.md`)

1. Title, one-paragraph "what it is", metadata line (directory, port(s), AS, Keycloak?, spec grade
   CONFORMANT / PARTIAL / OUTSIDE-SPEC / TRANSITIONAL with the spec lines it exercises)
2. When to use / when not
3. Sequence diagram (mermaid) of the happy path
4. How the code does it — the auth-specific ~30 lines quoted with file references, and what
   `extra.authInfo` looks like in `whoami`
5. Run it (two terminals; LAN variant; expected output)
6. Observe it — `curl` snippets with the mandatory headers and the exact 401/403 responses
7. Break it — the negative cases and how each surfaces (mirrors `server.test.ts`)
8. Threat model notes (what this approach protects against, what it does not)
9. Variations and links (docs-only patterns, IdP swaps, related examples)

### 9.3 Docs-only patterns (`docs/patterns.md`)

stdio transport (full 30-line listing; env-based secrets; process boundary) · CIMD / SEP-991 vs DCR
(SDK `clientMetadataUrl`, Keycloak experimental `cimd`) · strict RFC 8707 resource indicators at the
AS (Keycloak experimental flag, Auth0 `audience`, Entra app-ID URI, Okta) · runtime step-up with
HTTP 403 `insufficient_scope` and the SDK's one-shot upscoping · sender-constrained tokens (DPoP RFC
9449, certificate-bound RFC 8705) · device authorization grant (RFC 8628) · private_key_jwt details
(if 05's stretch is not shipped) · browser-embedded MCP clients (CORS, token storage, BFF) ·
token-issuing proxies vs the SDK facade and the consent rule for static-client proxies ·
off-the-shelf gateways (Envoy ext_authz, Traefik forwardAuth, oauth2-proxy, NGINX auth_request,
Kong/APISIX) · enterprise-managed authorization (ID-JAG / jwt-bearer; `mcp` 2.1.1 hooks; Keycloak
`identity-assertion-jwt`) · workload identity (SPIFFE, Kubernetes SA tokens) · fine-grained
authorization beyond scopes (Keycloak Authorization Services / UMA, OPA, AuthZEN) · legacy HTTP+SSE
transport and "AS at the MCP origin without PRM" · session, replay and abuse controls · secrets,
rotation and lifetimes.

### 9.4 README outline

1. Title + one paragraph (what, for whom, MCP auth spec version, SDK version)
2. **Comparison matrix** (one row per example + docs-only rows): caller identity (user/workload/host),
   browser needed, IdP needed, discovery (PRM/AS), token type & validation, audience binding,
   revocation latency, client registration, spec grade, effort, "use when"
3. Quick start: clone → `npm install` → copy `.env.example` → set `PUBLIC_HOST` → `npm run ex:01:server` /
   `ex:01:client` (no Keycloak) → `npm run kc:up` → `ex:04:server` / `ex:04:client`
4. Running from another LAN machine (pointer to `docs/lan-testing.md`)
5. The examples — one line each with links to `examples/NN` and `docs/NN`
6. How the pieces fit: shared modules, the three demo tools, the effective-scopes contract
7. Keycloak (pointer), Verification (`npm test`, `npm run test:kc`, `npm run smoke`), CI
8. Security notes (DEMO credentials, plain HTTP, `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL`, what to change for production)
9. Contributing / license

---

## 10. Implementation order and ownership

**Phase 0 — shared foundation (one agent, sequential, ~1 day).** Branch `feat/keycloak-shared`
(current). Deliver: `src/shared/prm.ts` (+test), `src/shared/keycloak.ts` (+test), `printResult`,
`MCP_BROWSER_CMD` + `MCP_AUTH_STORE_DIR` in `oauth-cli.ts`, `testing.ts` additions (§5.9, `mcp-test`
default), `scripts/browser-login.py`, `scripts/smoke.ts` (framework + the 00/01 rows; other rows are
filled in Phase 3 from the expectation table), `scripts/gen-certs.sh`, `kc.sh keys`, realm deltas
(§7.3), `.env.example` (§5.12), `package.json` scripts + `undici`, `vitest.config.ts` env,
`tests/conventions.test.ts`, `src/shared/README.md` update, this design saved as `docs/plan.md`
content. Definition of done: `npm run typecheck`, `npm test` (Keycloak up) green; `kc:reset` imports
the new realm; smoke passes for 00. Then **freeze** and open the PR.

**Phase 1 — examples in parallel (one agent per example, same checkout, each owning only
`examples/NN-*/**` and `docs/NN-*.md`; no edits outside).** Two waves only to keep review load sane;
there is no code dependency between examples (each imports shared only, and 05/07/09/10 copy 04's
20 verifier lines rather than importing 04):

* Wave A: **01, 02, 03, 04, 05, 08** (01/02/08 need no Keycloak; 03 is the long pole — start first).
* Wave B: **06, 07, 09, 10, 11** (all Keycloak-backed; 10 and 11 are the other long poles).

Per-example DoD: `server.test.ts` covers every row of its negative matrix; `README.md` run/verify/
break commands are exactly what the tests/smoke run; docs page complete per §9.2; typecheck + tests
green in the shared checkout; the smoke row for the example passes locally
(`npm run smoke -- NN`). Each agent commits only its own paths; the integrator merges.

**Phase 2 — integration (one agent).** Fill the smoke expectation rows, run the full smoke on the
dev box from a clean `.mcp-auth/`, run `npm run test:kc`, fix cross-cutting issues (shared changes
requested in example READMEs), finish `ci.yml` (Python 3.14 + uv, Playwright chromium, smoke job
with Keycloak service container, artifacts), write `comparison.md`, `spec-background.md`,
`threat-model.md`, `keycloak.md`, `lan-testing.md`, `patterns.md`, `glossary.md`, README.

**Phase 3 — adversarial verification.** A fresh agent follows only README + each `docs/NN` page on a
clean clone, including from a second LAN machine (`MCP_SERVER_URL=http://192.168.78.87:41NN/mcp`),
and files issues; a security-review agent checks each example against `threat-model.md`
(token logging, redirect validation, header trust, audience binding, error-message injection).
Fixes → PR → release `v0.1.0`.

---

## 11. Risks and open questions

| Risk | Mitigation |
|---|---|
| Plain-HTTP LAN demo (tokens/codes/passwords in cleartext; spec requires HTTPS AS endpoints) | Loud banners in README/threat-model; `env.ts` prints a one-line warning when the flag is set; `lan-testing.md` shows TLS-terminated Keycloak + dev CA as the upgrade path |
| SDK reads `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` once at module load | Import-order rule + `tests/conventions.test.ts` |
| `bearerAuth.js` interpolates verifier error messages into `WWW-Authenticate` unescaped | Static messages only; conventions test greps verifier `new InvalidTokenError(` arguments for template literals |
| `mcp-service-jwt` attribute name (`jwt.credential.public.key`) unverified | Stretch item in 05; drop from the template if the import complains |
| 10: covering the "subject token lacks the requester audience" rule needs a token without `mcp:tools` — `mcp-test` has it as a default scope | Test via `scope=email` and inspect `aud`; if `aud` is still present, document the rule instead of asserting it |
| Keycloak exact redirect-URI matching (no loopback port relaxation) | Port 4199 fixed and registered thrice; smoke runs examples sequentially; concurrent clients need a `OAUTH_CALLBACK_PORT` change + `kc:reset` |
| Anonymous DCR is open (Trusted Hosts removed) | Demo realm; hardened variant verified by the security proposal and documented; `max-clients` 200; `kc:reset` cleans up |
| Rate limits (50 `/token` per 15 min per IP) | `MCP_RATE_LIMIT=0` in tests/smoke; documented defaults; one test asserts the 429 with limits on |
| Python `mcp` 2.1.1 is a fresh major; PRM route / 401 header behaviour with `AuthSettings.resource_server_url` unverified | Fallback `create_protected_resource_routes`; the TS client tolerates root-PRM fallback; CI job for 11 allowed-to-fail until stable |
| undici fetch + SSE in Node 22 (08) | Verify early in 08; fallback `node:https` Agent shim |
| Playwright selectors drift with Keycloak themes | Role/label fallbacks + screenshot on failure; selectors re-verified on first DCR consent run |
| Keycloak session state across test runs (DCR'd clients, consent grants) | `kc:reset` before smoke in CI; tests use fresh `.mcp-auth/` dirs |
| Clock skew between LAN machines | `clockToleranceSec: 5` (JWT) / `leeway=5` (Python); NTP note in `lan-testing.md` |
| TypeScript 7 native compiler vs `tsx` on NodeNext + `.ts` imports | Both pass today (**verified**); pin versions in `package-lock.json` |

Open questions for the integrator (do not block Phase 1): (a) keep `mcp-test` in the public realm
(recommended, clearly labelled) or a test-only overlay realm; (b) ship a `--profile tls` compose
variant later; (c) promote runtime step-up (403 `insufficient_scope`) to a shared middleware in v0.2;
(d) whether 11 should additionally show `fastmcp` in a sub-folder once it supports `mcp` 2.x.
