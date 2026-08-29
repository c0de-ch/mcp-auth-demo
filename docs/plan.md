# Implementation plan — mcp-auth-demo

> **Status: decided (2026-08-29).** The design pass is complete: an exact API map of the installed
> `@modelcontextprotocol/sdk` 1.30.0, three independent architecture proposals (spec purist, DX
> pragmatist, security engineer) and a judged synthesis. **[`docs/design.md`](design.md) is the
> single source of truth** for the implementation — per-example specifications, shared-module API,
> Keycloak realm, negative-test matrices, smoke expectations, docs plan. This page keeps the short
> version: goal, stack, catalog, phases.

## 1. Goal

A public reference repository with **runnable MCP server + client pairs, one per authentication
approach**, Keycloak included, plus a `docs/` page per approach and a README that compares them.
A reader should be able to clone, run one command per example, and understand each approach from a
small, readable `server.ts` + `client.ts` pair.

## 2. Stack (fixed)

| Piece | Choice | Notes |
|---|---|---|
| Runtime | Node 22, TypeScript 7 (`tsc --noEmit` typecheck), `tsx` runner, Vitest 4 | ESM, `NodeNext` resolution |
| MCP | `@modelcontextprotocol/sdk` **1.30.0** | Streamable HTTP transport; SDK auth helpers (`mcpAuthRouter`, `requireBearerAuth`, `ProxyOAuthServerProvider`, client `OAuthClientProvider`) |
| HTTP | Express 5 | required by the SDK auth router |
| Tokens | `jose` 6 | JWT/JWKS verification, local key generation |
| IdP | **Keycloak 26.7.2** via Docker Compose | host port **8180** (8080 is taken on the dev box) |
| Browser tests | Playwright (Python, headless Chromium) | drives Keycloak / embedded-AS login pages |
| Secondary language | Python 3.14 + `uv` (`mcp` 2.1.1 / `fastmcp` 3.x) | one "twin" example, see catalog |

Guiding rules (from the owner's global conventions):

* Servers **bind `0.0.0.0`**; the demo is tested from other LAN machines, never only from localhost.
* Every issuer / resource / callback URL is **env-driven** from a single `PUBLIC_HOST` (default:
  the machine's LAN IP, e.g. `192.168.78.87`). Nothing is hard-coded to `localhost`.
* No real secrets are committed. Demo credentials are clearly labelled and live in `.env.example`.
* Feature branch → PR for every change; `main` is never committed to directly.

## 3. Approach catalog

Numbered from simplest to most complete. Each example is **architecturally distinct** — not a
variation of a neighbour — and consists of `examples/<nn>-<slug>/{server.ts, client.ts, README.md}`
plus `docs/<nn>-<slug>.md`.

| # | Directory | Approach | Category / spec grade | Keycloak? | Port |
|---|---|---|---|---|---|
| 00 | `examples/00-baseline-no-auth` | Unauthenticated Streamable HTTP pair — the reference every other example modifies | baseline (auth is optional in MCP) | no | 4100 |
| 01 | `examples/01-api-key` | Static API key as Bearer secret; hashed key table, per-key scopes, constant-time compare | shared secret (outside-spec; RFC 6750 syntax only) | no | 4101 |
| 02 | `examples/02-jwt-local` | Self-issued RS256 JWT verified via a JWKS URL served by a tiny local issuer; strict URL audience | self-issued token (outside-spec: no AS/discovery) | no | 4102 (+ issuer 4192) |
| 03 | `examples/03-oauth-embedded-as` | The MCP server **is** the OAuth 2.1 AS: `mcpAuthRouter`, login + consent pages, DCR, PKCE, refresh rotation, revocation | OAuth 2.1, AS co-located (conformant) | no | 4103 |
| 04 | `examples/04-keycloak-resource-server` | **Spec-recommended pattern**: Keycloak is the AS, the MCP server a pure Resource Server (PRM + JWKS, audience + scope checks) | OAuth 2.1, external AS (conformant; Keycloak ignores `resource`) | yes | 4104 |
| 05 | `examples/05-keycloak-client-credentials` | Machine-to-machine: service account, `client_credentials` (`client_secret_basic`; `private_key_jwt` as stretch) | OAuth 2.1 M2M (conformant) | yes | 4105 |
| 06 | `examples/06-oauth-proxy-keycloak` | MCP server as OAuth facade in front of Keycloak (`ProxyOAuthServerProvider`, DCR passthrough) | OAuth 2.1 proxied AS (transitional) | yes | 4106 |
| 07 | `examples/07-token-introspection` | RFC 7662 introspection with TTL cache — revocation visible immediately (contrast with 04) | OAuth 2.1 stateful validation (conformant) | yes | 4107 |
| 08 | `examples/08-mtls` | Mutual TLS: the client certificate is the credential; demo PKI script | transport-level (outside-spec) | no | 4108 (https) |
| 09 | `examples/09-auth-gateway` | Gateway validates tokens + serves PRM, reverse-proxies with a signed identity assertion to an internal server | infrastructure trust boundary | yes | 4109 (+ internal 4119) |
| 10 | `examples/10-token-exchange-downstream` | On-behalf-of: RFC 8693 standard token exchange (Keycloak) to call a downstream API as the user | OAuth 2.1 delegation (conformant) | yes | 4110 (+ downstream 4190) |
| 11 | `examples/11-python-mcp-keycloak` | Python twin of 04 with the official `mcp` 2.1.1 SDK; the TypeScript client is unchanged | language twin / interop (conformant) | yes | 4111 |

**Decided:** 07 (introspection), 10 (token exchange) and 11 (Python twin) are implemented — all three
were verified against the running Keycloak / installed SDKs before the decision. stdio, CIMD,
runtime step-up (403 `insufficient_scope`) and the rest of the list below stay docs-only.
Verified facts that shaped the design: Keycloak does not substitute `${env.X}` in realm imports
(hence the render step in `scripts/kc.sh`); defining `clientScopes` in an import suppresses the
built-in scopes (so the template carries them); anonymous DCR rejects `openid` as a scope; Keycloak
ignores RFC 8707 `resource`; standard token exchange needs `scope=downstream-api` in the request;
the SDK reads `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` once at module load (import-order rule).

### Documented but not implemented (`docs/patterns.md`)

* stdio transport — the OS process boundary *is* the auth boundary
* browser-embedded MCP clients — cookies / sessions / CSRF considerations
* Client ID Metadata Documents (CIMD) as an alternative to Dynamic Client Registration
* Device Authorization Grant for headless / TV-style clients
* DPoP / sender-constrained tokens
* Off-the-shelf gateways: Envoy `ext_authz`, Traefik `forwardAuth`, oauth2-proxy, Kong, API gateways
* Swapping the IdP: Auth0, Microsoft Entra ID, Okta, GitHub — what changes (issuer, audience, scope names)
* Secrets management, rate limiting, audit logging

## 4. Repository layout

```
mcp-auth-demo/
├── README.md                  # overview + comparison matrix + quick start
├── docs/                      # one page per approach + cross-cutting guides
├── examples/<nn>-<slug>/      # server.ts, client.ts, README.md, .env.example, tests/
├── src/shared/                # code shared by all examples (see §5)
├── keycloak/                  # docker-compose.yml, realm-mcp.json (realm import), README
├── scripts/                   # smoke-all, cert generation, token minting helpers
├── tests/                     # cross-example integration tests
├── package.json               # single package; scripts: ex:<nn>:server / ex:<nn>:client
└── tsconfig.json
```

A **single npm package** (no workspaces) keeps the mental model small: every example is two files
that import from `src/shared`.

## 5. Shared modules (`src/shared/`)

| Module | Exports | Purpose |
|---|---|---|
| `env.ts` | `PUBLIC_HOST`, `port(name, default)`, `KEYCLOAK_URL`, `KEYCLOAK_REALM`, `publicUrl(port)` | one place for every URL/port; all overridable via env / `.env` |
| `tools.ts` | `createDemoServer(name)` | registers the same three demo tools on every server: `whoami` (echoes the caller's `AuthInfo`), `add`, and `admin_only` (gated by scope/role) |
| `http.ts` | `startHttpServer({ port, authMiddleware?, extraRoutes? })` | Express 5 bootstrap on `0.0.0.0`, health endpoint, request logging, Streamable HTTP transport with session handling |
| `jwt.ts` | `verifyJwt({ issuer, audience, jwks })` → `AuthInfo` | `jose` JWKS verification used by every JWT-based example |
| `client/oauth-cli.ts` | `CliOAuthProvider` | SDK `OAuthClientProvider` for CLIs: local callback server on `0.0.0.0` with a configurable public callback URL, opens the browser (`xdg-open`/`open`) or prints the URL, file-based token store in `.mcp-auth/` (git-ignored) |
| `client/run.ts` | `runDemoClient(transport)` | connect → list tools → call `whoami`, `add`, `admin_only` → print, so every `client.ts` stays tiny |
| `testing.ts` | `startEphemeral(serverFactory)`, `mintTestToken()` | helpers for Vitest integration tests |

## 6. Keycloak

`keycloak/docker-compose.yml` runs `quay.io/keycloak/keycloak:26.7.2` with `start-dev --import-realm`.

* Host port **8180** (`8080` is occupied on the dev machine).
* Issuer pinned with `KC_HOSTNAME=http://${PUBLIC_HOST}:8180` so `iss` in tokens is identical no
  matter whether Keycloak is reached via localhost, LAN IP or hostname. Verified: without pinning,
  the issuer follows the request `Host` header, which breaks validation across machines.
* Realm **`mcp`** (imported from `keycloak/realm-mcp.json`):
  * users `alice` (role `mcp-user`) and `bob` (roles `mcp-user`, `mcp-admin`), demo password `password`
  * client `mcp-cli` — public, PKCE S256, redirect URIs for loopback and the LAN callback
  * client `mcp-service` — confidential, service account enabled (example 05)
  * client `mcp-server` — confidential; used for introspection (07) and token exchange (10)
  * client scopes `mcp:tools`, `mcp:admin`; an **audience mapper** so access tokens carry
    `aud=mcp-server` (resource binding — RFC 8707 style), plus `downstream-api` audience for 10
  * anonymous Dynamic Client Registration policy so example 04 can demonstrate DCR as well as the
    pre-registered client
  * standard token exchange enabled for example 10

## 7. Verification (all headless)

* `npm run typecheck`, `npm test` (Vitest): per example an integration test starts the server on an
  ephemeral port and asserts the **positive path** and the **rejection paths** — missing token,
  expired, wrong issuer, wrong audience, missing scope → `401`/`403` with correct
  `WWW-Authenticate` (`resource_metadata=` for the OAuth examples).
* Browser flows (03, 04, 06, 10): a Playwright script performs the login headlessly and asserts the
  client ends up calling `whoami` successfully.
* `npm run smoke` runs every example end-to-end against a running Keycloak.
* GitHub Actions workflow: typecheck + tests, Keycloak as a service container.
* A final **adversarial verification pass**: a fresh agent follows only each README and reports
  whether the instructions actually work; each approach also gets a security review against the
  threat model page.

## 8. Documentation

* `docs/<nn>-<slug>.md` per approach: what it is, when to use it, sequence diagram, how it works in
  the code, how to run, how it can fail, threat model, variations.
* `docs/comparison.md` — matrix: identity of caller, human vs machine, needs browser, needs IdP,
  spec conformance, token type, revocation, multi-tenant fit, effort, recommended for …
* `docs/spec-background.md` — MCP authorization spec (2025-06-18 and later), the RFCs it cites
  (6749/6750, 7591, 7636, 8414, 8707, 9728, 8693, 7662) and how the SDK implements them.
* `docs/threat-model.md` — token leakage, confused deputy, audience binding, replay, redirect URI
  validation, DNS rebinding, header trust behind gateways, secret handling.
* `docs/keycloak.md` — realm design, admin console walkthrough, how to swap in another IdP.
* `docs/lan-testing.md` — running from another machine on the LAN, `PUBLIC_HOST`, firewall notes.
* `docs/patterns.md` — the documented-only patterns from §3.
* `docs/glossary.md`.
* `README.md` — overview, comparison table with links, quick start, per-example run commands.

## 9. Delivery phases

0. **Shared foundation** (PR #1 merged the plan/scaffold; branch `feat/keycloak-shared`): Keycloak
   stack, `src/shared/*`, baseline example 00, CI workflow; then the Phase-0 additions from
   `design.md` §10 (PRM helper, Keycloak helper, browser driver, smoke framework, PKI script, realm
   deltas). Shared code is **frozen** afterwards.
1. **Examples in parallel** — wave A: 01, 02, 03, 04, 05, 08; wave B: 06, 07, 09, 10, 11. One agent
   per example, each owning only `examples/NN-*/**` and `docs/NN-*.md`.
2. **Integration**: smoke matrix, `npm run test:kc`, cross-cutting docs (`comparison`, `spec-background`,
   `threat-model`, `keycloak`, `lan-testing`, `patterns`, `glossary`), README, CI completion.
3. **Adversarial verification**: README-only reproduction on a clean clone and from a second LAN
   machine, security review against the threat model; fixes.
4. **Release** `v0.1.0` after the PR is merged, with Sigstore **cosign** keyless signing of the
   release artifacts and `cosign verify` instructions (releases are immutable; patch bumps thereafter).

## 10. Open questions — answered

* `client_credentials`: the SDK ships `ClientCredentialsProvider` / `PrivateKeyJwtProvider`
  (`client/auth-extensions.js`); the embedded AS (03) cannot serve the grant, Keycloak can.
* Keycloak matches redirect URIs exactly (no loopback-port relaxation): the callback port 4199 is
  fixed and registered for `localhost`, `127.0.0.1` and `PUBLIC_HOST`; DCR registers its own URI.
* Python twin uses the official `mcp` 2.1.1 (`MCPServer` + `TokenVerifier` + `AuthSettings`);
  `fastmcp` 3.x still pins `mcp<2` and is mentioned as a variation.
* Token exchange: Keycloak 26 **standard** token exchange (client attribute
  `standard.token.exchange.enabled`), no preview feature flag — verified with curl.

Remaining risks and integrator questions are tracked in `design.md` §11.
