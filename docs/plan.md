# Implementation plan — mcp-auth-demo

> **Status: draft v0.1 (2026-08-28).** An automated design pass (exact API map of the installed
> `@modelcontextprotocol/sdk` 1.30.0 + three independent architecture proposals + a synthesis) is
> refining this plan; changes land in this document as they are decided. Everything below is the
> working plan the implementation is being built against.

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

| # | Directory | Approach | Category | Authorization server | Keycloak? | Port |
|---|---|---|---|---|---|---|
| 00 | `examples/00-baseline-no-auth` | Unauthenticated Streamable HTTP server + client — the reference every other example modifies | baseline | – | no | 4100 |
| 01 | `examples/01-api-key` | Static API key / bearer secret, per-key identity + scopes, constant-time compare | shared secret | – | no | 4101 |
| 02 | `examples/02-jwt-local` | Locally issued JWT (RS256) verified against a local JWKS; claims → scopes → tool authorization. The stepping stone to an IdP | self-issued token | tiny `issue-token` script | no | 4102 |
| 03 | `examples/03-oauth-embedded-as` | The MCP server **is** an OAuth 2.1 authorization server: SDK `mcpAuthRouter`, in-memory provider, login page, Dynamic Client Registration, PKCE, refresh | OAuth 2.1 (embedded AS) | the MCP server | no | 4103 |
| 04 | `examples/04-oauth-keycloak-resource-server` | **Spec-recommended pattern.** Keycloak is the AS; the MCP server is a pure Resource Server: publishes Protected Resource Metadata (RFC 9728), returns `WWW-Authenticate … resource_metadata=`, validates JWTs via JWKS (issuer, audience, expiry), maps scopes → tools. Client discovers everything from the 401 | OAuth 2.1 (external AS) | Keycloak | yes | 4104 |
| 05 | `examples/05-keycloak-client-credentials` | Machine-to-machine: confidential client with a service account, `client_credentials` grant, no browser; role-based tool gating | OAuth 2.1 (M2M) | Keycloak | yes | 4105 |
| 06 | `examples/06-oauth-proxy-keycloak` | MCP server as an OAuth **facade** in front of Keycloak (SDK `ProxyOAuthServerProvider`): clients only ever talk to the MCP server; useful when the IdP must stay hidden or clients cannot do DCR against it | OAuth 2.1 (proxied AS) | Keycloak, via the MCP server | yes | 4106 |
| 07 | `examples/07-token-introspection` | Opaque / reference tokens validated with RFC 7662 introspection against Keycloak (server-side call per request, with caching); shows the JWT-vs-opaque trade-off | OAuth 2.1 (opaque tokens) | Keycloak | yes | 4107 |
| 08 | `examples/08-mtls` | Mutual TLS: the client presents a certificate, the server maps the certificate subject to an identity; generated dev CA + certs via script | transport-level | – | no | 4108 |
| 09 | `examples/09-auth-gateway` | Auth gateway / sidecar in front of an **unauthenticated** MCP server: the gateway validates Keycloak tokens and forwards trusted identity headers; the MCP server only accepts traffic from the gateway (trust boundary explained) | infrastructure | Keycloak | yes | 4109 (gateway) / 4119 (internal) |
| 10 | `examples/10-token-exchange-downstream` | On-behalf-of: the MCP server exchanges the caller's token (RFC 8693, Keycloak standard token exchange) for a token scoped to a downstream API and calls it as the user (no confused deputy) | OAuth 2.1 (delegation) | Keycloak | yes | 4110 (MCP) / 4190 (downstream API) |
| 11 | `examples/11-python-fastmcp-keycloak` | Python twin of #04 to show the pattern is SDK-agnostic | language twin | Keycloak | yes | 4111 |

**Decided in the design pass (may still change):** whether #07, #10 and #11 are implemented or
documented only, depending on what SDK 1.30.0 / Keycloak 26.7 support out of the box.

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

1. **Scaffold + shared + Keycloak** (this PR): package, tooling, `src/shared`, compose + realm, baseline example.
2. **Examples in parallel**: one agent per example, each owning only its example directory and its
   docs page; shared code is frozen during this phase.
3. **Adversarial verification**: README-only reproduction + security review per example; fixes.
4. **Docs + README**: comparison matrix, guides, completeness check.
5. **Release** `v0.1.0` after the PR is merged (releases are immutable; patch bumps thereafter).

## 10. Open questions (being answered by the design pass)

* Does the SDK 1.30.0 client `OAuthClientProvider` support `client_credentials` natively, or does
  example 05 call the token endpoint directly?
* Keycloak redirect-URI wildcard rules vs. the LAN callback host — pre-register a list or rely on DCR?
* Python twin: `mcp` 2.x low-level API vs. `fastmcp` 3.x — which reads better for the docs?
* Token exchange in Keycloak 26.7: standard (RFC 8693) vs. legacy preview flag — confirm the exact
  realm settings required.
