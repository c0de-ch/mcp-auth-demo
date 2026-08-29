# Keycloak guide

Every example that needs a real identity provider uses **Keycloak 26.7.2**, started by
`npm run kc:up` and configured by a single imported realm. This page explains what is in that realm
and why, which facts were verified against the running server, how to harden the demo settings, and
what changes if you point the examples at a different provider.

Quick reference is in [`keycloak/README.md`](../keycloak/README.md); this page is the reasoning
behind it.

## Starting and stopping

```bash
npm run kc:up       # render the realm, start the container, wait for the realm endpoint
npm run kc:status   # container state + the issuer Keycloak actually advertises
npm run kc:logs     # follow the container log
npm run kc:reset    # down -v + re-import (wipes DCR-registered clients and sessions)
npm run kc:down     # stop
npm run kc:keys     # regenerate the RSA key pair used by the private_key_jwt client
```

The stack is [`keycloak/docker-compose.yml`](../keycloak/docker-compose.yml): the container listens
on 8080 internally and is published on **host port 8180** (`KEYCLOAK_PORT`), because 8080 is
commonly taken. Storage is the dev-mode embedded database — `kc:reset` is the intended way to get
back to a clean realm.

### The issuer must be pinned

`KC_HOSTNAME` is set to `http://${PUBLIC_HOST}:${KEYCLOAK_PORT}`. Without it Keycloak derives its
issuer from the request's `Host` header, so a token fetched via `localhost` would carry
`iss: http://localhost:8180/realms/mcp` while a resource server reached over the LAN expects
`http://192.168.1.10:8180/realms/mcp`, and validation fails with a confusing "wrong issuer" error.

Verified: with the hostname pinned, `/realms/mcp/.well-known/openid-configuration` returns the same
`issuer` whether it is requested through `127.0.0.1`, the LAN address or a host name, and every
token carries that one value. `src/shared/env.ts` derives the identical string, the Protected
Resource Metadata advertises it, and clients discover it from there — so the only thing a tester
must get right is `PUBLIC_HOST`. See [lan-testing.md](lan-testing.md).

## The realm

The realm is generated from [`keycloak/realm-mcp.template.json`](../keycloak/realm-mcp.template.json)
by `scripts/kc.sh`, which substitutes `{{PUBLIC_HOST}}`, `{{OAUTH_CALLBACK_PORT}}` and the demo
secrets into `keycloak/.generated/realm-mcp.json` (git-ignored).

**Why a render step:** Keycloak does not substitute `${env.X}` placeholders inside imported realm
files. It validates redirect URIs while parsing the import and rejects `${env.PORT}` with
`Invalid client mcp-cli: A redirect URI is not a valid URI`, so the substitution has to happen
before the file reaches the container.

### Users

| User | Password | Realm roles | Purpose |
|---|---|---|---|
| `alice` | `password` | `mcp-user` | the ordinary user — may call `whoami` and `add`, never `admin_only` |
| `bob` | `password` | `mcp-user`, `mcp-admin` | the privileged user — `admin_only` succeeds |
| `service-account-mcp-service` | – | `mcp-user` | service account of the M2M client (example 05) |
| `service-account-mcp-server` | – | – | service account used for introspection and token exchange (07, 10) |

These are demo credentials in a demo realm with brute-force protection disabled and no TLS. They
exist so the examples can be driven headlessly; do not copy this realm into anything real.

### Clients

| Client | Type | Flows | Used by |
|---|---|---|---|
| `mcp-cli` | public, PKCE S256 | authorization code | the pre-registered path of examples 03, 04, 06, 07, 09, 10, 11 (`OAUTH_CLIENT_ID=mcp-cli`) |
| `mcp-test` | public | direct access grant (password) only | **tests only** — headless token minting; see the note below |
| `mcp-service` | confidential, secret | client credentials (service account) | example 05 |
| `mcp-service-jwt` | confidential, `client-jwt` (RS256) | client credentials with `private_key_jwt` | example 05 variant |
| `mcp-server` | confidential, secret, token exchange enabled | introspection caller, exchange requester | examples 07, 10 |
| `downstream-api` | confidential placeholder | none | the audience of the exchanged token (example 10) |

**`mcp-cli` has the password grant disabled on purpose.** The resource owner password credentials
grant was removed from OAuth 2.1: a public client that can exchange a username and password for a
token is exactly what PKCE and the browser redirect exist to avoid. But the test suite needs tokens
without a browser, so the realm carries a separate, clearly labelled `mcp-test` client that allows
it. Keeping the two apart means the client the documentation tells you to use cannot be misused,
and the test-only shortcut is visible as a shortcut. `src/shared/testing.ts` mints tokens through
`mcp-test`; asking Keycloak for a password grant on `mcp-cli` returns `unauthorized_client`.

Redirect URIs of `mcp-cli` are registered three times — `http://localhost:4199/callback`,
`http://127.0.0.1:4199/callback` and `http://${PUBLIC_HOST}:4199/callback`. Verified: Keycloak
matches redirect URIs **exactly** and does not relax the port for loopback addresses the way
RFC 8252 permits (a request on port 5555 fails with `Invalid parameter: redirect_uri`), which is
why the callback port is fixed at `OAUTH_CALLBACK_PORT` (4199) rather than random.

### Client scopes and the audience

| Scope | Default? | What it adds |
|---|---|---|
| `mcp:tools` | default | audience `mcp-server`, realm roles, `preferred_username` |
| `mcp:admin` | optional | audience `mcp-server` |
| `downstream-api` | optional | audience `downstream-api` |

The audience mappers are what bind a token to a resource. A token minted for the MCP servers
carries `aud: "mcp-server"`; the resource servers reject anything else, so a token stolen from a
different application of the same realm is useless against them, and the exchanged token of
example 10 (`aud: "downstream-api"`) is rejected by the MCP servers — verified, and asserted in the
tests of examples 04 and 10.

**One logical audience, not one per example.** Every MCP example validates `aud: mcp-server`
(overridable with `MCP_AUDIENCE`) rather than its own URL. Keycloak ignores the RFC 8707 `resource`
parameter — verified: sending `resource=http://192.168.1.10:4104/mcp` on the token request leaves
`aud` unchanged — and its experimental `resource-indicators` feature rejects any resource that is
not pre-registered, which breaks the SDK client because it always sends `resource=` once it has
found a Protected Resource Metadata document. Per-example audiences would therefore mean seven more
scopes and port-dependent mappers for little teaching value. Example 02 shows the strict URL-audience
form against a local issuer instead, and [patterns.md](patterns.md) documents strict resource
indicators.

**Role scope mappings** (`mcp:tools` → `mcp-user`, `mcp:admin` → `mcp-admin`) matter more than they
look. Dynamically registered clients have full scope disabled, so without these mappings their
tokens contain no `realm_access.roles` at all and `bob` could never reach `admin_only` through the
DCR flow. The same reason puts the roles and `preferred_username` mappers on the `mcp:tools` scope:
a DCR client only receives the `basic` scope plus what it asks for.

This is also where the repository's **effective scopes** contract comes from: a token's `scope`
says what the client was granted, a realm role says what the user is allowed to do, and
`keycloakEffectiveScopes` in `src/shared/jwt.ts` keeps `mcp:admin` only when both agree. Alice can
ask for `mcp:admin` and Keycloak will put it in her token's `scope` — she still does not get the
tool, because she does not hold the role.

### Dynamic Client Registration

Anonymous registration is **open** in this realm: the `trusted-hosts` policy is removed so an
example can register a client with no prior relationship, which is the flow the MCP specification
expects. The remaining policies still apply — consent required, full scope disabled, at most 200
clients, and an allow-list of `mcp:tools`, `mcp:admin`, `offline_access`.

Verified: `POST /realms/mcp/clients-registrations/openid-connect` with
`"scope": "mcp:tools"` returns a public client; including `openid` in the requested scope is
rejected with `insufficient_scope` ("Not permitted to use specified clientScope") because `openid`
is not a Keycloak client scope. `src/shared/client/oauth-cli.ts` therefore never asks for it.

Registered clients persist in the realm — one per machine and per fresh token store. `kc:reset`
clears them.

**Hardened variant** for anything beyond a demo: restore the trusted-hosts policy with
`client-uris-must-match: true` and an explicit host list, or disable anonymous registration
entirely and pre-register clients.

### Token exchange

`mcp-server` carries the attribute `standard.token.exchange.enabled: true` — Keycloak 26's
standard, RFC 8693-shaped token exchange, not the older preview feature. Verified: exchanging
alice's token for `audience=downstream-api` returns a token with `aud: downstream-api`,
`azp: mcp-server` and alice's `sub`; the request must include `scope=downstream-api` or Keycloak
answers `invalid_request: Requested audience not available`; and the subject token must itself
carry `mcp-server` in its audience. Example 10 builds on exactly this.

### Introspection

Verified: `POST /realms/mcp/protocol/openid-connect/token/introspect` with HTTP Basic
`mcp-server` credentials returns `{ active: true, aud: "mcp-server", scope, username, client_id, exp }`.
Keycloak only reports `active: true` to a client that is inside the token's audience, which the
realm guarantees for `mcp-server`. Example 07 relies on it and checks the audience again itself.

## Verified facts, at a glance

Everything below was checked against the running container while building this repository.

| Fact | Consequence |
|---|---|
| `${env.X}` is not substituted in realm imports | `scripts/kc.sh` renders the realm first |
| Defining `clientScopes` in an import replaces the built-ins | the template ships `profile`, `email`, `roles`, `web-origins`, `basic`, `acr`, `offline_access` explicitly |
| `sub` is emitted by the `basic` scope (Keycloak 25+) | the scope must stay on every client |
| Redirect URIs match exactly, no loopback port relaxation | fixed callback port, three registered URIs |
| Anonymous DCR rejects `openid` as a requested scope | the CLI provider requests `mcp:tools` only |
| DCR clients have full scope disabled | roles and `preferred_username` are mapped onto `mcp:tools` |
| `resource` is ignored; `resource-indicators` rejects unregistered resources | one logical audience `mcp-server` |
| Standard token exchange needs `scope=` and an audience-matching subject token | example 10's request shape |
| Introspection answers `active: false` to a client outside the audience | example 07's failure mode |
| Both `/realms/mcp/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server/realms/mcp` answer | the SDK client's discovery probe succeeds |
| Access token lifetime raised to 15 minutes | Keycloak's 60-second default makes demos flaky |

## Hardening this realm

The demo realm optimises for "clone and run". For anything else: serve Keycloak over TLS and drop
`MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` (see [lan-testing.md](lan-testing.md)); replace the demo
users and secrets; enable brute-force protection; restrict or disable anonymous DCR as above; add a
client policy that enforces PKCE for every public client; shorten token lifetimes and enable refresh
token rotation; consider lightweight access tokens if your resource servers only need a few claims;
and review the consent screens the DCR clients trigger. [threat-model.md](threat-model.md) lists
which of these mitigate which threat.

## Using a different identity provider

Nothing in the examples is Keycloak-specific beyond `src/shared/keycloak.ts` and the realm. A
resource server needs an issuer, a JWKS URL, an audience and a scope or role claim; the client
needs discovery and, ideally, dynamic registration.

| Provider | Discovery | DCR | Audience binding | Notes |
|---|---|---|---|---|
| Keycloak | RFC 8414 + OIDC | yes (policy-gated) | audience mapper on a client scope | this repository |
| Auth0 | OIDC | yes (`/oidc/register`, tenant setting) | `audience` request parameter, API identifier | RFC 8707 style via `audience`, not `resource` |
| Microsoft Entra ID | OIDC | no (app registration) | application ID URI, `aud` claim | admin consent for app roles |
| Okta | OIDC | yes (API) | authorization-server `audience` | custom AS per API |
| GitHub | none (no OIDC AS for apps) | no | – | OAuth 2.0 only; opaque tokens, introspection-style validation |

To switch, point `KEYCLOAK_URL`/`KEYCLOAK_REALM` (or the issuer of your own verifier) at the new
provider, set `MCP_AUDIENCE` to whatever it puts in `aud`, and map its role or group claim in place
of `realm_access.roles`. Providers without dynamic registration need a pre-registered client:
set `OAUTH_CLIENT_ID` and, for confidential clients, `OAUTH_CLIENT_SECRET`.
