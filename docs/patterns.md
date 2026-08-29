# Patterns this repository documents but does not run

The twelve examples cover the approaches that can be demonstrated end to end on a plain-HTTP LAN
with one Keycloak and no cloud account. This page covers the rest: patterns that are real, that you
will meet in production MCP deployments, and that were left out on purpose — because they need TLS,
a paid IdP tier, a Kubernetes cluster, or simply because they are one configuration flag away from
an example that already exists.

Every section answers the same four questions: **when** you would use it, **how** it works, **what
it would take here**, and where to read on. Nothing on this page is executed by `npm test` or
`npm run smoke`; code shown is either verified against the installed SDK (and said so) or marked as
a sketch.

Background for all of it: [spec-background](spec-background.md) for the protocol,
[sdk-notes](sdk-notes.md) for what `@modelcontextprotocol/sdk` 1.30.0 actually does.

---

## stdio transport: the process is the boundary

**When.** A local MCP server that a single desktop application or editor spawns for one user:
filesystem access, a local database, a wrapper around a CLI tool. This is still the most common way
MCP servers are shipped.

**How.** The client launches the server as a child process and speaks JSON-RPC over its stdin and
stdout — one message per line, no HTTP, no port, no listener. Authorization is the operating
system's: the pipe is private to the parent and the child, the child runs as the user who started
it, and any credential the server needs for *upstream* APIs is handed to it in its environment by
the parent. There is nobody to authenticate, because there is no way for a third party to speak to
the process at all.

This is why the MCP specification says, in the same breath as making authorization optional:
*"Implementations using an STDIO transport **SHOULD NOT** follow this specification, and instead
retrieve credentials from the environment."* Adding a bearer check to a stdio server would
authenticate the process against itself. What it must do instead is be careful about the two things
that *are* shared: the environment it inherits, and stdout.

A complete server — this listing was run against the installed SDK and answers `initialize` and
`tools/list` correctly:

```ts
#!/usr/bin/env -S npx tsx
/**
 * A complete MCP server over stdio. The client spawns this file; the OS process
 * boundary is the authorization boundary.
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

// Credentials come from the environment the parent process controls — never from the peer.
const API_TOKEN = process.env.WEATHER_API_TOKEN;
if (!API_TOKEN) {
  console.error('WEATHER_API_TOKEN is not set');   // stderr only: stdout is the JSON-RPC channel
  process.exit(1);
}

const server = new McpServer({ name: 'weather-stdio', version: '0.1.0' });

server.registerTool(
  'forecast',
  { title: 'Forecast', description: 'Forecast for a city.', inputSchema: { city: z.string() } },
  async ({ city }) => {
    const res = await fetch(`https://api.example.com/v1/forecast?city=${encodeURIComponent(city)}`, {
      headers: { Authorization: `Bearer ${API_TOKEN}` },
    });
    if (!res.ok) return { isError: true, content: [{ type: 'text', text: `upstream ${res.status}` }] };
    return { content: [{ type: 'text', text: await res.text() }] };
  },
);

// No port, no HTTP, no bearer token: stdin/stdout are private to parent and child.
await server.connect(new StdioServerTransport());
process.stderr.write('weather-stdio ready\n');
```

The rules that replace OAuth here:

* **Never write to stdout.** A stray `console.log` corrupts the JSON-RPC stream. Log to stderr; the
  SDK's `withLogging` client middleware defaults to `console` and must not be used with stdio.
* **Do not inherit the whole environment.** The parent decides what the child sees. A server that
  needs one API token should be given one API token, not the user's entire shell environment.
* **Least privilege is a process property.** File system scope, working directory, and user account
  are the access control; if the server must be constrained further, constrain the process
  (container, `systemd` unit, sandbox), not the protocol.
* **Trust the input anyway.** Being local does not make tool arguments safe — prompt injection
  reaches a stdio server exactly as it reaches an HTTP one.

**What it would take here.** Nothing but a thirteenth directory; the listing above is the whole
server. It is not an example because every other page in this repository is a comparison of *HTTP*
authorization, and stdio's answer to "how does the server authenticate the caller" is "it does not
have to".

**Read on.** [00 — baseline](00-baseline-no-auth.md) for the HTTP transport this replaces;
[09 — auth gateway](09-auth-gateway.md) for the same "the boundary is elsewhere" idea at network
level.

---

## Client ID Metadata Documents (SEP-991) vs DCR

**When.** You are shipping an MCP client that will meet authorization servers you have never heard
of, and you do not want a registration record created on each of them. Since the 2025-11-25
revision this is the spec's preferred answer — Dynamic Client Registration was demoted to **MAY**,
"included for backwards compatibility".

**How.** The client publishes a small JSON document at an HTTPS URL and uses that URL *as* its
`client_id`:

```json
{
  "client_id": "https://app.example.com/oauth/client-metadata.json",
  "client_name": "Example MCP Client",
  "client_uri": "https://app.example.com",
  "redirect_uris": ["http://127.0.0.1:4199/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

The AS sees a URL-shaped `client_id`, fetches it, checks that the document's `client_id` equals the
URL it fetched, validates the requested `redirect_uri` against the document's list, and shows
`client_name` on the consent screen. No registration endpoint, no client secret to expire, no
garbage records. It advertises the capability with
`"client_id_metadata_document_supported": true` in its RFC 8414 metadata.

Against DCR: DCR gives every installation its own `client_id` (good for revoking one machine, bad
for the AS's client table — this repository's realm caps it at `max-clients: 200` and
`npm run kc:reset` exists partly to clear the debris). CIMD gives one stable identity for the whole
product, which is what a consent screen wants to name, at the cost of a fetch the AS performs
against an attacker-supplied URL — hence the spec's SSRF warnings and the advice to display the
redirect host prominently, because a `localhost` redirect URI still lets a local attacker
impersonate a well-known client.

**What it would take here.** Two things this demo does not have, both verified:

* an HTTPS host for the document. `isHttpsUrl()` in the SDK requires `https:` **and** a non-root
  path, with no development override, and everything here runs on `http://192.168.78.87:…`;
* an AS that supports it. The bundled Keycloak 26.7.2 reports feature `CIMD` as
  `EXPERIMENTAL, enabled=false`, and its discovery document has no
  `client_id_metadata_document_supported` field. Enabling it means
  `--features=cimd` on the container and accepting a preview feature.

The client half is one property on the provider (`clientMetadataUrl`); the SDK then skips
registration entirely. There is no server half in the SDK — `mcpAuthRouter`'s AS cannot resolve a
URL-shaped `client_id`, so [03](03-oauth-embedded-as.md) could not be a CIMD server without
hand-rolled code.

**Read on.** [spec-background §5](spec-background.md#5-sep-991--client-id-metadata-documents);
[04](04-keycloak-resource-server.md) for the DCR flow it would replace.

---

## Strict RFC 8707 resource indicators at the authorization server

**When.** You run more than one MCP server against one authorization server and you want a token
minted for server A to be *unusable* at server B — enforced by the issuer, not by hope.

**How.** The client sends `resource=<canonical MCP URL>` on both the authorization and the token
request (the SDK does this automatically whenever a PRM was found). An AS that implements RFC 8707
mints a token whose audience is that exact URL, and rejects a `resource` value it does not
recognise with `invalid_target`. The resource server then validates `aud` against its own canonical
URL — a string comparison with no wiggle room.

**What it would take here.** The realm would have to stop ignoring the parameter. Verified state of
the bundled Keycloak 26.7.2: `resource=http://192.168.78.87:4104/mcp` on the token request leaves
`aud` as `mcp-server`, and the `RESOURCE_INDICATORS` feature is present but
`EXPERIMENTAL, enabled=false`. Turning it on (`--features=resource-indicators`) makes Keycloak
*strict*: it rejects any `resource` that is not registered on the client with `invalid_target` — and
the SDK client sends `resource=` on every request as soon as a PRM exists. So enabling it without
registering all seven MCP URLs on every client would break examples 04 through 11 at once. That
trade — one logical audience `mcp-server` for the whole realm, plus a per-URL audience shown in
[02](02-jwt-local.md) — is recorded in `docs/design.md` §2.

Other providers, for orientation (vendor behaviour, not verified in this repository):

| Provider | Mechanism |
|---|---|
| Auth0 | the non-standard `audience=` parameter on `/authorize` and `/oauth/token`, against a registered API identifier |
| Microsoft Entra ID | scopes are namespaced by the resource's Application ID URI (`api://<app-id>/mcp.tools`); the audience follows from the scope |
| Okta | one authorization server per API audience; the `audience` is a property of that server |
| Keycloak | `resource` ignored by default; strict with the experimental feature above; otherwise use an audience mapper on a client scope, which is what this realm does |

**Read on.** [02 — self-issued JWT](02-jwt-local.md) enforces an exact URL audience today;
[10 — token exchange](10-token-exchange-downstream.md) shows audience isolation between two
services; [spec-background §2](spec-background.md#2-the-discovery-sequence) for what the client
sends.

---

## Runtime step-up authorization

**When.** Most tools need `mcp:tools`; one tool needs `mcp:admin`. Asking every user to consent to
admin rights at connection time is the opposite of least privilege, so ask when the admin tool is
actually called.

**How.** The spec's *Scope Challenge Handling*: the server answers the `tools/call` with HTTP **403**
and

```http
HTTP/1.1 403 Forbidden
WWW-Authenticate: Bearer error="insufficient_scope",
                  scope="mcp:tools mcp:admin",
                  resource_metadata="http://192.168.78.87:4104/.well-known/oauth-protected-resource/mcp",
                  error_description="admin_only requires mcp:admin"
```

The `scope` value should be the *whole* set the client needs afterwards, not just the missing one —
otherwise the re-authorization drops the permissions it already had. The client then re-runs
authorization with that scope and retries the request.

The SDK client already implements this half, verified in `client/streamableHttp.js`: on a 403 whose
`WWW-Authenticate` carries `error="insufficient_scope"` it re-runs `auth()` with the challenged
scope and re-sends the message — **once per distinct header value**. A second identical challenge
throws `StreamableHTTPError(403, 'Server returned 403 after trying upscoping')`. Note that this path
calls `auth()` with the plain fetch, not the one carrying `requestInit` headers, so custom headers
are not applied during that discovery.

**What it would take here.** The blocker is the tool contract, not the protocol. `admin_only` in
`src/shared/tools.ts` returns a tool-level error (`isError: true`) rather than failing the HTTP
request, because that keeps all twelve examples comparable — every one of them shows the same
"denied" line. Making it a real 403 means giving the tool a way to abort the transport-level
request, which is a shared-code change:

```ts
// sketch — not in src/shared/tools.ts
import { InsufficientScopeError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
// inside a per-request middleware, before the JSON-RPC body reaches the transport:
if (methodNeedsAdmin(req.body) && !req.auth?.scopes.includes('mcp:admin')) {
  throw new InsufficientScopeError('mcp:admin required');   // → 403 + WWW-Authenticate
}
```

`requireBearerAuth` produces exactly that header shape when it is given `requiredScopes`, but it
applies to the whole endpoint, not to one tool — and pinning `requiredScopes` there has a cost of
its own, see [spec-background §3](spec-background.md#3-sep-835--scope-selection-and-the-trap-this-repository-hit).

**Read on.** [04](04-keycloak-resource-server.md) for where `mcp:admin` comes from and why alice
does not get it; `docs/design.md` §2 records the decision to keep this docs-only in v0.1.

---

## Sender-constrained tokens

**When.** A bearer token is a bearer secret: whoever holds it, uses it. Sender constraint binds a
token to a key the client holds, so a stolen token is useless without the key. Worth it for
high-value APIs, for tokens that cross more hops than you can audit, and increasingly required by
regulated profiles (FAPI 2.0).

**How.** Two standards, both supported by the bundled Keycloak and neither by the SDK.

**DPoP (RFC 9449)** — the client generates a key pair, and sends a `DPoP` header on every request: a
short JWT signed with the private key, covering the HTTP method, the URL, a nonce and a timestamp.
The AS binds the issued token to the public key's thumbprint (`cnf.jkt`), and the resource server
checks that the proof on each request matches the thumbprint in the token. It needs no PKI: the key
is ephemeral and can live in memory for the life of the client process.

**Certificate-bound tokens (RFC 8705)** — the client presents a TLS client certificate to the AS,
which records its thumbprint in `cnf.x5t#S256`; the resource server, which also terminates mTLS,
checks that the certificate on the connection matches. Stronger, but it needs a PKI and it breaks
wherever TLS is terminated by something that does not forward the certificate.

**What it would take here.** For DPoP: the SDK parses `dpop_signing_alg_values_supported` and
`dpop_bound_access_tokens_required` as *metadata fields* and does nothing else with them — no proof
is created client-side, none is validated server-side. You would hand-roll both halves (a `jose`
`SignJWT` per request on the client; on the server, verifying the proof, the `htm`/`htu` claims, the
`jti` replay window and the `cnf.jkt` binding). Keycloak's `DPOP` feature is `DEFAULT, enabled=true`
in the bundled 26.7.2 and the realm advertises ten DPoP signing algorithms, so the AS half is
already there. For RFC 8705: the realm advertises
`tls_client_certificate_bound_access_tokens: true` and Keycloak supports `tls_client_auth`, but the
whole demo runs on plain HTTP, so the transport would have to move to TLS first.

Note what [08 — mutual TLS](08-mtls.md) does and does not do: it uses a client certificate as the
*credential itself*, replacing the token. That is transport-level authentication, not a
sender-constrained OAuth token — there is no AS, no audience and no scope grant, and the two
patterns compose rather than compete.

**Read on.** [08 — mutual TLS](08-mtls.md); [spec-background §7](spec-background.md#7-what-the-sdk-does-not-implement).

---

## Device authorization grant (RFC 8628)

**When.** The client cannot open a browser or cannot receive a redirect: a terminal on a headless
box, an SSH session, a TV, an MCP server running in CI that nonetheless needs a *user's* identity.

**How.** The client posts to the AS's `device_authorization_endpoint` and gets back a `device_code`,
a short `user_code` and a verification URL. It prints "go to `https://…/device` and enter
`WDJB-MJHT`", then polls the token endpoint with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` until the user finishes on whatever device
has a browser. The token that comes back is an ordinary access token; nothing downstream changes.

**What it would take here.** A hand-rolled `OAuthClientProvider`. Verified: the string `device_code`
appears nowhere in `@modelcontextprotocol/sdk` 1.30.0, so `auth()` cannot drive this grant — you
would run the polling loop yourself and hand the resulting token to a provider whose `tokens()`
returns it (the same shape `ClientCredentialsProvider` uses, minus the grant). The AS half is ready:
the realm's metadata advertises
`device_authorization_endpoint: …/protocol/openid-connect/auth/device`,
`grant_types_supported` includes the device-code URN, and Keycloak's `DEVICE_FLOW` feature is
`DEFAULT, enabled=true` — the client would need `oauth2.device.authorization.grant.enabled` set.

Compared with this repository's browser-driven flow: `CliOAuthProvider` binds a loopback listener on
port 4199 and needs a browser *on the same machine or reachable from it*
(`OAUTH_REDIRECT_HOST` exists for the client-on-A/browser-on-B case, see
[lan-testing](lan-testing.md)). The device grant removes that constraint entirely.

**Read on.** [03](03-oauth-embedded-as.md) and [04](04-keycloak-resource-server.md) for the
redirect-based flow; [05](05-keycloak-client-credentials.md) for the case where there is no user at
all.

---

## private_key_jwt beyond example 05

**When.** Machine-to-machine authentication where a shared secret is unacceptable — it is copied
into CI, into `.env` files, into logs, and it is a symmetric credential the AS also stores.

**How.** RFC 7523 client authentication: instead of `client_secret`, the client sends
`client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and a short-lived JWT
signed with its private key, whose `iss` and `sub` are the client id and whose `aud` is the AS. The
AS verifies with a public key it holds (registered directly, or fetched from a `jwks_uri` the client
publishes).

[05](05-keycloak-client-credentials.md) ships this as its `--auth private-key-jwt` variant, with the
public key imported into the `mcp-service-jwt` client. What that example does *not* show:

* **JWKS instead of a pasted key.** Registering `jwks_uri` on the client lets you rotate by
  publishing a second key and retiring the first, with no realm change. Keycloak supports it (Signed
  JWT with "Use JWKS URL"); the demo pastes a key because a demo has nowhere to host the JWKS.
* **Key custody.** The point of the pattern is that the private key never leaves the workload. In
  production that means a KMS, an HSM, a cloud provider's managed identity, or SPIFFE (below) —
  `readFileSync` of a PEM from the repository is a demo affordance.
* **Audience quirks.** The SDK's `createPrivateKeyJwtAuth` defaults the assertion audience to
  `metadata.issuer` and then the token URL; different providers want different values, so it takes
  an explicit `audience` option. Getting this wrong yields a flat `invalid_client`.
* **The same trick for users.** `urn:ietf:params:oauth:grant-type:jwt-bearer` (advertised by this
  realm; Keycloak feature `JWT_AUTHORIZATION_GRANT` is `DEFAULT, enabled=true`) lets a trusted party
  present a signed assertion *about a user* and receive a token for them — the mechanism underneath
  the enterprise-managed pattern below.

Verified constraint: the SDK's `private_key_jwt` helpers dynamically import `jose` and require
`globalThis.crypto` (Node ≥ 19).

**Read on.** [05 — client credentials](05-keycloak-client-credentials.md);
[`keycloak/README.md`](../keycloak/README.md) for the `mcp-service-jwt` client.

---

## Browser-embedded MCP clients

**When.** The MCP client is a web application rather than a CLI or a desktop app — an agent UI that
talks to MCP servers directly from the page.

**How, and what breaks.** Three things that never come up in a CLI:

* **CORS.** The SDK's metadata, token, registration and revocation routers already set
  `cors()` for any origin; the `/mcp` endpoint does **not** — you add it yourself. It must expose
  `Mcp-Session-Id` and `mcp-protocol-version` on the response and allow `Content-Type`,
  `Authorization`, `mcp-session-id`, `mcp-protocol-version` and `Last-Event-ID` on the request, or
  the transport silently loses the session id. The SDK client also treats a CORS failure specially
  during discovery: a `TypeError` from `fetch` triggers one retry with no custom headers.
* **Token storage.** There is no safe place in a browser for a refresh token. `localStorage` is
  readable by any script that gets injected into the page; memory-only storage means a reload
  restarts the flow. The usual answer is the **BFF** (backend-for-frontend): the page never sees a
  token at all, a small server-side component holds them in an HTTP-only, `SameSite` cookie session
  and proxies MCP calls. That component is structurally example 09's gateway, turned around.
* **Redirect handling.** The loopback listener of `CliOAuthProvider` is replaced by a real redirect
  URI on your own origin, and the client must persist the PKCE verifier, the `state` and the client
  registration across the page navigation — the SDK's `finishAuth()` requires all of them
  (`Existing OAuth client information is required when exchanging an authorization code`).

**What it would take here.** A front-end build and an HTTPS origin, neither of which fits a
"two terminals and curl" repository. The server-side change is small: add `cors()` in front of
`mountMcp()` in `src/shared/http.ts` with the header list above.

**Read on.** [09 — auth gateway](09-auth-gateway.md) for the BFF shape;
[sdk-notes](sdk-notes.md) for the exact CORS and header-precedence rules.

---

## Token-issuing proxies and the confused-deputy rule

**When.** MCP clients must not be pointed at your real IdP — because it is on a private network,
because it cannot do DCR, or because you want one MCP-shaped facade in front of several IdPs.

**How.** [06](06-oauth-proxy-keycloak.md) is the SDK-supported version: `ProxyOAuthServerProvider`
serves `/authorize`, `/token`, `/register` and `/revoke` on the MCP origin and forwards each to the
upstream AS. Two structural facts, both verified in the SDK source, decide how far it takes you:
`skipLocalPkceValidation` is hard-set to `true` (the upstream must enforce PKCE, and it does), and
the upstream redirects the browser **straight to the MCP client's redirect URI** — the proxy is not
in the callback path, so those URIs must be registered upstream too.

The heavier variant is a proxy that issues its *own* tokens: it authenticates the user upstream,
then mints a token from its own key, with its own audience and its own lifetime. It gets you a
uniform token format across several IdPs and a place to add claims. It also makes you an
authorization server, with everything that implies — key management, revocation, refresh rotation,
consent, and an incident when your signing key leaks.

**The rule that governs both.** From the spec's security considerations: *"MCP proxy servers using
static client IDs **MUST** obtain user consent for each dynamically registered client before
forwarding to third-party authorization servers."* The attack is precise. A proxy that always
presents the same upstream `client_id` will have that client's consent remembered by the upstream
AS after the first user approves it. An attacker then registers a client at the proxy with their own
`redirect_uri`, sends a victim a crafted `/authorize` link, the upstream skips consent because "this
client is already approved", and the authorization code lands at the attacker's redirect URI. The
proxy is the confused deputy: it lent its established trust to a client the user never approved.

The defence is a consent screen *at the proxy*, per (client, user) pair, that cannot be skipped —
which is exactly what [03](03-oauth-embedded-as.md) implements for its own clients. Example 06 does
not need it in its default wiring, because it forwards DCR to Keycloak and each dynamically
registered client is a distinct upstream client with its own consent; the moment you switch it to a
single static upstream client (the "hide the upstream secret" variant), the rule applies and you
must add the screen.

**Read on.** [06 — OAuth proxy](06-oauth-proxy-keycloak.md);
[03 — embedded AS](03-oauth-embedded-as.md) for the consent implementation;
[spec-background §9](spec-background.md#9-security-requirements-that-are-not-about-discovery).

---

## Off-the-shelf gateways instead of example 09

**When.** You already run an ingress, and you would rather configure token validation once there
than link a verifier into every MCP server — especially with servers in several languages, as
[11](11-python-mcp-keycloak.md) hints at.

**How.** [09](09-auth-gateway.md) hand-rolls the gateway so the trust boundary is visible in
readable TypeScript: it validates the token, serves the PRM, strips inbound identity headers, and
forwards a short-lived signed assertion to an internal server that trusts nothing else. Every
product below does the same job with configuration:

| Gateway | Mechanism | Notes |
|---|---|---|
| **Envoy** | `jwt_authn` HTTP filter, or `ext_authz` to your own service | validates locally against a cached JWKS; `ext_authz` when you need introspection or policy |
| **Traefik** | `forwardAuth` middleware | calls your auth service per request; copies chosen response headers onward via `authResponseHeaders` |
| **NGINX** | `auth_request` (plus `njs` or `auth_jwt` in NGINX Plus) | same sub-request model as `forwardAuth` |
| **oauth2-proxy** | a ready-made OIDC front door | designed for browser sessions and cookies; a poor fit for MCP's per-request bearer model |
| **Kong / APISIX** | `openid-connect` / `jwt-auth` plugins | plugin per route; both can also do introspection and rate limiting |

A sketch of the Envoy form, equivalent to example 09's verifier (not run in this repository):

```yaml
http_filters:
  - name: envoy.filters.http.jwt_authn
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication
      providers:
        keycloak:
          issuer: http://192.168.78.87:8180/realms/mcp
          audiences: [mcp-server]
          remote_jwks:
            http_uri:
              uri: http://192.168.78.87:8180/realms/mcp/protocol/openid-connect/certs
              cluster: keycloak
              timeout: 5s
            cache_duration: { seconds: 300 }
          payload_in_metadata: jwt_payload
      rules:
        # The PRM must stay reachable without a token, or discovery can never start.
        - match: { prefix: /.well-known/ }
        - match: { prefix: /mcp }
          requires: { provider_name: keycloak }
```

Three things every gateway deployment gets wrong at least once:

* **The 401 must still carry `resource_metadata`.** Most gateways emit a bare
  `WWW-Authenticate: Bearer` on a missing token, which leaves an MCP client with nothing to
  discover. Either configure the header or let the MCP server answer the unauthenticated case.
* **The well-known paths must bypass the filter.** A PRM behind the token check is a deadlock.
* **The backend must not be reachable directly, or must not trust headers.** Example 09 exists to
  make this concrete: `INTERNAL_TRUST_MODE=network` demonstrates the attack where a plain
  `X-Forwarded-User` header is believed by a backend that anyone on the network can reach. A signed,
  short-lived, single-use assertion (or mTLS between gateway and backend) is the fix.
* **Streaming must survive.** MCP's `GET /mcp` is a long-lived SSE stream; buffering proxies break
  it. In NGINX that is `proxy_buffering off` and a long `proxy_read_timeout`.

**Read on.** [09 — auth gateway](09-auth-gateway.md).

---

## Enterprise-managed authorization (ID-JAG and jwt-bearer)

**When.** An enterprise wants to decide centrally which of its users may use which MCP servers,
without every MCP server federating to every customer's IdP, and without users clicking through a
consent screen per server.

**How.** The direction of travel is *identity assertions*: the enterprise IdP issues a short-lived,
audience-restricted assertion that says "this user, from this managed device, for this application",
and the MCP server's AS exchanges it for an access token. The concrete proposal is the
**Identity Assertion Authorization Grant** (ID-JAG, `draft-parecki-oauth-identity-assertion-authz-grant`),
built on RFC 8693 token exchange with a `requested_token_type` of
`urn:ietf:params:oauth:token-type:id-jag`. The older, deployed form of the same idea is the
`urn:ietf:params:oauth:grant-type:jwt-bearer` grant (RFC 7523 §2.1), where a trusted issuer's signed
JWT is exchanged directly for an access token.

**What it would take here.** The ID-JAG draft is moving; treat any implementation as experimental.
The pieces that exist today in this stack: the realm advertises
`urn:ietf:params:oauth:grant-type:jwt-bearer` and Keycloak's `JWT_AUTHORIZATION_GRANT` feature is
`DEFAULT, enabled=true` (both verified), so a second "enterprise IdP" realm could issue assertions
that the `mcp` realm accepts. What would make it a real example is a second identity provider and a
device-trust story, neither of which fits here. The Python SDK (`mcp` 2.1.1) exposes token-verifier
hooks that would accept such tokens unchanged.

**Read on.** [10 — token exchange](10-token-exchange-downstream.md) for the RFC 8693 machinery this
builds on; the extensions list at `github.com/modelcontextprotocol/ext-auth` for what the spec is
adopting.

---

## Workload identity (SPIFFE and Kubernetes service accounts)

**When.** The MCP client is a workload, not a person, and you would rather not manage a client
secret for it at all — the deployment platform already knows what it is.

**How.** Two shapes of the same idea.

**SPIFFE/SPIRE** issues every workload a short-lived X.509 certificate or JWT-SVID whose identity is
a URI like `spiffe://example.org/ns/prod/sa/mcp-agent`, attested from properties of the process and
node rather than a secret in a file. The MCP server can either terminate mTLS and map the SPIFFE ID
to a principal (structurally [08](08-mtls.md), with the demo CA replaced by SPIRE and the CN
replaced by a SPIFFE ID), or exchange the JWT-SVID at the AS for a normal access token.

**Kubernetes projected service-account tokens** are the same trick without a new component: the
kubelet mounts a short-lived, audience-scoped JWT into the pod, rotating it automatically. Set the
audience to your AS, and the workload can use it as a `jwt-bearer` assertion or as a
`private_key_jwt` substitute. The cluster's OIDC discovery document provides the JWKS.

Either way the durable secret disappears: [05](05-keycloak-client-credentials.md)'s
`MCP_SERVICE_CLIENT_SECRET` becomes a file the platform rotates for you, and revocation becomes
"stop scheduling that workload".

**What it would take here.** A cluster or a SPIRE deployment. The MCP server side needs no change at
all — it is still a JWT verifier with an issuer and an audience, which is exactly
`createJwtVerifier()` in `src/shared/jwt.ts`.

**Read on.** [05](05-keycloak-client-credentials.md), [08](08-mtls.md).

---

## Fine-grained authorization beyond scopes

**When.** "This caller may call `read_document`" is not the question you need answered; "may *this*
caller read *document 42*" is. Scopes are coarse by design — they describe the grant a client
received, not the rights a user holds over individual objects.

**How.** Keep the token check where it is and add a policy decision *inside* the tool. The options:

* **Keycloak Authorization Services / UMA.** Resources, policies and permissions modelled in the
  realm; the server exchanges the user's token for a Requesting Party Token with
  `grant_type=urn:ietf:params:oauth:grant-type:uma-ticket` (advertised by this realm; feature
  `AUTHORIZATION` is `DEFAULT, enabled=true`). No second component to run, at the cost of putting
  application policy into the IdP.
* **OPA (Open Policy Agent).** A sidecar or library evaluating Rego over an input document
  (`{subject, action, resource, context}`); decisions are fast and testable, and policy lives with
  the application.
* **AuthZEN.** The OpenID working group's standard *API* for exactly that question, so the policy
  engine becomes swappable rather than a vendor choice.
* **Relationship-based systems** (Zanzibar-style: SpiceDB, OpenFGA, Ory Keto) when the answer
  depends on graphs — folders, teams, sharing.

**What it would take here.** Structurally very little, which is the point: this repository's
effective-scopes contract already puts *all* authorization policy in one place. Tools read
`extra.authInfo.scopes` and nothing else; the verifier computes that list (see
`keycloakEffectiveScopes()`, which drops `mcp:admin` unless the user holds the `mcp-admin` role).
A policy engine slots in at the same seam — either enriching `AuthInfo.extra` at verification time,
or being called per tool invocation with the object id, which is where it belongs when the decision
depends on the arguments.

**Read on.** [`src/shared/README.md`](../src/shared/README.md) for the effective-scopes contract;
[04](04-keycloak-resource-server.md) for scope-versus-role in practice.

---

## Legacy discovery and the deprecated HTTP+SSE transport

**When.** You have to interoperate with clients or servers written against MCP 2024-11-05 or
2025-03-26.

**How, and what to watch for.**

* **The old transport.** Before Streamable HTTP there were two endpoints: a `GET /sse` that opened
  the stream and announced a session-specific POST URL, and that POST URL for messages. Both
  `SSEServerTransport` and `SSEClientTransport` still ship in the SDK and both are marked
  `@deprecated` in their type declarations. A server that must support both mounts the old pair
  alongside `/mcp`; there is no shared session state between them. The DNS-rebinding options on the
  old transport are deprecated too, in favour of the `hostHeaderValidation` middleware — the same
  protection `createApp()` installs in [00](00-baseline-no-auth.md).
* **Discovery without a PRM.** The 2025-03-26 spec had no RFC 9728: the MCP server's *own* origin
  was assumed to be the authorization server. The SDK client still falls back to that behaviour —
  if PRM discovery fails, `discoverOAuthServerInfo` sets the authorization server URL to the MCP
  server's origin and probes `/.well-known/oauth-authorization-server` and
  `/.well-known/openid-configuration` there. This is why examples [01](01-api-key.md) and
  [02](02-jwt-local.md) deliberately omit `resource_metadata` from their 401: there is nothing to
  discover, and advertising a metadata URL that cannot exist just sends clients on a chase.
* **Audience gaps.** Tokens minted under the old rules have no resource binding, because the
  `resource` parameter was not required. Treat them as valid only for the server that issued them.

**What it would take here.** A thirteenth example that mounts both transports. It was left out
because the deprecated transport contributes nothing to an authorization comparison — the bearer
middleware is identical.

**Read on.** [00 — baseline](00-baseline-no-auth.md) for the Streamable HTTP mechanics;
[sdk-notes](sdk-notes.md) for the fallback probe order.

---

## Session, replay and abuse controls

**When.** Always, in production — and this is where a demo's shortcuts are most visible.

**What the examples already do.** `mountMcp()` binds an MCP session to the subject that initialized
it and answers 403 when a different subject presents that session id, because the SDK deliberately
does not (`Session IDs are NOT bound to tokens`). Idle sessions are swept after 30 minutes.
`createApp()` validates the `Host` header against an allow-list before the body is parsed, which is
the DNS-rebinding defence. Example 09 gives its internal assertions a 30-second lifetime and a `jti`
replay cache.

**What production adds.**

* **Rate limiting and lockout.** The SDK's auth router ships per-IP limits on `/authorize`,
  `/token`, `/register` and `/revoke` (100, 50, 20/h, 50 per window) — this repository disables them
  with `MCP_RATE_LIMIT=0` in tests. Nothing limits `/mcp` itself; a token that is valid is valid as
  often as the caller likes. Add per-principal limits, and remember `app.set('trust proxy', <hops>)`
  behind a load balancer — `express-rate-limit` v8 refuses `trust proxy: true`.
* **Replay windows.** Bearer tokens are replayable by design for their whole lifetime; short
  lifetimes and sender constraint (above) are the only real answers. This realm's access tokens live
  15 minutes — Keycloak's 60-second default makes demos flaky, but 15 minutes is a demo choice, not
  a recommendation.
* **Session fixation.** Never accept a client-proposed session id, and re-derive identity from the
  token on every request rather than caching it against the session — which is what `mountMcp()`
  does.
* **Audit.** Log the authenticated principal, the tool name and the outcome; never the token, the
  code, or the `Authorization` header. The repository's convention is
  `sha256(token).slice(0, 8)` at most, enforced by `tests/conventions.test.ts`.

**Read on.** [00 — baseline](00-baseline-no-auth.md) (sessions, Host validation);
[09 — auth gateway](09-auth-gateway.md) (assertion replay cache).

---

## Secrets, rotation and lifetimes

**When.** The moment anything here leaves a laptop.

**What to change.** Everything in `.env.example` marked `DEMO` is a published credential:
`admin`/`admin` for Keycloak, `password` for alice and bob, `mcp-service-secret-demo`,
`mcp-server-secret-demo`, `demo-api-key-alice`. They exist so the repository runs with one command.
Beyond that:

* **Storage.** Client secrets and API keys belong in a secret manager, injected as environment
  variables or files at start-up, never committed. [01](01-api-key.md) shows the minimum discipline
  for the ones you cannot avoid: store a SHA-256 digest, compare in constant time, log at most eight
  hex characters of the digest.
* **Rotation.** Overlap, always: two valid credentials at once, move consumers, retire the old one.
  For API keys that is a second table row. For signing keys it is a second entry in the JWKS — which
  is why [02](02-jwt-local.md) publishes a `kid` and rotates by adding a key rather than replacing
  one. For client secrets, prefer removing the secret entirely (`private_key_jwt`, or workload
  identity above).
* **Lifetimes.** Short access tokens plus refresh-token rotation is the OAuth 2.1 shape, and it is
  what makes an ordinary JWT verifier acceptable despite having no revocation. Where you cannot
  accept revocation latency, pay for introspection instead — [07](07-token-introspection.md) makes
  the trade measurable: after `adminLogoutUser('alice')` the introspecting server rejects the very
  next call while a JWKS verifier keeps accepting the same token until `exp`.
* **Blast radius.** One credential per workload and per environment; audience-restrict every token
  so a leak is bounded by what it can be presented to. That is the whole argument for RFC 8707
  above, and for example 10 refusing to pass a token through.
* **Transport.** All of this assumes TLS. This repository runs plain HTTP on a LAN and sets
  `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=1` to make the SDK accept an `http://` issuer; both are
  demo affordances with the word "dangerously" in them for a reason. See
  [lan-testing](lan-testing.md) for adding TLS.

**Read on.** [`keycloak/README.md`](../keycloak/README.md) and [keycloak](keycloak.md) for the realm's
demo settings and how to harden them; [01](01-api-key.md) for key hygiene.
