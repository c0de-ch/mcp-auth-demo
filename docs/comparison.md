# Comparison — choosing an approach

Twelve runnable examples, one page. Every row below is a working server/client pair you can start in
two terminals; the page linked from each row carries the sequence diagram, the captured wire trace
and the negative matrix. This page exists to get you to the right row.

## Start with one question: who is the caller?

Almost every other decision follows from it, and getting it wrong is the mistake that is expensive
to undo later.

* **A human, through an MCP client.** The token must carry the *user's* identity, so the flow needs
  a browser once, consent, and an authorization server that knows about people: OAuth 2.1
  authorization code with PKCE. That is [03](03-oauth-embedded-as.md), [04](04-keycloak-resource-server.md),
  [06](06-oauth-proxy-keycloak.md), [07](07-token-introspection.md), [09](09-auth-gateway.md),
  [10](10-token-exchange-downstream.md) and [11](11-python-mcp-keycloak.md). If a third-party MCP
  client must be able to connect knowing nothing but your URL, you are also committed to discovery,
  which narrows this to the OAuth rows.
* **A workload acting as itself** — a cron job, a pipeline, another service, an agent with no user
  behind it. There is no consent to obtain and nobody to show a login page to, so the credential is
  something the deployment holds: [05](05-keycloak-client-credentials.md) (a service account at a
  real IdP), or, without an IdP, [01](01-api-key.md) and [02](02-jwt-local.md).
* **A machine identity established below HTTP** — both ends provisioned by you or your platform,
  and the property you want is "no valid certificate, no conversation": [08](08-mtls.md).

Do not launder one into another. A service account is not "any user" — an audit trail that collapses
every action onto `service-account-mcp-service` cannot answer who did what
([05](05-keycloak-client-credentials.md)). And a server that must call another API *as the user*
needs delegation, not a second identity: [10](10-token-exchange-downstream.md).

## How to read the matrix

* **Caller** — user (a human logs in), workload (a service authenticates as itself), host (a machine
  identity proved by a certificate).
* **Browser** — whether completing the flow once requires a browser (headless drivers count).
* **IdP** — whether an external identity provider must be running (`npm run kc:up` here).
* **Discovery** — whether an unconfigured MCP client can bootstrap from the 401 alone: RFC 9728
  Protected Resource Metadata plus RFC 8414/OIDC authorization-server metadata, or nothing.
* **Credential / validation** — what the caller presents, and what the server does with it.
* **Audience binding** — what stops a token minted elsewhere from working here.
* **Revocation latency** — how long a withdrawn credential keeps working, worst case.
* **Registration** — how a client obtains a `client_id`: none, static (pre-registered), or RFC 7591
  Dynamic Client Registration.
* **Grade** — the spec grade from [design.md](design.md) §3: CONFORMANT, PARTIAL, TRANSITIONAL,
  OUTSIDE-SPEC. OUTSIDE-SPEC is not a verdict on the approach, only on whether an MCP client can
  discover and use it; see [spec-background](spec-background.md).
* **Effort** — S / M / L, the work to adopt the shape in your own server, not the size of the example.

## The matrix

| # | Approach | Caller | Browser | IdP | Discovery | Credential | Validation | Audience binding | Revocation latency | Registration | Grade | Effort |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| [00](00-baseline-no-auth.md) | [unauthenticated reference](../examples/00-baseline-no-auth/) | none | no | no | none | none | none | none | n/a | none | baseline (auth is OPTIONAL in MCP) | S |
| [01](01-api-key.md) | [static API key as bearer](../examples/01-api-key/) | workload | no | no | none | shared secret, no expiry | SHA-256 digest + `timingSafeEqual` over every table entry | none | immediate (delete the row) | none — keys handed out out of band | OUTSIDE-SPEC (RFC 6750 syntax only) | S |
| [02](02-jwt-local.md) | [self-issued JWT via a local JWKS](../examples/02-jwt-local/) | user or workload | no | no (a local token vending endpoint on 4192) | none | JWT (RS256, 300 s) | signature via cached JWKS + `iss`/`aud`/`exp` | exact MCP URL (`…:4102/mcp`) | none — valid until `exp` | none | OUTSIDE-SPEC | M |
| [03](03-oauth-embedded-as.md) | [the MCP server **is** the OAuth 2.1 AS](../examples/03-oauth-embedded-as/) | user | yes | no (built in) | PRM + AS metadata, both on the MCP origin | opaque access token (15 min) + rotating refresh | in-memory lookup — AS and RS are one object | RFC 8707 `resource`, validated (`invalid_target`) | immediate (`/revoke`; code or refresh reuse burns the family) | DCR, or the seeded `mcp-cli` | CONFORMANT | L |
| [04](04-keycloak-resource-server.md) | [external AS, MCP is a pure resource server](../examples/04-keycloak-resource-server/) | user | yes | Keycloak | PRM + AS metadata | JWT (RS256) | signature via realm JWKS + `iss`/`aud`/`exp` | logical `mcp-server` | until `exp` (15 min in this realm) | DCR, or `OAUTH_CLIENT_ID=mcp-cli` | CONFORMANT; PARTIAL (Keycloak ignores `resource`) | M |
| [05](05-keycloak-client-credentials.md) | [M2M service account, incl. `private_key_jwt`](../examples/05-keycloak-client-credentials/) | workload | no | Keycloak | PRM + AS metadata | JWT for the RS; client secret or a signed assertion at the token endpoint | signature via realm JWKS | logical `mcp-server` | until `exp` (15 min); disabling the client stops new grants | static (pre-registered confidential client) | CONFORMANT | S/M |
| [06](06-oauth-proxy-keycloak.md) | [MCP server as an OAuth facade](../examples/06-oauth-proxy-keycloak/) | user | yes | Keycloak (invisible to the client) | PRM + AS metadata, both on the facade origin | JWT, Keycloak's, passed through verbatim | signature via realm JWKS (the facade holds no keys) | logical `mcp-server` | until `exp` | DCR proxied to Keycloak, or the seeded `mcp-cli` | TRANSITIONAL | M |
| [07](07-token-introspection.md) | [RFC 7662 introspection with a TTL cache](../examples/07-token-introspection/) | user | yes | Keycloak | PRM + AS metadata | opaque to the server (a JWT here, never parsed) | one introspection call per token per TTL window | `mcp-server`, re-checked in the response | `INTROSPECTION_TTL_SECONDS` (default 10 s; `0` = immediate) | DCR, or `mcp-cli` | CONFORMANT | M |
| [08](08-mtls.md) | [client certificate is the credential](../examples/08-mtls/) | host | no | no | none — no bearer scheme, no `WWW-Authenticate` at all | X.509 certificate + private key | TLS 1.3 handshake (chain, validity), then a CN allow-list | none — the channel is bound, not a token | none in the demo (no CRL/OCSP) — until `notAfter` | none — the CA issues certificates | OUTSIDE-SPEC (transport-level) | M |
| [09](09-auth-gateway.md) | [gateway validates, signs an assertion inward](../examples/09-auth-gateway/) | user | yes | Keycloak | PRM at the gateway + AS metadata; the internal server serves none | JWT at the edge; a 30 s HS256 assertion inside | JWKS at the gateway; HS256 + `aud` + `jti` replay cache inside | `mcp-server` at the gateway, `mcp-internal` on the assertion | until `exp` at the gateway (the assertion lives 30 s) | DCR, or `mcp-cli` | infrastructure (the gateway is a CONFORMANT RS) | M |
| [10](10-token-exchange-downstream.md) | [RFC 8693 on-behalf-of to a downstream API](../examples/10-token-exchange-downstream/) | user (the server acts as delegate) | yes | Keycloak | PRM + AS metadata | JWT in, a second exchanged JWT out | signature via realm JWKS on both hops | `mcp-server` inbound, `downstream-api` outbound | until `exp` on both hops | DCR or `mcp-cli`; the exchange itself uses the confidential `mcp-server` | CONFORMANT delegation; PARTIAL (`audience=` is a client id) | L |
| [11](11-python-mcp-keycloak.md) | [Python twin of 04 (`mcp` 2.1.1)](../examples/11-python-mcp-keycloak/) | user | yes | Keycloak | PRM + AS metadata | JWT (RS256) | signature via realm JWKS (PyJWT) | logical `mcp-server` | until `exp` | DCR, or `mcp-cli` | CONFORMANT; PARTIAL as 04 | M |

Two reminders the table cannot carry. Every "until `exp`" row is a deliberate trade: signature
validation is fast, offline and survives an IdP outage, and it *cannot see revocation* — that is the
whole reason [07](07-token-introspection.md) exists next to [04](04-keycloak-resource-server.md).
And every row runs plain HTTP on a LAN, so nothing here is safe from an on-path observer; see
[lan-testing](lan-testing.md) and [threat-model](threat-model.md).

## Choose X when …

**[00 — no auth](00-baseline-no-auth.md).** Only as the diff base for reading the other eleven, or
where something else already authenticates: a gateway in front (09), or stdio, where the process
boundary is the boundary ([patterns](patterns.md#stdio-transport-the-process-is-the-boundary)).
Everything is allowed for everyone who can reach the port.

**[01 — API key](01-api-key.md).** When you need identity *today*, inside one trust domain, and a
human can move a secret out of band. It is one middleware and one table, and it already gives you
distinct principals, per-key scopes and instant revocation. What it costs: no discovery (an MCP
client cannot bootstrap against it — the 401 deliberately carries no `resource_metadata`), no
expiry, no user identity, no consent, no audience, and a revocation story that is an operator
editing a table. It is a bearer secret with no proof of possession, so it is exactly as strong as
your transport.

**[02 — self-issued JWT](02-jwt-local.md).** When you want claims, short lifetimes and offline
verification, but no IdP: you own a signing key, publish a JWKS, and the server verifies without
ever calling you. It is also the honest way to learn JWT validation before adding an AS. The cost is
that you now run key management, rotation and — because there is no revocation at all — you live
with tokens being valid until `exp`. Still no discovery: this is 04 with the OAuth machinery cut
away.

**[03 — embedded AS](03-oauth-embedded-as.md).** When you want the full spec-conformant experience
with zero external dependencies: an appliance, a self-contained demo, an internal tool with a
handful of users — or when you need to *watch* the protocol, because every message is in one
process's log. The cost is that you have become an authorization server: consent screens, PKCE,
code single-use, refresh rotation, revocation and the key material are all now yours to get right,
AS availability equals RS availability, and here all state is in memory, so a restart is a mass
logout.

**[04 — Keycloak resource server](04-keycloak-resource-server.md).** The default answer when a human
is the caller and an IdP exists or can exist. The MCP server holds no secrets, no password hashes
and no signing keys; it answers two questions (where do tokens come from, is this one for me) and
scales horizontally. The cost is running an IdP, and the revocation blind spot: a stolen token works
until `exp`. The PARTIAL grade is Keycloak ignoring `resource`, so the audience is the logical
`mcp-server` rather than a per-URL one — see
[patterns](patterns.md#strict-rfc-8707-resource-indicators-at-the-authorization-server).

**[05 — client credentials](05-keycloak-client-credentials.md).** When there is no human: the
workload authenticates as itself and gets a short-lived token for a service account. Far better than
a static API key — the credential lives in the IdP, tokens expire, revocation is disabling a client
— and `private_key_jwt` removes the shared secret entirely. The cost: no user, no consent, no
delegation semantics, and a discipline problem if you are tempted to run user actions through it.

**[06 — OAuth facade](06-oauth-proxy-keycloak.md).** When clients must see exactly one origin —
firewall rules, an IdP on an internal network, an IdP you may swap — or when your IdP has no
anonymous DCR but MCP clients expect `/register` to work. The cost is real and worth reading before
copying: upstream errors become opaque `500 server_error` (the client never learns `invalid_grant`
from `invalid_client`, and on the refresh path that degrades into a surprise browser round trip),
PKCE is enforced only upstream, the facade's advertised `issuer` is not the `iss` in the tokens, and
a compromised facade sees every token that crosses `/token`. With a single static upstream client
you also inherit the confused-deputy consent rule.

**[07 — introspection](07-token-introspection.md).** When revocation must take effect in seconds —
an admin kicks a user, a leaked token is killed — or when the AS issues opaque tokens, where local
validation is not an option at all. You buy a central kill switch and AS-side audit of every
validation, and you pay one AS round trip per uncached request, a hard dependency on the AS being up
(this server fails closed with a 500), and a cache TTL that *is* your revocation latency.

**[08 — mutual TLS](08-mtls.md).** When both ends are machines you provision, and you want callers
without a certificate to be unable to speak HTTP to you at all. The credential is a private key that
never crosses the wire, so nothing can leak into a log or be replayed elsewhere. The cost: no login,
no consent, no scopes chosen per grant, no audience — a certificate says what the machine is, never
which user asked for what — plus PKI operations, and any TLS-terminating hop in the path breaks it
unless it forwards the certificate.

**[09 — auth gateway](09-auth-gateway.md).** When the MCP server cannot or should not be made
OAuth-aware — legacy code, another language, a fleet of small tools — and you want one conformant
front door with validation, PRM, logging and rate limiting in one place. The cost is an extra hop, a
second credential to rotate (the assertion secret), and a model that only holds if the backend is
unreachable except through the gateway; the token also stops at the gateway, so the backend cannot
act onward as the user.

**[10 — token exchange](10-token-exchange-downstream.md).** When a tool must call another API *as
the user*: per-user authorization downstream, per-user audit, least privilege per hop. The exchanged
token keeps the user's `sub`, names the MCP server as `azp`, and is scoped and audience-bound to the
downstream only — so neither token works at the other hop. The cost: both services must trust the
same AS, the AS must implement RFC 8693, and the exchange credential is a real secret (its holder
can turn any token addressed to `mcp-server` into a downstream token). The alternative — forwarding
the caller's token — is forbidden by the spec and is the classic confused deputy.

**[11 — Python twin](11-python-mcp-keycloak.md).** When the server is Python and the rest of the
fleet is not. Architecturally it *is* 04; the point is that the PRM + JWT contract is the interface,
and an unchanged TypeScript client walks the whole discovery dance against it. The cost is a handful
of SDK deltas worth knowing before you put health checks on edge statuses: a JWKS outage becomes 401
rather than 500, a foreign session id answers 404 rather than 403, and a forged `Host` answers 421
rather than 403.

## Combining approaches

The rows are not exclusive. Three combinations come up constantly:

* **mTLS underneath a bearer token.** [08](08-mtls.md) uses the certificate *as* the credential, but
  the same handshake can simply be channel security under any OAuth row — and binding the token to
  the certificate (RFC 8705) or to a client-held key (DPoP, RFC 9449) turns a bearer token into a
  sender-constrained one, which is the only real answer to token theft. Both are docs-only here:
  [patterns](patterns.md#sender-constrained-tokens).
* **A gateway in front of anything.** [09](09-auth-gateway.md) is drawn in front of a server with no
  auth of its own, but the shape composes with every row: validate once at the edge (by JWKS or by
  introspection, centralising the cache and the introspection credential) and keep the backends
  small. Off-the-shelf equivalents — Envoy, Traefik, NGINX, Kong, oauth2-proxy — are in
  [patterns](patterns.md#off-the-shelf-gateways-instead-of-example-09).
* **Token exchange behind any user-facing approach.** [10](10-token-exchange-downstream.md) is drawn
  on top of 04, but a tool that needs to call onward as the user can sit behind 06, 07, 09 or 11
  just as well; what it needs is a verified caller token and an AS that will exchange it. Behind 09
  it needs a rethink, because there the token deliberately stops at the gateway.

Two more that are configuration rather than composition: introspection can replace JWKS validation
in any Keycloak row when revocation latency matters, and the `service_only` tool of
[05](05-keycloak-client-credentials.md) shows that client identity (`azp`) is a third authorization
axis next to scope and role, usable anywhere.

## Patterns this repository documents but does not run

[patterns.md](patterns.md) covers the approaches that need TLS, a paid IdP tier, a cluster, or that
are one flag away from an example above. Use when:

| Pattern | Use when |
|---|---|
| [stdio transport](patterns.md#stdio-transport-the-process-is-the-boundary) | the server is spawned by one desktop app for one user — the process boundary is the auth boundary, and the spec says stdio servers SHOULD NOT implement HTTP authorization |
| [Client ID Metadata Documents (SEP-991)](patterns.md#client-id-metadata-documents-sep-991-vs-dcr) | you ship a client that meets many unknown authorization servers and want one stable identity instead of a registration record on each |
| [Strict RFC 8707 resource indicators](patterns.md#strict-rfc-8707-resource-indicators-at-the-authorization-server) | several MCP servers share one AS and a token for A must be unusable at B, enforced at issuance |
| [Runtime step-up authorization](patterns.md#runtime-step-up-authorization) | one tool needs a scope the rest do not, and asking every user for it at connect time is the wrong default |
| [Sender-constrained tokens](patterns.md#sender-constrained-tokens) | a stolen token must be useless without the client's key — high-value APIs, many hops, FAPI-style profiles |
| [Device authorization grant](patterns.md#device-authorization-grant-rfc-8628) | the client cannot open a browser or receive a redirect, but you still need a user's identity |
| [private_key_jwt beyond 05](patterns.md#private_key_jwt-beyond-example-05) | M2M where a shared secret is unacceptable, and you want JWKS-based key rotation and real key custody |
| [Browser-embedded MCP clients](patterns.md#browser-embedded-mcp-clients) | the client is a web page — CORS on `/mcp`, nowhere safe to store a refresh token, and a BFF instead |
| [Token-issuing proxies](patterns.md#token-issuing-proxies-and-the-confused-deputy-rule) | a facade must mint its own tokens across several IdPs — and with it, the consent rule for static-client proxies |
| [Off-the-shelf gateways](patterns.md#off-the-shelf-gateways-instead-of-example-09) | you already run an ingress and would rather configure validation once than link a verifier into every server |
| [Enterprise-managed authorization](patterns.md#enterprise-managed-authorization-id-jag-and-jwt-bearer) | an enterprise decides centrally which users reach which MCP servers, across trust domains |
| [Workload identity](patterns.md#workload-identity-spiffe-and-kubernetes-service-accounts) | the platform already attests what a workload is, and you would rather manage no client secret at all |
| [Fine-grained authorization](patterns.md#fine-grained-authorization-beyond-scopes) | the question is "may this caller read *document 42*", which no scope can answer |
| [Legacy discovery and HTTP+SSE](patterns.md#legacy-discovery-and-the-deprecated-httpsse-transport) | you must interoperate with clients or servers written against MCP 2024-11-05 or 2025-03-26 |
| [Session, replay and abuse controls](patterns.md#session-replay-and-abuse-controls) | always, in production — rate limits, replay windows, session fixation, audit |
| [Secrets, rotation and lifetimes](patterns.md#secrets-rotation-and-lifetimes) | anything here leaves a laptop |

## Where to go next

* [spec-background](spec-background.md) — the protocol behind the CONFORMANT rows: roles, the
  discovery sequence, SEP-835 scope selection, and where SDK 1.30.0 and the spec disagree.
* [threat-model](threat-model.md) — per threat, which example demonstrates the control.
* [sdk-notes](sdk-notes.md) — the SDK behaviours that silently break implementations.
* [keycloak](keycloak.md) — the realm every Keycloak row uses, and how to swap in another IdP.
* [`src/shared/README.md`](../src/shared/README.md) — the shared modules and the effective-scopes
  contract that makes these twelve rows comparable at all.
* [glossary](glossary.md) — one paragraph per term used above.
