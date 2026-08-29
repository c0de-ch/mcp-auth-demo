# Glossary

One paragraph per term, alphabetically, each ending with where it appears in practice in this
repository. For the protocol these terms compose into, read [spec-background](spec-background.md);
for choosing between the approaches that use them, [comparison](comparison.md).

## Access token

The credential a client presents on every MCP request, in an `Authorization: Bearer …` header. It is
short-lived by design (Keycloak's realm here issues 15-minute tokens; the embedded AS of 03 issues
15 minutes as well, and the local issuer of 02 defaults to 300 seconds), and authorization is *per
HTTP request*, not per session — the POST, the GET notification stream and the DELETE all carry it.
Whatever its format, every verifier in this repository turns it into the SDK's `AuthInfo`, which is
the only thing tools ever see. → the `AuthInfo` contract in [`src/shared/README.md`](../src/shared/README.md);
[04 — Keycloak resource server](04-keycloak-resource-server.md).

## Audience

The `aud` claim: who the token is *for*. A resource server must reject tokens that do not name it,
or it will happily accept a token its identity provider minted for a completely different
application — the audience-confusion attack. Two shapes appear here: a *logical* audience
(`mcp-server`, added by a Keycloak client-scope mapper and shared by every Keycloak example), and a
*URL* audience (the exact canonical `/mcp` URL, the strict RFC 8707 form). Exactness matters: a
trailing slash is a different audience. → [02 — self-issued JWT](02-jwt-local.md) for the strict
form; [10 — token exchange](10-token-exchange-downstream.md) proves the isolation in both directions.

## Authorization server (AS)

The component that interacts with the user and issues access tokens for use at a resource server. The
MCP specification deliberately leaves its implementation out of scope: it may be a separate entity or
hosted with the resource server. Splitting the roles is what keeps an MCP server free of passwords,
consent screens, MFA and signing keys. → Keycloak in 04–07 and 09–11; the MCP process itself in
[03](03-oauth-embedded-as.md); a facade over Keycloak in [06](06-oauth-proxy-keycloak.md).

## Bearer token

RFC 6750: a token whose possession alone authorises the holder — no proof that you are the party it
was issued to. Whoever captures it can replay it until it expires or is revoked, which is why
transport security, short lifetimes and audience binding carry so much weight, and why
sender-constrained tokens exist. The RFC also fixes the syntax this repository uses everywhere: the
`Authorization: Bearer` header and the `WWW-Authenticate` challenge. → [01 — API key](01-api-key.md)
uses the syntax and nothing else; [threat-model](threat-model.md) for the replay discussion.

## Client credentials

The OAuth grant (RFC 6749 §4.4) in which a client authenticates as *itself* at the token endpoint and
receives a token with no user behind it — no browser, no redirect, no consent, no refresh token. The
client authenticates with a secret (`client_secret_basic`) or, better, a signed assertion
(`private_key_jwt`, RFC 7523). The SDK's embedded authorization server deliberately does not
implement this grant. → [05 — client credentials](05-keycloak-client-credentials.md).

## Client ID Metadata Document (CIMD)

SEP-991: instead of registering to obtain a `client_id`, a client publishes a small JSON document at
an HTTPS URL and uses *that URL* as its `client_id`. The AS fetches it, checks that the document's
`client_id` equals the URL it fetched, validates the redirect URI against the document, and shows
`client_name` on the consent screen. Since the 2025-11-25 revision this is the spec's preferred route
and DCR was demoted to MAY. The SDK implements the client half only, and the bundled Keycloak reports
the feature as experimental and disabled. → docs-only:
[patterns](patterns.md#client-id-metadata-documents-sep-991-vs-dcr), [spec-background §5](spec-background.md#5-sep-991--client-id-metadata-documents).

## Confused deputy

A component with more authority than its caller being tricked into using that authority on the
caller's behalf. Two forms matter here. A server that forwards the caller's token to a downstream API
("token passthrough") gives the downstream no way to tell it apart from anything else holding such a
token — which is why the spec forbids it and why delegation exists. And an OAuth proxy that always
presents the *same* static upstream client can let one client consume another's remembered consent,
so the spec requires per-client consent at the proxy. → [10](10-token-exchange-downstream.md) ships
the passthrough anti-pattern behind `DEMO_PASSTHROUGH=1`; the proxy rule is in
[06](06-oauth-proxy-keycloak.md) and [patterns](patterns.md#token-issuing-proxies-and-the-confused-deputy-rule).

## Consent

The user's explicit approval that a named client may act with named scopes on their behalf. It is the
only defence against a client that registered itself dynamically with a plausible name — so the
screen must show the client, the user, each scope and the exact redirect target, all HTML-escaped,
because dynamic registration metadata is attacker input. → [03](03-oauth-embedded-as.md) implements
its own login and consent pages; Keycloak's consent screen appears for DCR clients in 04, 06 and 11.

## DNS rebinding

An attack in which a page on `evil.example` rebinds its own DNS name to your server's address, so the
victim's browser talks to a server on your network and the request arrives with `Host: evil.example`.
The defence is a `Host` allow-list evaluated before the body is parsed. → `createApp()` in
[`src/shared/http.ts`](../src/shared/http.ts) answers 403 (the Python twin answers 421); tested in
[00 — baseline](00-baseline-no-auth.md).

## Dynamic Client Registration (DCR)

RFC 7591: a client `POST`s its metadata to the AS's registration endpoint and receives a `client_id`
with no prior relationship — the mechanism that lets an off-the-shelf MCP client connect knowing
nothing but a URL. The cost is a registration record per installation, and an open registration
endpoint is an abuse surface, so this realm keeps consent required, a scope allow-list and a
200-client cap. → [03](03-oauth-embedded-as.md) (the SDK's own `/register`),
[04](04-keycloak-resource-server.md) (Keycloak's anonymous DCR), [06](06-oauth-proxy-keycloak.md)
(proxied).

## Effective scopes

This repository's central contract. Tools consult exactly one thing — `extra.authInfo.scopes` — and
the *verifier* is responsible for putting the effective list there: what the client was granted
**and** what the user is actually allowed to do. `keycloakEffectiveScopes()` keeps `mcp:admin` only
when the token's `realm_access.roles` contains `mcp-admin`, so a token that overstates its subject's
rights is trimmed at the resource server rather than trusted. Because all policy lives at that one
seam, every example shares the same three tools and can be compared one to one. → the contract in
[`src/shared/README.md`](../src/shared/README.md); the rule in `src/shared/jwt.ts`, restated in
Python in [11](11-python-mcp-keycloak.md).

## Identity provider (IdP)

The system of record for people: accounts, groups, passwords, MFA, SSO sessions, account recovery. In
OAuth terms it usually also plays the authorization server, which is why the two words get used
interchangeably — but the roles are separable, and it is the AS role an MCP server discovers and
depends on. → Keycloak, described end to end in [keycloak.md](keycloak.md), including what changes
for Auth0, Entra ID or Okta.

## Introspection

RFC 7662: instead of validating a token locally, the resource server asks the authorization server
"is this token active, and what does it grant?", authenticating itself as a confidential client. It
is the only option for opaque tokens, and it makes revocation visible immediately because the AS
consults live session state. The price is one round trip per uncached request, a hard dependency on
the AS being reachable, and a cache TTL that *is* the revocation latency. → [07 — token
introspection](07-token-introspection.md); `introspect()` in `src/shared/keycloak.ts`.

## Issuer

The `iss` claim and the identity of an authorization server — a URL, compared as an exact string.
Pinning it is what stops a look-alike IdP or a second realm from minting tokens your server accepts,
and it must agree byte-for-byte across three places: what the AS writes into tokens, what the server
verifies against, and what the Protected Resource Metadata advertises. → `keycloak()` in
[`src/shared/env.ts`](../src/shared/env.ts) derives one canonical value; [04](04-keycloak-resource-server.md)
and [keycloak.md](keycloak.md) on pinning `KC_HOSTNAME`.

## JWKS

A JSON Web Key Set (RFC 7517): the public keys an issuer publishes so anyone can verify its
signatures without contacting it per request. Keys carry a `kid`, and a verifier caches the set and
re-fetches when it meets an unknown `kid` — which is what makes key rotation invisible, and what
makes "publish the new key, wait, retire the old one" the correct rotation order. A JWKS that cannot
be fetched is *our* outage, not the client's: the shared verifier maps it to a 500 without a
`WWW-Authenticate` header so clients do not start re-authorising. → `createJwtVerifier()` in
`src/shared/jwt.ts`; the toy issuer of [02](02-jwt-local.md) serves one at
`/.well-known/jwks.json`.

## JWT

A JSON Web Token (RFC 7519), signed as a JWS (RFC 7515): a base64url `header.payload.signature`
carrying claims such as `iss`, `aud`, `exp`, `sub` and `scope`. Its virtue is offline validation; its
consequence is that it stays valid until `exp` no matter what happens at the AS. Validation must pin
the algorithm (an allow-list defeats `alg: none` and HS256-with-the-public-key confusion), the issuer
and the audience — a signature check alone is not a validation. → [02](02-jwt-local.md) end to end;
`src/shared/jwt.ts` for the shared verifier.

## MCP client / host / server

Three roles the specification separates. The **server** exposes tools over a transport; the **client**
holds one connection to one server and speaks JSON-RPC to it; the **host** is the application that
contains one or more clients and decides which servers to connect to, what the user sees and where
credentials live. In this repository the little CLIs under `examples/*/client.ts` are both host and
client, which is why they own the token store and the browser launch. → [00 — baseline](00-baseline-no-auth.md);
`CliOAuthProvider` in [`src/shared/client/oauth-cli.ts`](../src/shared/client/oauth-cli.ts).

## Mutual TLS (mTLS)

A TLS handshake in which *both* peers present certificates: the server demands one signed by a CA it
trusts, and the client proves possession of the matching private key. Authentication then happens
below HTTP — a caller without a certificate never gets to send a request — and the credential never
crosses the wire. It says what the machine is, never which user asked for what, and any
TLS-terminating hop in the path breaks it. Distinct from certificate-*bound* OAuth tokens (RFC 8705),
which combine the two. → [08 — mutual TLS](08-mtls.md); RFC 8705 in
[patterns](patterns.md#sender-constrained-tokens).

## Opaque token

A token with no structure the resource server can read — a random string that means something only to
the authorization server that issued it. It cannot leak claims, cannot be validated offline, and
therefore forces stateful validation (introspection), which is exactly why it comes with immediate
revocation. → [03](03-oauth-embedded-as.md) issues 32 random bytes looked up in memory;
[07](07-token-introspection.md) treats a JWT as opaque on purpose, and a lint test asserts its server
never imports `jose`.

## PKCE (code verifier, code challenge)

Proof Key for Code Exchange, RFC 7636. Before starting an authorization request the client generates
a random secret — the **code verifier** — and sends only its SHA-256 hash, the **code challenge**,
with `code_challenge_method=S256`. At the token endpoint it presents the verifier, and the AS checks
the hash. An attacker who intercepts the authorization code cannot redeem it without the verifier,
which is what makes public clients (no secret) safe. OAuth 2.1 makes it mandatory; the SDK never
generates a `plain` challenge. → every browser flow here: [03](03-oauth-embedded-as.md) (verified
in-process), 04, 06 and 11 (verified by Keycloak).

## Protected Resource Metadata (PRM)

RFC 9728: the one document a pure MCP resource server serves, at
`/.well-known/oauth-protected-resource<path>`. It names the `resource` (the canonical MCP URL), the
`authorization_servers` clients should go to, and `scopes_supported` — which, per SEP-835, is what a
discovering client will ask for. Two rules cost real debugging time: the path is path-aware, and
`resource` must be byte-identical to the URL the client dials, with no trailing slash. Serving it is
the difference between a client that can bootstrap from a 401 and one that cannot. → [`src/shared/prm.ts`](../src/shared/prm.ts);
deliberately absent in [01](01-api-key.md), [02](02-jwt-local.md) and [08](08-mtls.md).

## Refresh token

A longer-lived credential exchanged at the token endpoint for a new access token, so the user is not
sent back through the browser every fifteen minutes. OAuth 2.1 expects rotation for public clients:
each use issues a new refresh token, and replaying a retired one is treated as theft and revokes the
whole family. Client-credentials grants have none — expiry is simply discovered on the next 401. →
rotation and family revocation in [03](03-oauth-embedded-as.md); the absence in
[05](05-keycloak-client-credentials.md).

## Resource indicator (RFC 8707)

The `resource` parameter a client sends on the authorization and token requests, naming the exact
service the token is for; a conforming AS then mints a token whose audience is that URL and rejects
an unknown value with `invalid_target`. The SDK sends it automatically whenever a PRM was found.
Keycloak accepts and ignores it — verified — so this repository binds the audience with a client-scope
mapper instead, which is the PARTIAL in several spec grades. → [03](03-oauth-embedded-as.md)
validates it strictly; [02](02-jwt-local.md) shows the URL-audience result;
[patterns](patterns.md#strict-rfc-8707-resource-indicators-at-the-authorization-server) for making an
AS honour it.

## Resource server (RS)

The service that holds the protected thing and validates tokens: in MCP, the server exposing tools.
Its obligations are small and normative — serve the PRM, verify that a token was issued *for it*,
enforce scope, and answer 401 / 403 correctly. It never issues tokens, and a pure one holds no
secrets at all, which is the whole appeal. → `examples/*/server.ts`; the canonical shape is
[04](04-keycloak-resource-server.md), moved into infrastructure in [09](09-auth-gateway.md).

## Role

What a *user* is allowed to do, held by the identity provider — here the realm roles `mcp-user` and
`mcp-admin`. It answers a different question from a scope, and the two must agree before a privileged
tool runs: alice may ask for `mcp:admin`, but without the role Keycloak does not issue it and the
resource server would drop it anyway. → [keycloak.md](keycloak.md) on role scope mappings;
`keycloakEffectiveScopes()` in `src/shared/jwt.ts`.

## Scope

What a *client* was granted, as a space-separated list in the token's `scope` claim — `mcp:tools` for
the ordinary tools, `mcp:admin` for the privileged one. A scope is a grant, not a right: it says what
the user consented to let this client do, which is why it is checked together with the user's role.
Which scopes a client asks for is decided by SEP-835 — the 401's `scope=`, else the PRM's
`scopes_supported`, else the client's own configuration — and that ordering is why required scopes
belong on the verifier here, not on `requireBearerAuth`. → [spec-background §3](spec-background.md#3-sep-835--scope-selection-and-the-trap-this-repository-hit);
the wiring table in [`src/shared/README.md`](../src/shared/README.md).

## Sender-constrained token

A token bound to a key its legitimate holder possesses, so that stealing the token is not enough.
Two standards: **DPoP** (RFC 9449), where the client signs a per-request proof with an ephemeral key
and the AS records its thumbprint in `cnf.jkt`; and **certificate-bound tokens** (RFC 8705), where the
binding is to a TLS client certificate. Neither is implemented by the SDK, and both are the real
answer to the replay problem that short lifetimes only bound. → docs-only:
[patterns](patterns.md#sender-constrained-tokens); [08](08-mtls.md) is the adjacent, transport-level
idea.

## Service account

The identity a workload authenticates as, with no human behind it. Keycloak materialises a hidden
user `service-account-<clientId>` per confidential client, so the token has a `sub` and can hold
roles like any other principal — but no consent stands behind it, and running user actions through
one collapses the audit trail onto the workload. → [05 — client credentials](05-keycloak-client-credentials.md);
`service-account-mcp-server` performs introspection (07) and token exchange (10).

## Session

Two different things wear this name. The **MCP session** is the `mcp-session-id` header the server
returns from `initialize` and the client repeats on every later request; it is transport state, and
the SDK explicitly does not bind it to a token — so `mountMcp()` records the authenticated subject
and answers 403 when a different subject presents that id. The **OAuth/IdP session** is the user's
login at the authorization server, which outlives any single token, is what a refresh token draws
on, and is what an admin ends when they log a user out — invisible to a JWKS verifier and immediately
visible to introspection. → [00 — baseline](00-baseline-no-auth.md) for the MCP session;
[07](07-token-introspection.md) for the IdP session ending under a still-unexpired token.

## stdio transport

The other MCP transport: the client spawns the server as a child process and speaks JSON-RPC over its
stdin and stdout. There is no port and no third party, so the operating system's process boundary
*is* the authorization boundary — the spec says stdio servers SHOULD NOT implement the HTTP
authorization specification and should take credentials from their environment instead. What replaces
OAuth is discipline: never write to stdout, do not inherit the whole environment, constrain the
process. → docs-only, with a complete listing:
[patterns](patterns.md#stdio-transport-the-process-is-the-boundary).

## Streamable HTTP

The HTTP transport every example uses: one URL (`/mcp`) speaking JSON-RPC, where a POST answers with
either JSON or an SSE stream, an optional GET opens a long-lived notification stream, and DELETE ends
the session. It is strict about headers — a POST without both `Accept` values gets 406 and without
`Content-Type: application/json` gets 415, before authentication is even considered — which is the
first thing to check when a `curl` reproduction misbehaves. Auth middleware must guard POST, GET and
DELETE alike. → [00 — baseline](00-baseline-no-auth.md); `mountMcp()` in
[`src/shared/http.ts`](../src/shared/http.ts).

## Token exchange / on-behalf-of

RFC 8693: a service presents the caller's token as `subject_token` and receives a *different* token
for a downstream service — same user in `sub`, the service in `azp`, and an audience and scope
narrowed to that one hop. This is delegation, not impersonation: the downstream can authorise per
user and write an honest audit line, and neither token works at the other hop. Microsoft Entra's
"on-behalf-of" flow is the same shape. It is the correct alternative to forwarding the caller's
token. → [10 — token exchange](10-token-exchange-downstream.md); `exchangeToken()` in
`src/shared/keycloak.ts`.

## Trust boundary

The line across which one component stops trusting another's claims and starts verifying them.
Naming it is the whole design exercise: a gateway that authenticates callers and forwards
`X-Forwarded-User` has moved the boundary to "anyone who can reach the backend port", because a plain
header carries no proof. The fix is a signed, audience-bound, short-lived, replay-checked assertion,
with network isolation as defence in depth rather than the mechanism. → [09 — auth gateway](09-auth-gateway.md),
which ships the forgeable variant behind `INTERNAL_TRUST_MODE=network` so a test can prove it.

## WWW-Authenticate challenge

The header on a 401 or 403 that tells the client what went wrong and where to go:
`Bearer error="…", error_description="…", scope="…", resource_metadata="…"`, in that order, with the
last two present only when the middleware was configured for them. It is the entry point of the whole
discovery sequence, and it is also a header-injection hazard — the SDK interpolates the error message
without escaping, so every message here is a static string or passes through `headerSafe()`. A server
with nothing to discover omits `resource_metadata` deliberately rather than advertising a document
that cannot exist. → [spec-background §2](spec-background.md#step-1--the-challenge);
[01](01-api-key.md) and [02](02-jwt-local.md) for the deliberately bare challenge; [08](08-mtls.md)
has none at all.
