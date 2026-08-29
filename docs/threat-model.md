# Threat model

What each authentication approach in this repository protects against, what it does not, and where
to look in the code. The examples are deliberately small, so most controls are one or two lines —
this page names the attack each of those lines exists to stop.

Scope: an MCP server exposing tools over Streamable HTTP, its clients, and the authorization server
in between. Out of scope: the security of the tools themselves (what an authorised caller is
allowed to *do* is an application concern), physical access, and supply-chain attacks on the
dependencies — though [release-signing.md](release-signing.md) covers how this repository's own
artifacts are signed.

**This is a demo.** It runs over plain HTTP on a LAN with published passwords. The threats below
are real; the demo's own posture against several of them is deliberately weak, and each section
says so.

## Threats

### Token leakage in transit

An attacker who can observe the network reads a bearer token and replays it. Bearer tokens are
exactly as strong as the channel carrying them.

*Mitigation:* TLS everywhere. The MCP authorization specification requires HTTPS for authorization
server endpoints, and the SDK enforces it unless the issuer is loopback — which is why
`src/shared/env.ts` sets `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` for this LAN demo. That flag
is the single largest deviation from a production posture in this repository.
[lan-testing.md](lan-testing.md) shows how to move to TLS; example 08 already serves HTTPS.

*Beyond TLS:* sender-constrained tokens (DPoP, RFC 9449; certificate-bound tokens, RFC 8705) make a
stolen token useless without the corresponding key — see [patterns.md](patterns.md). Example 08's
mutual TLS achieves a similar property at the transport layer: the credential never leaves the
client because it is a private key, not a token.

### Token leakage through logs and errors

Tokens end up in request logs, crash dumps, or an error message echoed to the caller.

*Mitigation:* every server in this repository logs method, URL and status only; verifiers log at
most `sha256(token)[0:8]`; `formatAuthInfo` omits the token from `whoami` output.
`tests/conventions.test.ts` fails the build if an example logs a token.

There is a subtler variant the SDK forces on you: `requireBearerAuth` interpolates the *message* of
an `InvalidTokenError` into the `WWW-Authenticate` header without escaping. A message built from
attacker-controlled input would let that attacker inject header parameters. Every verifier here
therefore throws static strings, and the conventions test greps for template literals in those
constructors.

### Replay of a captured token

*Mitigation:* short lifetimes (15 minutes in this realm), plus one of: immediate revocation
checking (example 07 — the resource server asks the authorization server on every request, with a
short cache, so a revoked token stops working within the cache window) or sender constraining
(above). JWKS-based validation (example 04) cannot detect revocation at all; a token stays valid
until `exp`. That trade-off is the entire point of having both examples.

### Audience confusion — a token minted for one service used against another

An MCP server that accepts any well-signed token from its identity provider will happily accept a
token issued for a completely different application of the same realm.

*Mitigation:* validate `aud`, not just the signature and issuer. `createJwtVerifier` requires an
explicit audience and every Keycloak example checks `aud: mcp-server`; example 07 checks the
audience again in the introspection response even though Keycloak already refuses to introspect for
a client outside the audience. Example 10 proves the isolation in both directions: its exchanged
token (`aud: downstream-api`) is rejected by the MCP server, and an MCP token is rejected by the
downstream API.

The specification's mechanism for this is the resource indicator (RFC 8707): the client tells the
authorization server which resource the token is for. Keycloak ignores it — verified — so this
repository binds the audience through a client-scope mapper instead. Example 02 shows the strict
form, where the audience is the resource URL itself. See [keycloak.md](keycloak.md).

### Confused deputy — the server acting with more authority than the caller

The MCP server holds powerful credentials of its own. If it calls a downstream API with *its own*
identity while acting on a user's request, every user gets the server's authority.

*Mitigation:* on-behalf-of delegation. Example 10 exchanges the caller's token (RFC 8693) for one
scoped to the downstream API that keeps the user's `sub`, so the downstream service applies its own
authorization to the actual user. The same example ships the anti-pattern behind
`DEMO_PASSTHROUGH=1` — forwarding the caller's token unchanged — which the downstream API rejects
on audience, demonstrating why passthrough is not a shortcut.

A second form affects OAuth proxies: a proxy that presents a single static client to the upstream
authorization server can let one client consume another's consent. Example 06 documents this and
its consequences; the general rule is in [patterns.md](patterns.md).

### Authorization-code interception

An attacker who captures an authorization code redeems it before the legitimate client does.

*Mitigation:* PKCE with S256, mandatory in the SDK's authorization server and enforced by Keycloak
for the public clients here. Example 03 additionally implements the OAuth 2.1 rules that make a
captured code less useful: codes are single-use, and reusing one revokes every token already issued
from it; refresh tokens rotate, and replaying an old one revokes the family.

### Open redirect through `redirect_uri`

A permissive redirect URI turns the authorization server into an open redirector and hands codes to
an attacker.

*Mitigation:* exact matching of registered redirect URIs. Keycloak matches exactly — verified, it
does not even relax the port for loopback addresses — and the SDK's own authorization server
relaxes only the port for `127.0.0.1`/`localhost`, never the host or path. Example 03 tests that an
unregistered URI produces a 400 rather than a redirect, and that `localhost` and `127.0.0.1` do not
cross-match.

### Dynamic client registration abuse

Open registration lets anyone create clients — filling the database, or registering a client whose
name and redirect URI are designed to mislead a user on the consent screen.

*Mitigation:* this demo realm deliberately allows anonymous registration, because that is the flow
the MCP specification expects, but keeps consent required, full scope disabled, a scope allow-list
and a 200-client cap. [keycloak.md](keycloak.md) gives the hardened variant. Do not copy the demo
policy.

### DNS rebinding and Host-header attacks

A page in a victim's browser resolves an attacker-controlled name to your server's address and
talks to a local MCP server from the victim's network position.

*Mitigation:* `createApp()` validates the `Host` header against an allow-list built from
`PUBLIC_HOST` plus loopback (`MCP_ALLOWED_HOSTS` extends it) and answers 403 otherwise. Example 00
tests it. Browser clients additionally need a deliberate CORS policy; the SDK does not add one to
the MCP endpoint.

### Trusting headers behind a proxy

Once a gateway authenticates callers and forwards identity in headers, anything that can reach the
backend directly can forge that identity.

*Mitigation:* example 09 signs a short-lived assertion (30 seconds, single-use `jti`, explicit
audience) that the backend verifies, strips inbound copies of its own headers, and never passes the
caller's `Authorization` through. It also ships the insecure variant behind
`INTERNAL_TRUST_MODE=network`, with a test asserting that the forged header *is* accepted there —
so the warning cannot be quietly deleted. Network isolation is the other half; the demo binds the
internal listener publicly only because the examples must be reachable across a LAN.

### Session hijacking and session confusion

MCP sessions are identified by an `mcp-session-id` header. The SDK does not bind a session to the
principal that created it, so a second token could drive someone else's session.

*Mitigation:* `mountMcp` records the authenticated subject with the session and answers 403 if a
different subject presents the same session id; the auth middleware runs on POST, GET *and* DELETE,
so the SSE stream and teardown are protected too. Tested in examples 01 and 04.

### Credential and secret handling

*Mitigation:* no real secrets in the repository; demo values live in `.env.example` and are labelled
`DEMO`; `.env`, `.mcp-auth/`, generated certificates and generated realm files are git-ignored. The
CLI token store is written with mode 0600. API keys are stored hashed (example 01) and compared with
`timingSafeEqual` over every entry, so neither the value nor its position leaks through timing.
Client secrets are avoidable entirely: example 05's `private_key_jwt` variant proves the client's
identity with a signature, so no shared secret is transmitted.

### Denial of service and abuse

*Mitigation:* the SDK's authorization-server router rate-limits `/authorize`, `/token`, `/register`
and `/revoke` per IP (this repository disables the limits only under `MCP_RATE_LIMIT=0`, used by
tests and smoke); introspection results are cached so a token flood cannot be amplified into
authorization-server traffic (example 07); sessions have an idle sweeper. Anything beyond that —
per-user quotas, tool-level cost control — is out of scope here.

## Which example demonstrates which control

| Control | Examples |
|---|---|
| Credential never transmitted (key or certificate) | 05 (`private_key_jwt`), 08 (mTLS) |
| Hashed credential storage, constant-time compare | 01 |
| Signature, issuer and audience validation | 02, 04, 05, 06, 09, 10, 11 |
| Immediate revocation | 07 |
| Scope and role separation (effective scopes) | 04, 05, 07, 09, 10, 11 |
| Client-identity authorization | 05 (`service_only`) |
| PKCE, single-use codes, refresh rotation | 03 |
| Exact redirect-URI matching | 03, and Keycloak in 04/06/07/09/10/11 |
| Consent | 03, and Keycloak's consent screen for DCR clients |
| Audience isolation between services | 10 |
| Delegation instead of impersonation | 10 |
| Signed identity assertion across a trust boundary | 09 |
| Host-header validation | all (shared `createApp`) |
| Session bound to the authenticated subject | all (shared `mountMcp`) |
| Rate limiting | 03, 06 (SDK router) |

## What this repository does not defend against

Compromise of the authorization server or its signing keys; a malicious tool implementation; a
compromised client machine (tokens are readable in `.mcp-auth/` by the user who owns them); traffic
analysis; and — in the demo configuration specifically — anything an observer on the LAN can do,
because the transport is plain HTTP. Fix that first if you take any of this beyond a demo.
