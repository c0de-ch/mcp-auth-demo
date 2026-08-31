# mcp-auth-demo

Twelve runnable **Model Context Protocol** server + client pairs, each demonstrating a different
way to answer the same question: *who is calling this MCP server, and what are they allowed to do?*

They start from an unauthenticated server, work up through a static API key and a self-issued JWT
to the pattern the MCP authorization specification actually recommends — an external identity
provider with the MCP server as a pure resource server — and then keep going into the situations
real deployments hit: machine-to-machine credentials, an OAuth facade, opaque tokens with
introspection, mutual TLS, an auth gateway, and calling a downstream API on the user's behalf.
Every example is two small files you can read in a sitting, plus a test suite that proves the
failure paths, plus a documentation page that explains the trade-off.

Built with `@modelcontextprotocol/sdk` 1.30.0 (TypeScript), the official `mcp` 2.1.1 Python SDK for
one example, and **Keycloak 26** as the identity provider. Everything runs locally with
`docker compose`; nothing here needs a cloud account.

> **This is a teaching repository.** It runs over plain HTTP on a LAN with published demo
> passwords. Read [`docs/threat-model.md`](docs/threat-model.md) before borrowing anything for
> production, and [`docs/lan-testing.md`](docs/lan-testing.md) for how to put it behind TLS.

## The approaches

| # | Approach | Caller | Browser | IdP | Token / credential | Server validates by | Spec |
|---|---|---|---|---|---|---|---|
| [00](examples/00-baseline-no-auth) | [No authentication](docs/00-baseline-no-auth.md) — the reference every other example modifies | anyone | – | – | none | nothing | baseline |
| [01](examples/01-api-key) | [Static API key](docs/01-api-key.md) | machine | no | no | shared secret | hashed table lookup | outside |
| [02](examples/02-jwt-local) | [Self-issued JWT](docs/02-jwt-local.md) via a local JWKS | user | no | no | JWT | signature + JWKS | outside |
| [03](examples/03-oauth-embedded-as) | [The MCP server *is* the OAuth 2.1 AS](docs/03-oauth-embedded-as.md) | user | yes | built in | opaque | own store | conformant |
| [04](examples/04-keycloak-resource-server) | **[Keycloak AS, MCP as resource server](docs/04-keycloak-resource-server.md)** — the recommended pattern | user | yes | yes | JWT | signature + JWKS | conformant |
| [05](examples/05-keycloak-client-credentials) | [Client credentials](docs/05-keycloak-client-credentials.md) (service account, `private_key_jwt`) | workload | no | yes | JWT | signature + JWKS | conformant |
| [06](examples/06-oauth-proxy-keycloak) | [OAuth facade](docs/06-oauth-proxy-keycloak.md) hiding Keycloak | user | yes | yes (hidden) | JWT | signature + JWKS | transitional |
| [07](examples/07-token-introspection) | [Token introspection](docs/07-token-introspection.md) (RFC 7662) | user | yes | yes | opaque or JWT | asks the AS, cached | conformant |
| [08](examples/08-mtls) | [Mutual TLS](docs/08-mtls.md) — the certificate is the credential | machine / host | no | no | X.509 key pair | TLS handshake | outside |
| [09](examples/09-auth-gateway) | [Auth gateway / sidecar](docs/09-auth-gateway.md) | user | yes | yes | JWT → signed assertion | gateway validates, backend verifies the assertion | infrastructure |
| [10](examples/10-token-exchange-downstream) | [Token exchange](docs/10-token-exchange-downstream.md) (RFC 8693) for a downstream API | user | yes | yes | JWT → exchanged JWT | signature + JWKS, both hops | conformant |
| [11](examples/11-python-mcp-keycloak) | [Python twin of 04](docs/11-python-mcp-keycloak.md) | user | yes | yes | JWT | signature + JWKS | conformant |

"Spec" is how the example relates to the MCP authorization specification: **conformant** implements
it, **transitional** is a pattern it tolerates, **outside** is a legitimate approach the spec simply
does not describe, and **infrastructure** solves it a layer below. None of them is wrong; they
answer different questions. [`docs/comparison.md`](docs/comparison.md) is the decision aid —
including which approach to choose when — and [`docs/patterns.md`](docs/patterns.md) covers what
this repository documents but does not implement (stdio, DPoP, device grant, CIMD, off-the-shelf
gateways, workload identity, and more).

## Quick start

```bash
git clone https://github.com/c0de-ch/mcp-auth-demo && cd mcp-auth-demo
npm install
cp .env.example .env      # then set PUBLIC_HOST to this machine's LAN address
```

No identity provider needed for the first three:

```bash
npm run ex:01:server      # terminal 1
npm run ex:01:client      # terminal 2
```

```
tools        -> whoami, add, admin_only
whoami       -> {"clientId":"alice","scopes":["mcp:tools"],"extra":{"sub":"alice","kind":"api-key"}}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
```

Then start Keycloak and run the real thing — the client discovers the authorization server from the
server's 401, registers itself, opens a browser, and comes back with a token:

```bash
npm run kc:up             # Keycloak 26 on :8180, realm imported
npm run ex:04:server      # terminal 1
npm run ex:04:client      # terminal 2 — log in as alice / password
```

Log in as `bob` instead and `admin_only` succeeds, because bob holds the `mcp-admin` realm role.
That difference — a scope the client was granted versus a role the user actually holds — is the
authorization story these examples keep coming back to.

## How it fits together

Every example shares the same three demo tools, so the only thing that changes between them is the
authentication: `whoami` (echoes the caller's identity as the server sees it), `add` (any
authenticated caller) and `admin_only` (needs the `mcp:admin` scope). Read one example, and the
next one is a diff.

```
src/shared/       env, HTTP + session plumbing, the demo tools, JWT verification,
                  protected-resource metadata, Keycloak helpers, the CLI OAuth client
examples/NN-*/    server.ts, client.ts, server.test.ts, README.md  (+ extra roles where needed)
docs/NN-*.md      what it is, when to use it, how it works, how to break it, threat notes
keycloak/         docker compose + the imported realm
scripts/          smoke matrix, headless browser login, demo PKI, Keycloak lifecycle
```

The one rule worth knowing before reading the code: **the verifier decides scopes, tools only read
them.** A verifier turns whatever credential arrived into an `AuthInfo` with a list of effective
scopes — for Keycloak that means keeping `mcp:admin` only when the user's realm roles back it — and
the tools never look at anything else. Swapping authentication approaches therefore never touches a
tool. [`src/shared/README.md`](src/shared/README.md) documents the shared API.

## Running it from another machine

Servers bind `0.0.0.0` and derive every URL from `PUBLIC_HOST`, because the interesting failures
(issuer mismatches, audience mismatches, callback URLs that only work on loopback) never show up
when everything is `localhost`. Set `PUBLIC_HOST` to your LAN address and point a client at it:

```bash
MCP_SERVER_URL=http://192.168.1.10:4104/mcp npm run ex:04:client
```

[`docs/lan-testing.md`](docs/lan-testing.md) covers firewall ports, browser-on-another-machine
logins, clock skew and the move to TLS.

## Verifying

```bash
npm run typecheck    # TypeScript, project-wide
npm test             # 437 tests; Keycloak-backed suites skip themselves if it is not running
npm run test:kc      # same, but a skipped Keycloak suite is a failure
npm run smoke        # end-to-end: real ports, real browser logins, every example
```

The tests are where the security claims live. Each example asserts its happy path *and* its
rejection matrix — expired tokens, wrong issuer, wrong audience, missing scope, tampered payloads,
replayed codes, forged assertions, untrusted certificates — because an authentication example that
only demonstrates success is not demonstrating much. `npm run smoke` drives the browser flows
headlessly with Playwright and checks what each client actually printed.

## Documentation

| Page | What it covers |
|---|---|
| [course.html](docs/course.html) | **Start here if you are learning.** A fourteen-episode lesson over all twelve examples, each with a read-aloud script |
| [comparison.md](docs/comparison.md) | The matrix, and which approach to choose when |
| [spec-background.md](docs/spec-background.md) | The MCP authorization spec and the RFCs it builds on |
| [sdk-notes.md](docs/sdk-notes.md) | Verified behaviour of SDK 1.30.0 — the things that silently break auth |
| [threat-model.md](docs/threat-model.md) | Per-threat: the attack, the mitigation, the example that shows it |
| [keycloak.md](docs/keycloak.md) | The realm explained, hardening, swapping in another IdP |
| [lan-testing.md](docs/lan-testing.md) | `PUBLIC_HOST`, ports, remote browsers, TLS |
| [patterns.md](docs/patterns.md) | Documented but not implemented, and why |
| [glossary.md](docs/glossary.md) | The vocabulary, with pointers to where each term appears |
| [release-signing.md](docs/release-signing.md) | Verifying releases with Sigstore cosign |
| [design.md](docs/design.md) | How the repository was designed, and the decisions behind it |

## Security notes

The demo credentials (`alice`/`bob` with the password `password`, the API keys in `.env.example`,
the Keycloak client secrets, the admin console login) are published on purpose so the examples run
unattended. They are labelled `DEMO` wherever they appear. Beyond that: the transport is plain HTTP,
which is why `src/shared/env.ts` sets `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` — the SDK
otherwise refuses a non-HTTPS issuer, correctly; Keycloak runs in dev mode with brute-force
protection off; and anonymous dynamic client registration is open so the examples can demonstrate
it. Each of those is called out where it matters, with the production alternative next to it.

Releases are signed with [Sigstore cosign](docs/release-signing.md) — source archive, checksums and
container image, all keyless with GitHub OIDC, plus SLSA build provenance.

## License

[MIT](LICENSE).
