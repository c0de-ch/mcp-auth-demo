# 00 — Baseline: Streamable HTTP, no auth

**Directory:** `examples/00-baseline-no-auth` · **Port:** 4100 · **Authorization server:** none

This is the reference implementation. Every other example in this repository is *this* server plus
an auth middleware, and *this* client plus a way to obtain credentials. Read it once; afterwards
each example page only talks about the auth part.

## Streamable HTTP in one paragraph

MCP's Streamable HTTP transport is a single URL (`/mcp`) that speaks JSON-RPC:

* the client `POST`s a JSON-RPC message with `Accept: application/json, text/event-stream`; the
  server answers either with a JSON body or an SSE stream (`event: message` / `data: {...}`)
* an optional `GET` opens a long-lived SSE stream for server-initiated notifications
* `DELETE` ends the session

The SDK is strict about the headers: a POST without both `Accept` values gets **406**, without
`Content-Type: application/json` gets **415** (the shared `mountMcp` checks this before anything
else, so it also holds for the very first request). A body that is not valid JSON gets **400** with
a JSON-RPC `-32700` error. Remember that when you test with `curl`.

## Sessions

The first request must be `initialize`. The server creates a `StreamableHTTPServerTransport`
together with a fresh `McpServer` for it and answers with an `mcp-session-id` header. The client
sends that id on every later request; the server routes it to the same transport. Unknown id → 404
(the SDK client treats this as "session expired"); missing id on a non-initialize request → 400.
`DELETE`, a closed transport, or 30 minutes without a request (`sessionIdleMs`) removes the session.

This is implemented once in `src/shared/http.ts` (`mountMcp`) and reused everywhere. Two details
that the SDK deliberately leaves to you:

* **auth middleware must guard POST, GET and DELETE** — the notification stream and session
  termination are just as sensitive as tool calls
* **sessions are not bound to tokens** — a valid token for *another* user could otherwise reuse a
  session id it observed. `mountMcp` remembers the subject that initialized the session and answers
  **403** when a different subject shows up with that id. (Irrelevant here, essential from 01 on.)

A `stateless: true` mode (new transport + server per request, GET/DELETE → 405) exists for
deployments behind load balancers; the examples use stateful sessions because they show the
session ↔ identity binding.

## The demo tools

| Tool | Input | What it does |
|---|---|---|
| `whoami` | – | returns the `AuthInfo` the server derived from the caller's credentials, or `{ "anonymous": true }` |
| `add` | `{ a, b }` | returns `a + b`; proves the session works at all |
| `admin_only` | – | succeeds only when the caller's **effective scopes** include `mcp:admin`; otherwise a tool error `insufficient_scope: …` |

Tools only ever look at `extra.authInfo.scopes`. Deriving those scopes (from a key table, JWT
claims, Keycloak roles, an introspection response, …) is the verifier's job — this is what makes
the examples comparable. See "effective scopes" in `src/shared/README.md`.

## `PUBLIC_HOST` and LAN testing

This repository is meant to be exercised from *other* machines on your network (a laptop running
the client, a phone opening the login page). Therefore:

* every server binds `0.0.0.0`
* every URL that matters — the MCP endpoint, the OAuth `resource`, the Keycloak issuer, the
  callback URL — is built from **one** value, `PUBLIC_HOST` (`.env`), via `publicUrl()` /
  `keycloak()` in `src/shared/env.ts`; nothing is derived from the request's `Host` header and
  nothing says `localhost`
* if `PUBLIC_HOST` is unset the first non-loopback IPv4 address is used; the startup banner tells
  you which value was picked and where it came from

OAuth is unforgiving about this: the `resource` in the token, the `resource` in the Protected
Resource Metadata and the URL the client dials must be byte-identical, and Keycloak's `iss` must
equal the issuer the server verifies against. One canonical string avoids a whole class of bugs.

## Host-header validation (DNS rebinding)

A web page on `evil.example` can make the victim's browser talk to `192.168.78.87:4100` by
rebinding its DNS name to that IP; the request then arrives with `Host: evil.example`. Without a
check the unauthenticated server would happily execute tools for the attacker. `createApp()` installs
the SDK's `hostHeaderValidation` with `[PUBLIC_HOST, localhost, 127.0.0.1, [::1]]` (+
`MCP_ALLOWED_HOSTS`) and answers **403** for anything else — before the body is even parsed. The
example test and README show the `curl` reproduction.

Two smaller hygiene points live in the same file: Express's default error and 404 pages (an HTML
stack trace with file paths, `Cannot GET /x`) are replaced by JSON-RPC error bodies, and the request
log prints method, URL (path plus query string), status and duration — never headers or bodies.
Note the query string: examples 03 and 06 serve `/authorize`, whose query carries `state` and the
PKCE challenge; neither is secret, but a production log would trim it.

## How the code is organised

```
examples/00-baseline-no-auth/server.ts   createApp() → mountMcp({ createServer }) → listen()
examples/00-baseline-no-auth/client.ts   StreamableHTTPClientTransport → runDemo() → printResult()
src/shared/env.ts                        PUBLIC_HOST, ports, canonical URLs, Keycloak endpoints
src/shared/http.ts                       Express app, sessions, Host check, listen banner
src/shared/tools.ts                      whoami / add / admin_only
src/shared/client/run.ts                 list tools → whoami → add → admin_only report, RESULT line
```

The client's last stdout line is `RESULT {"example":"00",…,"adminOnly":"denied"}` — the
machine-readable summary `npm run smoke` compares against its expectation table. `MCP_SERVER_URL`
(or the first CLI argument) points the client at another machine; `EXPECT_ADMIN=ok|denied` turns a
wrong `admin_only` outcome into exit code 2.

The server file is ~20 lines. Every other example's `server.ts` differs from it by one added
option — `auth: requireBearerAuth({ verifier })` — plus whatever it takes to build that verifier
(and, for OAuth examples, the metadata routes clients discover the authorization server through).

## Threat model of "no auth"

Everything is allowed for everyone who can reach the port. Use this only on a trusted network,
behind a gateway that authenticates for you (see example 09), or over stdio where the process
boundary is the auth boundary (`docs/patterns.md`).
