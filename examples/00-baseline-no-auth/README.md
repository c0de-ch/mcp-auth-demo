# 00 — Baseline: Streamable HTTP without authentication

The reference every other example is diffed against. A plain MCP server over Streamable HTTP with
the three shared demo tools, and a client that connects without any credentials.

## What it demonstrates

* the Express 5 + `StreamableHTTPServerTransport` wiring (`src/shared/http.ts`): one transport and
  one `McpServer` per session, `mcp-session-id` header, `DELETE` to end a session
* the shared demo tools: `whoami`, `add`, `admin_only` (`src/shared/tools.ts`)
* the LAN conventions: bind `0.0.0.0`, advertise one canonical URL built from `PUBLIC_HOST`
* DNS-rebinding protection via Host-header validation — the only "security" an unauthenticated
  server can offer

## Run it

```bash
npm run ex:00:server                    # terminal 1 — http://<PUBLIC_HOST>:4100/mcp
npm run ex:00:client                    # terminal 2 — or: npm run ex:00:client -- http://192.168.78.87:4100/mcp
```

Port: `PORT_00` (or `MCP_PORT`), default 4100. The client dials, in this order: the first CLI
argument, `MCP_SERVER_URL`, `http://<PUBLIC_HOST>:4100/mcp`.

## What you should see

Server:

```
[00-baseline-no-auth] listening on 0.0.0.0:4100
[00-baseline-no-auth] MCP endpoint: http://192.168.78.87:4100/mcp   (PUBLIC_HOST 192.168.78.87 — env)
POST /mcp 200 10.1ms
...
```

Client:

```
tools        -> whoami, add, admin_only
whoami       -> {"anonymous":true}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
RESULT {"example":"00","tools":["add","admin_only","whoami"],"whoami":{"anonymous":true},"add":"5","adminOnly":"denied"}
```

`whoami` has nothing to report and `admin_only` can never succeed: nobody has any scopes. The
last line is the machine-readable summary every client prints (`npm run smoke` reads it);
`EXPECT_ADMIN=ok|denied` makes the client exit 2 when reality disagrees.

Try the Host check by hand (a forged `Host` is what a DNS-rebinding attack looks like to the server):

```bash
curl -s -X POST http://192.168.78.87:4100/mcp -H 'Host: evil.example' \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# -> 403 {"jsonrpc":"2.0","error":{"code":-32000,"message":"Invalid Host: evil.example"},"id":null}
```

## Why this is NOT enough

Anyone who can reach the port can call every tool as an anonymous caller, and the server cannot
tell callers apart, rate-limit them, audit them or give some of them more rights than others.
Every following example keeps this exact server and adds one thing:

| Example | Adds |
|---|---|
| `01-api-key` | a shared secret per client (`Authorization: Bearer <key>`) |
| `02-jwt-local` | signed tokens with claims → scopes |
| `03-oauth-embedded-as` | the full OAuth 2.1 dance with the MCP server acting as authorization server |
| `04-keycloak-resource-server` | the spec-recommended shape: Keycloak issues tokens, the server only verifies them |
| … | see the repository README for the complete catalog |

Implementation-wise every one of them is `mountMcp(app, { auth: <middleware> })` on the server and
either a static header or an `OAuthClientProvider` on the client. See `docs/00-baseline-no-auth.md`.
