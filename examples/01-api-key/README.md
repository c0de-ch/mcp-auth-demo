# 01 — API key: `Authorization: Bearer <static key>`

The baseline server plus one middleware: every request must present a known API key as an RFC 6750
bearer credential. The server keeps only SHA-256 digests (principal + scopes per key) and looks
keys up with constant work (`timingSafeEqual` against every entry). No authorization server, no
browser — the key is the whole story. Full walk-through: [`docs/01-api-key.md`](../../docs/01-api-key.md).

## Run it

```bash
npm run ex:01:server                                     # terminal 1 — http://<PUBLIC_HOST>:4101/mcp
npm run ex:01:client                                     # terminal 2 — alice (default key): admin_only denied
MCP_API_KEY=demo-api-key-bob EXPECT_ADMIN=ok npm run ex:01:client   # bob: admin_only ok
npm run ex:01:client -- http://192.168.78.87:4101/mcp    # from another LAN machine (or MCP_SERVER_URL=…)
```

## Break it

```bash
MCP_API_KEY=nope npm run ex:01:client     # "API key rejected (401)…", exit 1
curl -si -X POST http://192.168.78.87:4101/mcp \
  -H 'Accept: application/json, text/event-stream' -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}'
# -> 401 · WWW-Authenticate: Bearer error="invalid_token", error_description="Missing Authorization header"
#    (deliberately NO resource_metadata — there is nothing to discover)
```

The full negative matrix (one-char-off key, `Bearer  key` double space, wrong scheme, runtime key
removal, session↔principal binding, constant-time lookup unit test) is `server.test.ts`:
`npx vitest run examples/01-api-key`.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `MCP_API_KEYS` | the two DEMO keys | server table: `key:principal:scope scope;…` |
| `MCP_API_KEY` | – (required) | the key the client presents |
| `PORT_01` / `MCP_PORT` | 4101 | server port |
| `MCP_SERVER_URL` / first CLI arg | `http://<PUBLIC_HOST>:4101/mcp` | URL the client dials |
| `EXPECT_ADMIN` | – | `ok`\|`denied` — client exits 2 when `admin_only` disagrees |

Both keys in the default table are DEMO credentials (see `.env.example`); rotate before any real use.

## Integration notes

* No shared changes needed; implemented against the frozen `src/shared` API.
* Deviation from design §6.1, per the post-design SEP-835 finding: the `mcp:tools` requirement is
  enforced inside the verifier (`InsufficientScopeError`, static message) instead of
  `requireBearerAuth({ requiredScopes })`. Consequence: the 401 challenge carries neither
  `resource_metadata` nor `scope` — nothing a keyless client could act on anyway — and the
  smoke row (401 without `resource_metadata`) still passes as specified.
