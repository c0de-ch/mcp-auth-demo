# 10 — token exchange: call a downstream API on the user's behalf

Example 04's Keycloak resource server plus one tool, `downstream_profile`: the MCP server trades
the caller's token (RFC 8693 standard token exchange, client `mcp-server`) for one scoped to a
separate downstream API (`aud=downstream-api`) and calls that API **as the user** — never by
forwarding the caller's token. Full walk-through: [`docs/10-token-exchange-downstream.md`](../../docs/10-token-exchange-downstream.md).

## Run

```bash
npm run kc:up                 # Keycloak must be running
npm run ex:10:all             # downstream API :4190 + MCP server :4110 in one terminal
npm run ex:10:client          # DCR + browser login, then downstream_profile
# or two terminals:           npm run ex:10:downstream / npm run ex:10:server
# anti-pattern tool as well:  DEMO_PASSTHROUGH=1 npm run ex:10:all
```

The client's `RESULT` line carries `extra.downstream` — the downstream API's view of the exchanged
token: `sub` = you, `azp` = `mcp-server`, `aud` = `downstream-api`.

## Verify / break it

```bash
npx vitest run examples/10-token-exchange-downstream   # hermetic + Keycloak-backed matrix
```

Headline negatives (details and curl reproductions in the docs page): the exchanged token is
refused at `/mcp` (401, wrong audience), the caller's MCP token is refused at `/me` (401, wrong
audience), an exchange without `scope=downstream-api` is `invalid_request`, an exchange by a client
without `standard.token.exchange.enabled` is refused, and `downstream_passthrough`
(`DEMO_PASSTHROUGH=1`) shows the confused-deputy anti-pattern failing.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `PORT_10` | `4110` | MCP server port |
| `PORT_10_DOWNSTREAM` | `4190` | downstream API port |
| `MCP_SERVER_CLIENT_SECRET` | `mcp-server-secret-demo` (DEMO) | secret of the exchanging client `mcp-server` |
| `DEMO_PASSTHROUGH` | unset | `1` registers the `downstream_passthrough` anti-pattern tool |
| `MCP_AUDIENCE`, `OAUTH_*`, `MCP_SERVER_URL`, … | see `.env.example` | as in example 04 |

## Integration notes

* **Port 4190 is on the WHATWG fetch bad-ports list** (ManageSieve): Node's global `fetch`
  refuses to dial it — `TypeError: fetch failed`, `cause: Error: bad port` — while `curl` and
  `node:http` work. Worked around inside this example (`httpGetJson` in `server.ts` uses
  `node:http` for the downstream call). If shared code ever needs to reach `:4190` via `fetch`
  (`waitForHttp`, a smoke `readyUrl`, …) it will hit the same wall; consider moving
  `PORT_10_DOWNSTREAM` off the blocklist (e.g. 4191) in a later phase. Nothing shared touches it
  today (smoke waits on `:4110/healthz` only).
* **Smoke's browser step for 10 uses `OAUTH_CLIENT_ID=mcp-cli`**, whose registered redirect URIs
  are pinned to callback port **4199** — running smoke with `OAUTH_CALLBACK_PORT` set to anything
  else makes Keycloak answer "Invalid parameter: redirect_uri" before the login page. Run
  `npm run smoke -- 10` with 4199 free (DCR-based manual runs can use any free port — DCR
  registers its own redirect URI).
* `src/shared/README.md` "Known limitations" says dynamically registered clients get no
  `preferred_username` / `realm_access`; on the current realm the `mcp:tools` scope carries both
  (verified: a DCR run's `whoami` shows `username: "alice"`, `roles: ["mcp-user"]`). The shared
  README is frozen for example agents — worth updating in integration.
