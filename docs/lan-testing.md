# Running the examples across a LAN

Every server in this repository binds `0.0.0.0` and builds its public URLs from a single variable,
`PUBLIC_HOST`, so the examples work from other machines rather than only from the box that runs
them. This page explains what to set, which ports to open, how the browser-based flows behave when
the browser is not on the same machine, and how to move off plain HTTP.

## The one variable that matters

`PUBLIC_HOST` is the address **other machines use to reach this box** — a LAN IP such as
`192.168.1.10` or a resolvable host name. It flows into three places that must agree:

1. **Keycloak's issuer.** `KC_HOSTNAME=http://${PUBLIC_HOST}:${KEYCLOAK_PORT}` pins the `iss` claim
   of every token and the contents of the discovery document.
2. **The MCP server's resource URL.** `publicUrl(port)` in `src/shared/env.ts` produces
   `http://${PUBLIC_HOST}:${port}/mcp`, which is what the Protected Resource Metadata advertises as
   `resource` and what clients must dial.
3. **The OAuth callback URL**, unless you override it — see below.

```bash
cp .env.example .env
# set PUBLIC_HOST to this machine's LAN address
sed -i 's/^PUBLIC_HOST=.*/PUBLIC_HOST=192.168.1.10/' .env
npm run kc:up
npm run kc:status     # prints the issuer Keycloak actually advertises — check it matches
```

If `PUBLIC_HOST` is unset, `src/shared/env.ts` picks the first non-internal IPv4 address of the
host and falls back to `127.0.0.1`. Auto-detection is a convenience for a single-homed machine; on
a box with several interfaces (Docker bridges, VPNs, a second NIC) set it explicitly. Every server
prints which source it used in its startup banner:

```
[04-keycloak-resource-server] listening on 0.0.0.0:4104
[04-keycloak-resource-server] MCP endpoint: http://192.168.1.10:4104/mcp   (PUBLIC_HOST 192.168.1.10 — env)
```

**Never use `localhost` for `PUBLIC_HOST`.** A token whose issuer is `http://localhost:8180/...`
cannot be validated by a resource server that expects the LAN address, and a Protected Resource
Metadata document that advertises `http://localhost:4104/mcp` makes the SDK client reject the
server it just connected to (`Protected resource … does not match expected …`). `scripts/smoke.ts`
refuses to run with `PUBLIC_HOST=localhost` for this reason.

## Ports

| Port | What |
|---|---|
| 8180 | Keycloak (`KEYCLOAK_PORT`) |
| 4100–4111 | one MCP server per example (`PORT_00` … `PORT_11`); 4108 is HTTPS |
| 4119 | example 09's internal server behind the gateway |
| 4190 | example 10's downstream API |
| 4192 | example 02's local token issuer |
| 4199 | the client-side OAuth callback listener (`OAUTH_CALLBACK_PORT`) |

Open the ones you use. On a typical Linux dev box:

```bash
sudo ufw allow from 192.168.1.0/24 to any port 8180 proto tcp
sudo ufw allow from 192.168.1.0/24 to any port 4100:4111 proto tcp
```

Tests never use these ports — `startTestServer()` binds an ephemeral port — so a running demo and
`npm test` do not collide. `npm run smoke` does use the real ports and runs examples sequentially,
because the callback listener port is shared.

## Host-header validation

`createApp()` installs a DNS-rebinding guard: requests whose `Host` header is not `PUBLIC_HOST`,
`localhost`, `127.0.0.1` or `[::1]` are rejected with 403. If you reach a server through a name
that is not in that list — a reverse proxy, an mDNS name, a second address of the same box — add it:

```bash
MCP_ALLOWED_HOSTS=mcp.lan,10.0.0.5 npm run ex:04:server
```

Host names only, no ports; matching is case-insensitive. A 403 that says `Invalid Host: …` is this
guard, not an authentication failure.

## Client on one machine, server on another

Point the client at the server; everything else is discovery:

```bash
# on the second machine, in a clone of this repository
npm install
MCP_SERVER_URL=http://192.168.1.10:4104/mcp npm run ex:04:client
# or as a positional argument
npm run ex:04:client -- http://192.168.1.10:4104/mcp
```

The client learns the authorization server from the 401 challenge and the Protected Resource
Metadata, so it needs no Keycloak configuration of its own — but it must be able to reach Keycloak
on 8180 as well, because it performs the token request itself.

## Browser-based flows across machines

Examples 03, 04, 06, 07, 09, 10 and 11 open a browser for the authorization-code flow. The client
starts a small HTTP listener for the redirect, by default on `127.0.0.1:4199`, and that address must
be reachable **by the browser**.

* **Browser on the same machine as the client** (the normal case): nothing to do.
* **Browser on another machine** — for example the client runs headless on a server and you log in
  from a laptop: the callback must point at an address the laptop can reach.

  ```bash
  OAUTH_REDIRECT_HOST=192.168.1.10 npm run ex:04:client
  ```

  The listener then binds `0.0.0.0` instead of loopback. The realm already registers
  `http://${PUBLIC_HOST}:4199/callback` alongside the two loopback forms, so Keycloak accepts it.
  Be aware of what this means: the authorization code travels over your LAN in cleartext to a
  listener anyone on that LAN can reach. Acceptable for a demo, not for anything real.

* **No browser at all**: set `MCP_NO_BROWSER=1` and the client prints the authorization URL for you
  to open manually; or set `MCP_BROWSER_CMD` to drive it automatically:

  ```bash
  MCP_BROWSER_CMD="python3 scripts/browser-login.py --user alice --password password" \
    npm run ex:04:client
  ```

  That is exactly what `npm run smoke` does. The driver is Python Playwright with headless Chromium;
  on another machine install it with
  `uv run --with playwright python -m playwright install chromium`.

Registered redirect URIs are matched exactly by Keycloak, so if you change `OAUTH_CALLBACK_PORT`
you must add the new URI to the `mcp-cli` client (or let Dynamic Client Registration register its
own, which is the default path — see [keycloak.md](keycloak.md)).

Tokens are cached per server URL under `.mcp-auth/` (mode 0600, git-ignored); `MCP_AUTH_STORE_DIR`
moves the store, and `npm run ex:04:client -- --logout` clears it.

## Clock skew

JWT validation allows five seconds of skew (`clockToleranceSec` in `src/shared/jwt.ts`, `leeway` in
the Python example). Machines whose clocks differ by more than that produce tokens that look
expired or not yet valid; run NTP on every machine involved before blaming the code.

## Plain HTTP, and how to get off it

This demo speaks plain HTTP so it can run on a LAN with no certificate work. That means access
tokens, authorization codes and the demo passwords are visible to anyone who can see the traffic,
and it is why `src/shared/env.ts` sets `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL=1` — the MCP
authorization specification requires HTTPS for authorization-server URLs, and the SDK enforces that
unless the issuer is loopback or the flag is set. The flag is a demo affordance, not a
recommendation; [threat-model.md](threat-model.md) lists what it costs you.

To run over TLS:

1. Issue certificates for `PUBLIC_HOST` — `scripts/gen-certs.sh` (written for example 08) produces a
   demo CA and a server certificate whose SAN covers `PUBLIC_HOST`, `127.0.0.1` and `localhost`, and
   any real CA or an internal PKI works as well.
2. Put Keycloak behind TLS — either terminate in front of it, or give the container the certificate
   and set `KC_HOSTNAME=https://${PUBLIC_HOST}:8443`.
3. Terminate TLS in front of the MCP servers, or follow example 08, which serves HTTPS directly
   (`listen()` accepts a pre-built server, and `publicUrl(port, path, 'https')` produces the URL).
4. Trust the CA on every client machine, then remove
   `MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL` from the environment — nothing else changes, because
   every URL in the examples is derived, not hard-coded.

Example 08 is worth reading first: it already does the certificate handling end to end.
