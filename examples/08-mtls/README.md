# 08 — Mutual TLS (mTLS)

The client **certificate** is the credential: authentication happens in the TLS handshake, before
a single HTTP byte. No bearer tokens, no Keycloak, no browser — `Authorization` headers are
ignored. Full walk-through: [`docs/08-mtls.md`](../../docs/08-mtls.md).

* `server.ts` — `certAuth` maps the verified peer certificate to the shared `AuthInfo`
  (CN → `clientId`/`sub`, OU `mcp-admin` → `mcp:admin`, notAfter → `expiresAt`), `mountMcp({ auth: certAuth() })`
* `tls.ts` — `listenTls()` (https, `requestCert` + `rejectUnauthorized`, TLS 1.3 only) and the
  undici `Agent`/`fetch` the client plugs into `StreamableHTTPClientTransport`
* `client.ts` — picks a certificate via `MTLS_CLIENT` and runs the shared demo

## Run it

```bash
npm run ex:08:certs                    # once: demo PKI → examples/08-mtls/certs/ (git-ignored)
npm run ex:08:server                   # terminal 1 — https://<PUBLIC_HOST>:4108/mcp
npm run ex:08:client                   # terminal 2 — alice (mcp:tools)
MTLS_CLIENT=bob npm run ex:08:client   #             bob   (mcp:tools + mcp:admin) → admin_only ok
```

From another LAN machine: `npm run ex:08:client -- https://192.168.78.87:4108/mcp` — the server
certificate's SAN contains `IP:<PUBLIC_HOST>`, so verification succeeds without `--insecure`
anywhere. Changed `PUBLIC_HOST`? Regenerate: `bash scripts/gen-certs.sh --force`.

## Verify / break it

```bash
cd examples/08-mtls/certs
curl -sS --cacert ca.crt --cert alice.crt --key alice.key https://192.168.78.87:4108/healthz   # {"ok":true}
curl -sS --cacert ca.crt https://192.168.78.87:4108/healthz          # alert: certificate required
MTLS_CLIENT=none npm run ex:08:client                                # handshake failure → exit 1
MTLS_CLIENT=expired-alice npm run ex:08:client                       # handshake failure → exit 1
MTLS_CLIENT=rogue-client npm run ex:08:client                        # unknown CA → exit 1
MTLS_ALLOWED_CN=bob npm run ex:08:server                             # then alice → HTTP 403
```

Tests (hermetic — own PKI in a temp dir, servers on port 0): `npx vitest run examples/08-mtls`.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `MTLS_CLIENT` | `alice` | client certificate: `alice` \| `bob` \| `expired-alice` \| `rogue-client` \| `none` |
| `MTLS_ALLOWED_CN` | `alice,bob` | server: CNs that are *authorized* (authentication ≠ authorization) |
| `MTLS_SOFT_FAIL` | – | `1` → `rejectUnauthorized: false`; app answers 401 JSON instead of a handshake alert |
| `MTLS_CERT_DIR` | `examples/08-mtls/certs` | where both sides read PEM files (tests point it at a temp dir) |
| `PORT_08` | `4108` | https port |

## Integration notes

* **`scripts/gen-certs.sh` env precedence is inverted vs `env.ts`**: it sources the repo `.env`
  *after* the caller's environment (`set -a; . .env`), so an explicitly exported `PUBLIC_HOST`
  is clobbered by the `.env` value — the header's advertised
  `PUBLIC_HOST=10.0.0.5 scripts/gen-certs.sh` only works when `.env` does not set `PUBLIC_HOST`.
  Harmless here (the SAN always also contains `IP:127.0.0.1, DNS:localhost`, which is what tests
  dial), and `OUT_DIR` is unaffected; suggested one-line fix when `scripts/` unfreezes:
  capture `CALLER_PUBLIC_HOST="${PUBLIC_HOST:-}"` before sourcing and prefer it afterwards.
* **No shared changes needed.** Design §6.8 says the shared `listen()` is http-only; the version
  on this branch already accepts a pre-built `server:` (and `publicUrl(port, path, 'https')`),
  so `listenTls()` here just wraps `https.createServer(...)` and delegates — banner and JSON
  404/error tail stay identical to every other example.
* **undici works, no fallback needed**: the SDK's `StreamableHTTPClientTransport` runs fine over
  `undici.fetch` + `Agent({ connect: { ca, cert, key } })` on Node 22.22 — POST SSE responses,
  the standalone GET notification stream and DELETE all verified (see `docs/08-mtls.md`). The
  only deviation from the §6.8 snippet: `servername` (SNI) is set only for DNS hostnames — RFC
  6066 forbids IP literals in SNI (Node warns DEP0123) and undici/Node verify IP SANs from the
  dialled host on their own.
* `.env.example` (frozen) lists only `MTLS_CLIENT`; `MTLS_ALLOWED_CN`, `MTLS_SOFT_FAIL` and
  `MTLS_CERT_DIR` could be added as comments to the "Example-specific" block when it unfreezes.
* Smoke starts this server with a fixed 1.5 s delay instead of polling `/healthz` (which needs a
  client certificate under hard-fail) — works as designed; no change requested.
