# 02 — Self-issued JWT verified via a JWKS URL

The baseline server (00) plus a **bearer JWT** verifier. A tiny local issuer signs RS256 tokens and
publishes its public key as a JWKS; the MCP server verifies every token offline against that key —
checking signature, issuer, **exact** audience, expiry and the `mcp:tools` scope. No Keycloak, no
browser, no OAuth discovery.

This is the smallest example that carries a real, verifiable **identity with claims**: `whoami`
shows the token's `sub`, `preferred_username`, roles and scopes, and `admin_only` succeeds only for
a token that actually carries `mcp:admin` (bob), not one that does not (alice).

## Files

| File | Role |
|---|---|
| `issuer.ts` | the local token vending machine: `GET /.well-known/jwks.json` + `POST /token` (port 4192). Owns the signing key (persisted to `.mcp-auth/02-issuer-keys.json`, `--rotate` to replace it). |
| `server.ts` | the MCP server (port 4102): `mountMcp({ auth: requireBearerAuth({ verifier }) })` with `createJwtVerifier({ issuer, audience, jwks, requiredScopes: ['mcp:tools'] })`. |
| `client.ts` | gets a token from the issuer (or `MCP_TOKEN`), then calls the server with `Authorization: Bearer <jwt>`. `--expired` shows the 401. |
| `mint.ts` | prints one token to stdout for the "break it" section — including deliberately broken ones (`--alg none`, `--alg HS256`, `--tamper`, unknown `--kid`, future `--nbf`, wrong `--aud`/`--iss`, negative `--ttl`). |
| `server.test.ts` | the negative matrix, hermetic (in-memory keys + a mutable JWKS endpoint). |

## Run it

```bash
npm run ex:02:issuer                 # terminal 1 — http://<PUBLIC_HOST>:4192  (JWKS + /token)
npm run ex:02:server                 # terminal 2 — http://<PUBLIC_HOST>:4102/mcp
npm run ex:02:client                 # terminal 3 — alice; or: -- http://192.168.78.87:4102/mcp
DEMO_USER=bob EXPECT_ADMIN=ok npm run ex:02:client     # bob can call admin_only
npm run ex:02:client -- --expired    # exits 1: the server returns 401 for an expired token
```

Ports: `PORT_02` (4102) and `PORT_02_ISSUER` (4192). Users: `DEMO_USER` (`alice`|`bob`) /
`DEMO_PASSWORD` (`password`). `MCP_TOKEN` presents a token verbatim and skips the issuer.

## What you should see

```
whoami       -> {"clientId":"alice","scopes":["mcp:tools"],...,"extra":{"sub":"alice","username":"alice","roles":["mcp-user"],"claims":{...}}}
add(2, 3)    -> 5
admin_only   -> ERROR insufficient_scope: admin_only requires scope mcp:admin
RESULT {"example":"02","tools":["add","admin_only","whoami"],"whoami":{...},"add":"5","adminOnly":"denied"}
```

bob's `RESULT` ends `"adminOnly":"ok"` (his token carries `mcp:admin`).

## Verify / break it

```bash
npm run ex:02:mint -- --sub alice --ttl -60        # expired      -> 401 "JWT rejected: token expired"
npm run ex:02:mint -- --sub alice --alg none        # unsigned     -> 401
npm run ex:02:mint -- --sub alice --alg HS256       # alg confusion-> 401
npm run ex:02:mint -- --sub alice --tamper          # bad signature-> 401
npm run ex:02:mint -- --sub alice --aud http://x/mcp # wrong aud   -> 401
npm run ex:02:mint -- --sub alice --scope email      # no mcp:tools -> 403 insufficient_scope
```

Full walkthrough (sequence diagram, curl transcripts, threat model): **`docs/02-jwt-local.md`**.
Tests: `npx vitest run examples/02-jwt-local`. Smoke: `npm run smoke -- 02`.

## Integration notes

* **No shared changes required.** `server.ts`/`client.ts`/`mint.ts` import `issuer.ts` for the shared
  constants (`PORT`, `issuerUrl()`, `audienceUrl()`, `jwksUrl()`); everything else is the frozen
  shared API (`createJwtVerifier`, `createApp`/`mountMcp`/`listen`, `createDemoServer`).
* **Deviation from design §6.2's negative matrix, per the post-design SEP-835 note.** The required
  scope lives on the **verifier** and `requireBearerAuth` is called with just `{ verifier }` (no
  `requiredScopes`, no `resourceMetadataUrl`). So the missing-scope 403 carries
  `error_description="missing scope: mcp:tools"` and **no** `scope="mcp:tools"` parameter (design
  §6.2 predicted `scope="mcp:tools"`, which would only appear if `requiredScopes` were on
  `requireBearerAuth`). The 401 for no/invalid tokens likewise carries no `resource_metadata` —
  there is no AS to discover. Tests and the smoke negative probe assert this shape.
* **Key-rotation caveat worth a future shared knob.** `createJwtVerifier` does not expose jose's
  `createRemoteJWKSet` cache options, whose default `cacheMaxAge` is 10 minutes. A running server
  therefore keeps accepting a token from a **retired** key until its JWKS cache expires (~10 min) or
  the process restarts; only an *unknown* kid triggers an immediate refetch. `server.test.ts` covers
  rotation deterministically by modelling the post-refresh state with a fresh verifier. If examples
  ever need fast rotation, a `cacheMaxAgeMs` passthrough on `createJwtVerifier` would help.
