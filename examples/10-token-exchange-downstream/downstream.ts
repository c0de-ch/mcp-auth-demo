/**
 * 10 — the downstream API (port 4190): a PLAIN HTTP resource, no MCP. It represents "some other
 * service the MCP server calls on the user's behalf" — a profile store, an internal REST API, …
 *
 * It accepts ONLY tokens whose audience is `downstream-api` and whose scope contains
 * `downstream-api` — i.e. the tokens the MCP server obtains via RFC 8693 token exchange, never
 * the caller's original MCP token (`aud=mcp-server`). This audience isolation is the entire
 * point of the example: a token stolen from (or passed through by) one service is worthless at
 * the next one.
 */
import { isMain, port } from '../../src/shared/env.ts';
import type { Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { createApp, listen } from '../../src/shared/http.ts';
import { createJwtVerifier, type JwksSource } from '../../src/shared/jwt.ts';
import { discoverKeycloak, KC } from '../../src/shared/keycloak.ts';

export const DOWNSTREAM_PORT = port('PORT_10_DOWNSTREAM', 4190);

export interface DownstreamOverrides {
  /** Hermetic tests: expected `iss` without talking to Keycloak (pass `jwks` too). */
  issuer?: string;
  /** Hermetic tests: local key set instead of the realm's JWKS URL. */
  jwks?: JwksSource;
}

/**
 * GET /me — "who is calling me, and with what rights?" — guarded by a JWT verifier pinned to
 * audience `downstream-api`. Deliberately NOT `keycloakEffectiveScopes`: this API has its own
 * authorization model (the single `downstream-api` scope); the mcp:admin role policy belongs to
 * the MCP server. No Protected Resource Metadata either — this API is not an MCP server and its
 * only caller (`mcp-server`) obtains tokens via exchange, not via discovery.
 */
export async function buildDownstreamApp(overrides: DownstreamOverrides = {}): Promise<Express> {
  let { issuer, jwks } = overrides;
  if (issuer === undefined || jwks === undefined) {
    const metadata = await discoverKeycloak();
    issuer ??= metadata.issuer;
    jwks ??= metadata.jwks_uri;
  }
  const verifier = createJwtVerifier({
    issuer,
    audience: [KC.clients.downstream], // 'downstream-api' — an MCP token (aud=mcp-server) is rejected here
    jwks,
    requiredScopes: [KC.scopes.downstream],
  });

  const app = createApp();
  app.get('/me', requireBearerAuth({ verifier }), (req, res) => {
    const auth = req.auth!; // set by requireBearerAuth
    const claims = (auth.extra?.claims ?? {}) as Record<string, unknown>;
    res.json({
      sub: claims.sub, // the USER the exchanged token still acts for
      azp: claims.azp, // the client that obtained it: 'mcp-server', not the user's MCP client
      aud: claims.aud,
      scope: claims.scope,
      roles: auth.extra?.roles ?? [],
    });
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(await buildDownstreamApp(), { port: DOWNSTREAM_PORT, name: '10-downstream-api', path: '/me' });
}
