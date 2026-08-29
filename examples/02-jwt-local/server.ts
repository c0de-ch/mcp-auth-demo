/**
 * 02 — MCP server that accepts self-issued JWTs.
 *
 * Same Streamable HTTP server as the baseline (00) plus ONE thing: a bearer verifier. The verifier
 * fetches the issuer's JWKS (issuer.ts) and, for every request, checks the token's signature,
 * `iss`, `aud` (exact canonical URL), expiry and required scope — all offline, no network call to
 * the issuer per request beyond the cached JWKS.
 *
 * SEP-835 wiring: the required scope lives on the VERIFIER (createJwtVerifier({ requiredScopes })),
 * and requireBearerAuth is called with just `{ verifier }` — no requiredScopes and, crucially, no
 * resourceMetadataUrl: there is no authorization server to discover here, so the 401 must NOT
 * advertise Protected Resource Metadata. Example 04 is exactly this server with PRM added.
 */
import { isMain, publicUrl } from '../../src/shared/env.ts';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { type Express } from 'express';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { createJwtVerifier, type JwksSource } from '../../src/shared/jwt.ts';
import { createDemoServer, SCOPE_TOOLS } from '../../src/shared/tools.ts';
import { ISSUER_PORT, PORT, audienceUrl, issuerUrl, jwksUrl } from './issuer.ts';

export { PORT };

export interface Overrides {
  /** Expected `iss` (default: the local issuer's canonical URL). */
  issuer?: string;
  /** Expected `aud` (default: this server's canonical `/mcp` URL — exact match, RFC 8707 style). */
  audience?: string | string[];
  /** Key source: a JWKS URL (default), JWK Set, JWK or CryptoKey. Tests pass an in-memory JWK Set. */
  jwks?: JwksSource;
  /** Scopes the token must carry (default `['mcp:tools']`). */
  requiredScopes?: string[];
}

/** Builds the Express app; exported so tests can run it on an ephemeral port with in-memory keys. */
export function buildApp(overrides: Overrides = {}): Express {
  const issuer = overrides.issuer ?? issuerUrl();
  const audience = overrides.audience ?? audienceUrl();
  const jwks = overrides.jwks ?? jwksUrl();

  // requiredScopes on the verifier -> a token missing mcp:tools becomes 403 insufficient_scope with
  // the static description "missing scope: mcp:tools". No effectiveScopes hook: for a self-issued
  // token the issuer is the sole authority on scope, so the token's `scope` claim is authoritative
  // (bob's token carries mcp:admin, alice's does not). Contrast example 04, which passes
  // keycloakEffectiveScopes so a role gates mcp:admin.
  const verifier = createJwtVerifier({ issuer, audience, jwks, requiredScopes: overrides.requiredScopes ?? [SCOPE_TOOLS] });

  const app = createApp();
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '02-jwt-local' }),
    auth: requireBearerAuth({ verifier }), // no resourceMetadataUrl: nothing to discover (see module doc)
  });
  return app;
}

if (isMain(import.meta)) {
  console.error(`[02-jwt-local] verifying iss=${issuerUrl()} aud=${audienceUrl()} via JWKS ${jwksUrl()} (issuer on :${ISSUER_PORT})`);
  await listen(buildApp(), { port: PORT, name: '02-jwt-local' });
}
