/**
 * 03 — the MCP server IS the OAuth 2.1 authorization server ("embedded AS", one process).
 *
 * The SDK's mcpAuthRouter mounts, at the origin root:
 *   /.well-known/oauth-authorization-server   RFC 8414 metadata (issuer = this origin)
 *   /.well-known/oauth-protected-resource/mcp RFC 9728 PRM (resource = <origin>/mcp)
 *   GET|POST /authorize   validates client_id + redirect_uri, then calls provider.authorize()
 *   POST /token           PKCE S256 verified by the SDK; authorization_code + refresh_token only
 *   POST /register        RFC 7591 Dynamic Client Registration (open — demo!)
 *   POST /revoke          RFC 7009 revocation
 * plus our own /login and /consent pages (pages.ts) and the guarded /mcp endpoint.
 *
 * requireBearerAuth carries NO requiredScopes on purpose: SEP-835 clients take the scope to
 * request from the 401's scope= first — pinning "mcp:tools" there would stop bob from ever being
 * granted mcp:admin. Instead the PRM advertises scopes_supported and the provider's
 * verifyAccessToken enforces mcp:tools itself (403 insufficient_scope without it).
 */
import { isMain, port, publicUrl } from '../../src/shared/env.ts';
import type { Express } from 'express';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { createDemoServer } from '../../src/shared/tools.ts';
import { DemoAuthorizationServer, SCOPES_SUPPORTED } from './provider.ts';
import { authPagesRouter } from './pages.ts';

export const PORT = port('PORT_03', port('MCP_PORT', 4103));

export interface Overrides {
  /** Origin (no trailing slash) used for issuer/resource/PRM — tests pass http://127.0.0.1:<port>. */
  origin?: string;
  /** A pre-built provider (tests keep a handle; must be built with resource = `<origin>/mcp`). */
  provider?: DemoAuthorizationServer;
  /** Force the SDK auth router's rate limits on/off (default: on unless MCP_RATE_LIMIT=0). */
  rateLimit?: boolean;
}

export function buildApp(overrides: Overrides = {}): Express {
  const origin = overrides.origin ?? publicUrl(PORT, '');
  const resourceUrl = `${origin}/mcp`;
  const provider = overrides.provider ?? new DemoAuthorizationServer({ resource: resourceUrl });
  const rl = (overrides.rateLimit ?? process.env.MCP_RATE_LIMIT !== '0') ? undefined : false;

  const app = createApp();
  app.use(authPagesRouter(provider)); // /login + /consent — the human-facing half of /authorize
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL(`${origin}/`), // http:// LAN issuer needs MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL (env.ts)
      resourceServerUrl: new URL(resourceUrl),
      scopesSupported: [...SCOPES_SUPPORTED],
      resourceName: '03-oauth-embedded-as',
      clientRegistrationOptions: { clientSecretExpirySeconds: 0, rateLimit: rl }, // DCR secrets never expire (demo)
      authorizationOptions: { rateLimit: rl },
      tokenOptions: { rateLimit: rl },
      revocationOptions: { rateLimit: rl },
    }),
  );
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '03-oauth-embedded-as' }),
    auth: requireBearerAuth({
      verifier: provider, // the same object is AS and RS verifier — one process, one token store
      resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(resourceUrl)),
    }),
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(buildApp(), { port: PORT, name: '03-oauth-embedded-as' });
  console.log(`[03-oauth-embedded-as] authorization server at ${publicUrl(PORT, '/')}: /authorize /token /register /revoke`);
  console.log('[03-oauth-embedded-as] demo users (DEMO): alice / password (mcp:tools) · bob / password (mcp:tools + mcp:admin)');
  console.log('[03-oauth-embedded-as] in-memory state: a restart forgets clients/tokens — run the client with --logout after a restart.');
}
