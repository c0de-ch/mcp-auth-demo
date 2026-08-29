/**
 * 04 — the spec-recommended pattern: Keycloak is the AUTHORIZATION SERVER, this MCP server is a
 * pure RESOURCE SERVER. It never issues, stores or proxies tokens; it only
 *
 *   1. advertises where tokens come from — RFC 9728 Protected Resource Metadata at
 *      /.well-known/oauth-protected-resource/mcp, referenced by every 401's
 *      `WWW-Authenticate: Bearer … resource_metadata="…"` header, and
 *   2. verifies the RS256 JWTs Keycloak mints, against the realm's JWKS: signature, `iss`
 *      (pinned issuer), `aud` (logical audience `mcp-server`), `exp`, and the required
 *      `mcp:tools` scope; `mcp:admin` survives only for users holding the `mcp-admin` realm
 *      role (`keycloakEffectiveScopes` — scope = client grant, role = user right).
 *
 * SEP-835 (scope selection) is why `requireBearerAuth` gets NO `requiredScopes` here: the SDK
 * client requests the scope named in the 401 challenge if there is one, and only falls back to
 * the PRM's `scopes_supported`. A 401 pinning `scope="mcp:tools"` would make every client ask
 * for exactly that, and bob could never obtain `mcp:admin` through the browser flow. Instead the
 * VERIFIER enforces `mcp:tools` (403 `insufficient_scope`, `error_description="missing scope:
 * mcp:tools"`), the 401 carries only `resource_metadata`, and the PRM advertises both scopes.
 * See docs/04-keycloak-resource-server.md and "Scope selection" in src/shared/README.md.
 */
import { isMain, port, publicUrl } from '../../src/shared/env.ts';
import type { Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import type { JwksSource } from '../../src/shared/jwt.ts';
import { createKeycloakVerifier, discoverKeycloak, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { mountProtectedResourceMetadata } from '../../src/shared/prm.ts';
import { createDemoServer, SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';

export const PORT = port('PORT_04', port('MCP_PORT', 4104));

export interface Overrides {
  /** Full discovery document (skips the discovery request). */
  metadata?: KeycloakMetadata;
  /** Hermetic tests: expected `iss` without talking to Keycloak (pass `jwks` too). */
  issuer?: string;
  /** Hermetic tests: local key set instead of the realm's JWKS URL. */
  jwks?: JwksSource;
  /** Accepted `aud` values (default: MCP_AUDIENCE or `mcp-server`). */
  audience?: string[];
}

/** Stand-in metadata for hermetic tests — shaped like a realm, but never fetched from. */
function offlineMetadata(issuer: string): KeycloakMetadata {
  return {
    issuer,
    authorization_endpoint: `${issuer}/protocol/openid-connect/auth`,
    token_endpoint: `${issuer}/protocol/openid-connect/token`,
    jwks_uri: `${issuer}/protocol/openid-connect/certs`,
    response_types_supported: ['code'],
  };
}

export async function buildApp(overrides: Overrides = {}): Promise<Express> {
  // The real server discovers the realm once at startup; tests inject { issuer, jwks } and stay offline.
  const metadata = overrides.metadata ?? (overrides.issuer ? offlineMetadata(overrides.issuer) : await discoverKeycloak());
  const resourceUrl = publicUrl(PORT); // canonical — must equal what clients dial AND the PRM `resource`
  const app = createApp();

  // RFC 9728: the ONLY metadata a pure resource server serves. No
  // /.well-known/oauth-authorization-server mirror — that document belongs to the issuer's origin.
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [metadata.issuer],
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN], // SEP-835: this is what DCR clients will request
    resourceName: '04-keycloak-resource-server',
  });

  // issuer + JWKS from discovery, audience `mcp-server`, required scope enforced HERE (403),
  // effective scopes = token scopes minus mcp:admin unless the user has the mcp-admin realm role.
  const verifier = await createKeycloakVerifier({
    metadata,
    requiredScopes: [SCOPE_TOOLS],
    audience: overrides.audience,
    jwks: overrides.jwks,
  });

  mountMcp(app, {
    createServer: () => createDemoServer({ name: '04-keycloak-resource-server' }),
    // Deliberately NO requiredScopes here (SEP-835, see the header comment): the 401/403 carry
    // resource_metadata but no scope=, so clients follow the PRM's scopes_supported.
    auth: requireBearerAuth({ verifier, resourceMetadataUrl }),
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(await buildApp(), { port: PORT, name: '04-keycloak-resource-server' });
}
