/**
 * 05 — machine-to-machine: the SAME pure resource server as example 04 (diff this file against
 * examples/04-keycloak-resource-server/server.ts — the auth wiring is byte-for-byte the pattern:
 * RFC 9728 PRM + Keycloak JWT verifier, no requiredScopes on requireBearerAuth per SEP-835).
 * What changes is WHO calls it: not a human with a browser, but a workload that obtained its
 * token with the OAuth 2.1 `client_credentials` grant (Keycloak service account, no user, no
 * redirect, no consent). A resource server cannot tell — and should not care — which grant minted
 * a token; it verifies the same signature, issuer, audience, expiry and scopes either way.
 *
 * The ONE addition is the `service_only` tool: authorization on the CLIENT IDENTITY
 * (`authInfo.clientId`, i.e. the token's `azp`) against an allow-list, MCP_ALLOWED_CLIENTS
 * (default `mcp-service,mcp-service-jwt`). That is a third, separate axis:
 *
 *   scope  = what the CLIENT was granted        (admin_only needs scope mcp:admin)
 *   role   = what the USER may do               (mcp:admin survives only with realm role mcp-admin)
 *   client = WHICH WORKLOAD is calling          (service_only: allow-listed client ids only)
 *
 * A user token (azp `mcp-cli` / `mcp-test`) with perfect scopes still cannot call service_only,
 * and the service account cannot call admin_only — the axes do not substitute for each other.
 * See docs/05-keycloak-client-credentials.md.
 */
import { isMain, port, publicUrl } from '../../src/shared/env.ts';
import type { Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import type { JwksSource } from '../../src/shared/jwt.ts';
import { KC, createKeycloakVerifier, discoverKeycloak, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { mountProtectedResourceMetadata } from '../../src/shared/prm.ts';
import { createDemoServer, SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';

export const PORT = port('PORT_05', port('MCP_PORT', 4105));
const NAME = '05-keycloak-client-credentials';

/** Client ids allowed to call `service_only`: MCP_ALLOWED_CLIENTS (comma list) or the realm's two service accounts. */
export function allowedClients(): string[] {
  const fromEnv = (process.env.MCP_ALLOWED_CLIENTS ?? '').split(',').map((c) => c.trim()).filter(Boolean);
  return fromEnv.length > 0 ? fromEnv : [KC.clients.service, KC.clients.serviceJwt];
}

export interface Overrides {
  /** Full discovery document (skips the discovery request). */
  metadata?: KeycloakMetadata;
  /** Hermetic tests: expected `iss` without talking to Keycloak (pass `jwks` too). */
  issuer?: string;
  /** Hermetic tests: local key set instead of the realm's JWKS URL. */
  jwks?: JwksSource;
  /** Accepted `aud` values (default: MCP_AUDIENCE or `mcp-server`). */
  audience?: string[];
  /** Canonical MCP URL (default publicUrl(PORT)); tests pass their ephemeral 127.0.0.1 URL so SDK clients pass the RFC 8707 resource check. */
  resourceUrl?: string;
  /** `service_only` allow-list override (default allowedClients()). */
  allowedClients?: string[];
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
  // Identical resource-server wiring as example 04: discovery once at startup, PRM, JWT verifier.
  const metadata = overrides.metadata ?? (overrides.issuer ? offlineMetadata(overrides.issuer) : await discoverKeycloak());
  const resourceUrl = overrides.resourceUrl ?? publicUrl(PORT);
  const allowed = overrides.allowedClients ?? allowedClients();
  const app = createApp();

  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [metadata.issuer],
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN], // SEP-835: drives what discovering clients request
    resourceName: NAME,
  });

  // Same verifier as 04: issuer + JWKS from discovery, audience `mcp-server`, required scope
  // enforced here (403 insufficient_scope), keycloakEffectiveScopes role policy.
  const verifier = await createKeycloakVerifier({
    metadata,
    requiredScopes: [SCOPE_TOOLS],
    audience: overrides.audience,
    jwks: overrides.jwks,
  });

  mountMcp(app, {
    createServer: () => {
      const server = createDemoServer({ name: NAME });
      // The 05-specific tool: client-identity authorization. `clientId` is the verified token's
      // `azp` claim — set by Keycloak, not by the caller — so an allow-list on it is trustworthy.
      server.registerTool(
        'service_only',
        { title: 'Service only', description: `Succeeds only for the allow-listed service clients (${allowed.join(', ')}) — client identity, not scope or role.` },
        async (extra): Promise<CallToolResult> => {
          const clientId = extra.authInfo?.clientId;
          return clientId !== undefined && allowed.includes(clientId)
            ? { content: [{ type: 'text', text: `service ok: client ${clientId} is allow-listed` }] }
            : { isError: true, content: [{ type: 'text', text: `forbidden_client: service_only requires one of: ${allowed.join(', ')}` }] };
        },
      );
      return server;
    },
    // As in 04: NO requiredScopes here — the 401 carries resource_metadata but no scope=.
    auth: requireBearerAuth({ verifier, resourceMetadataUrl }),
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(await buildApp(), { port: PORT, name: NAME });
}
