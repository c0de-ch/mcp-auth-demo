/**
 * prm.ts — RFC 9728 Protected Resource Metadata for PURE resource servers (04, 05, 07, 09, 10).
 *
 * An MCP server that only verifies tokens issued elsewhere (Keycloak) must tell clients where the
 * authorization server is. The SDK client discovers it like this:
 *   401 + `WWW-Authenticate: Bearer … resource_metadata="<url>"`  →  GET <url>  →
 *   `authorization_servers[0]`  →  AS metadata  →  (DCR) → authorize → token → retry.
 *
 * Why not the SDK's mcpAuthMetadataRouter()? It unconditionally mirrors the AS document at
 * `<rs-origin>/.well-known/oauth-authorization-server`, i.e. the resource server would claim to be
 * an authorization server (RFC 8414 says that document belongs at the ISSUER's origin). The client
 * never needs the mirror, so we serve only the PRM document — at the path-aware URL RFC 9728
 * prescribes for a resource whose URL has a path (`/.well-known/oauth-protected-resource/mcp`).
 * Examples 03 and 06 are different: there the MCP origin IS the AS and mcpAuthRouter is right.
 */
import './env.ts';
import type { Express } from 'express';
import { metadataHandler } from '@modelcontextprotocol/sdk/server/auth/handlers/metadata.js';
import { getOAuthProtectedResourceMetadataUrl } from '@modelcontextprotocol/sdk/server/auth/router.js';
import type { OAuthProtectedResourceMetadata } from '@modelcontextprotocol/sdk/shared/auth.js';

export interface PrmOptions {
  /** The canonical MCP endpoint URL — publicUrl(PORT). Must equal what clients dial. */
  resourceUrl: string;
  /** Issuer URL(s) of the authorization server(s), e.g. keycloak().issuer. */
  authorizationServers: string[];
  /** Advertised scopes; the SDK client requests exactly these when the 401 names none (SEP-835). */
  scopesSupported?: string[];
  resourceName?: string;
  /** How the token may be presented; MCP only uses the Authorization header. */
  bearerMethodsSupported?: string[];
}

/** The PRM document as JSON (RFC 9728 §2). */
export function protectedResourceMetadata({
  resourceUrl,
  authorizationServers,
  scopesSupported,
  resourceName,
  bearerMethodsSupported = ['header'],
}: PrmOptions): OAuthProtectedResourceMetadata {
  return {
    resource: resourceUrl,
    authorization_servers: authorizationServers,
    scopes_supported: scopesSupported,
    resource_name: resourceName,
    bearer_methods_supported: bearerMethodsSupported,
  };
}

/**
 * The URL a resource server advertises in `WWW-Authenticate: … resource_metadata="…"`:
 * `<origin>/.well-known/oauth-protected-resource<path>` (path-aware per RFC 9728 §3.1).
 */
export function resourceMetadataUrl(resourceUrl: string): string {
  return getOAuthProtectedResourceMetadataUrl(new URL(resourceUrl));
}

/**
 * Serves the PRM document (GET + OPTIONS, CORS `*` like the SDK) at the path-aware well-known URL
 * and returns that URL — pass it to `requireBearerAuth({ resourceMetadataUrl })`. Mount it BEFORE
 * `mountMcp()` on the same app. No `/.well-known/oauth-authorization-server` mirror is installed.
 */
export function mountProtectedResourceMetadata(app: Express, options: PrmOptions): string {
  const url = resourceMetadataUrl(options.resourceUrl);
  app.use(new URL(url).pathname, metadataHandler(protectedResourceMetadata(options)));
  return url;
}
