/**
 * 10 — on-behalf-of: this MCP server is 04's Keycloak resource server PLUS one tool,
 * `downstream_profile`, that calls a downstream API **as the user**:
 *
 *   caller token (aud=mcp-server) ──RFC 8693 token exchange (client mcp-server)──▶
 *   exchanged token (aud=downstream-api, azp=mcp-server, sub=<the user>) ──▶ GET /me
 *
 * The caller's token is never forwarded: its audience is `mcp-server`, so the downstream API
 * would (and does — see `downstream_passthrough`) refuse it. Instead the server trades it at
 * Keycloak's token endpoint (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
 * authenticated as the confidential client `mcp-server`, which has
 * `standard.token.exchange.enabled=true`) for a token scoped to exactly the one API it needs.
 * Keycloak requires `scope=downstream-api` in the request on top of `audience=downstream-api`,
 * and only accepts subject tokens that carry `mcp-server` in `aud` — the requester must itself
 * be an audience of the token it wants to trade in.
 *
 * Exchanged tokens are cached per SUBJECT TOKEN (key = sha256 of it, never the token itself)
 * until the earlier of the two expiries: a new inbound token, an expired inbound token and an
 * expired exchanged token all cause a fresh exchange.
 *
 * The verifier wiring is copied from example 04 (not imported — examples stay self-contained):
 * PRM + `createKeycloakVerifier({ requiredScopes: ['mcp:tools'] })` + `requireBearerAuth`
 * WITHOUT `requiredScopes` (SEP-835: the 401 carries only `resource_metadata`, clients follow
 * the PRM's `scopes_supported`; a missing scope is a 403 with a static description).
 */
import { env, isMain, port, publicUrl } from '../../src/shared/env.ts';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import type { Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import type { JwksSource } from '../../src/shared/jwt.ts';
import { createKeycloakVerifier, discoverKeycloak, exchangeToken, KC, KeycloakError, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { mountProtectedResourceMetadata } from '../../src/shared/prm.ts';
import { createDemoServer, SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';
import { DOWNSTREAM_PORT } from './downstream.ts';

export const PORT = port('PORT_10', port('MCP_PORT', 4110));

export interface Overrides {
  /** Full discovery document (skips the discovery request). */
  metadata?: KeycloakMetadata;
  /** Hermetic tests: expected `iss` without talking to Keycloak (pass `jwks` too). */
  issuer?: string;
  /** Hermetic tests: local key set instead of the realm's JWKS URL. */
  jwks?: JwksSource;
  /** Accepted `aud` values (default: MCP_AUDIENCE or `mcp-server`). */
  audience?: string[];
  /** Base URL of the downstream API (default `http://<PUBLIC_HOST>:4190`). */
  downstreamUrl?: string;
  /** Secret of the exchanging client `mcp-server` (default: env MCP_SERVER_CLIENT_SECRET). */
  clientSecret?: string;
  /** fetch used for the exchange POST only — tests count the calls or stub the response. */
  exchangeFetch?: typeof fetch;
  /** Register the `downstream_passthrough` anti-pattern tool (default: env DEMO_PASSTHROUGH=1). */
  passthrough?: boolean;
  /** Clock for the token cache, epoch seconds (tests advance it). */
  now?: () => number;
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

/**
 * Unverified JWT payload — used only to DISPLAY the exchanged token's claims and to read its
 * `exp` for the cache. The downstream API is the one that actually verifies it. Never applied
 * to inbound tokens (those go through the real verifier).
 */
function decodePayload(token: string): Record<string, unknown> {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
  } catch {
    return {};
  }
}

const json = (value: unknown): CallToolResult => ({ content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] });
const jsonError = (value: unknown): CallToolResult => ({ isError: true, content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] });

/**
 * GET via node:http, NOT global fetch: the WHATWG fetch spec blocklists port 4190 (ManageSieve),
 * and Node's undici enforces it — `fetch('http://…:4190/me')` throws `TypeError: fetch failed`
 * with cause `bad port`. curl and node:http have no such list, so the downstream API keeps the
 * port the repository assigns it (`PORT_10_DOWNSTREAM=4190`).
 */
function httpGetJson(url: string, headers: Record<string, string>): Promise<{ status: number; body: unknown; wwwAuthenticate?: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method: 'GET', headers, timeout: 10_000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let body: unknown;
        try {
          body = JSON.parse(text);
        } catch {
          body = undefined;
        }
        resolve({ status: res.statusCode ?? 0, body, wwwAuthenticate: res.headers['www-authenticate'] });
      });
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('downstream request timed out')));
    req.on('error', reject);
    req.end();
  });
}

export async function buildApp(overrides: Overrides = {}): Promise<Express> {
  const metadata = overrides.metadata ?? (overrides.issuer ? offlineMetadata(overrides.issuer) : await discoverKeycloak());
  const downstreamBase = (overrides.downstreamUrl ?? publicUrl(DOWNSTREAM_PORT, '')).replace(/\/+$/, '');
  const clientSecret = overrides.clientSecret ?? env('MCP_SERVER_CLIENT_SECRET');
  const exchangeFetch = overrides.exchangeFetch ?? fetch;
  const passthrough = overrides.passthrough ?? process.env.DEMO_PASSTHROUGH === '1';
  const now = overrides.now ?? (() => Math.floor(Date.now() / 1000));

  const resourceUrl = publicUrl(PORT); // canonical — must equal what clients dial AND the PRM `resource`
  const app = createApp();

  // ---- 04's resource-server wiring, verbatim (see the header comment) ----------------------
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [metadata.issuer],
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN], // SEP-835: what DCR clients will request
    resourceName: '10-token-exchange-downstream',
  });
  const verifier = await createKeycloakVerifier({
    metadata,
    requiredScopes: [SCOPE_TOOLS],
    audience: overrides.audience,
    jwks: overrides.jwks,
  });

  // ---- the on-behalf-of part ---------------------------------------------------------------

  /** Exchanged tokens per subject token; expiry = min(subject exp, exchanged exp). */
  interface CacheEntry {
    accessToken: string;
    expiresAt: number;
  }
  const cache = new Map<string, CacheEntry>();

  async function exchangedTokenFor(authInfo: AuthInfo): Promise<string> {
    const key = createHash('sha256').update(authInfo.token).digest('hex'); // never the token itself
    const hit = cache.get(key);
    if (hit && hit.expiresAt > now()) return hit.accessToken;
    cache.delete(key);
    if (cache.size >= 1000) {
      for (const [staleKey, entry] of cache) if (entry.expiresAt <= now()) cache.delete(staleKey);
    }
    const tokens = await exchangeToken({
      subjectToken: authInfo.token,
      audience: KC.clients.downstream, // 'downstream-api' — in Keycloak this is a CLIENT id, not a URI
      scope: KC.scopes.downstream, // required on top of audience=, otherwise invalid_request
      clientId: KC.clients.server,
      clientSecret,
      metadata,
      fetchFn: exchangeFetch,
    });
    const exchangedPayload = decodePayload(tokens.access_token);
    const exchangedExp = typeof exchangedPayload.exp === 'number' ? exchangedPayload.exp : now() + (tokens.expires_in ?? 60);
    const subjectExp = typeof authInfo.expiresAt === 'number' ? authInfo.expiresAt : exchangedExp;
    cache.set(key, { accessToken: tokens.access_token, expiresAt: Math.min(subjectExp, exchangedExp) });
    return tokens.access_token;
  }

  const callMe = (accessToken: string) => httpGetJson(`${downstreamBase}/me`, { authorization: `Bearer ${accessToken}`, accept: 'application/json' });

  const createServer = () => {
    const server = createDemoServer({ name: '10-token-exchange-downstream' });

    server.registerTool(
      'downstream_profile',
      {
        title: 'Downstream profile (on-behalf-of)',
        description: 'Exchanges your token (RFC 8693) for one with aud=downstream-api and calls the downstream API as you.',
      },
      async (extra) => {
        const authInfo = extra.authInfo;
        if (!authInfo) return jsonError({ error: 'unauthenticated', error_description: 'no token on this session' });
        try {
          const accessToken = await exchangedTokenFor(authInfo);
          const me = await callMe(accessToken);
          if (me.status !== 200) return jsonError({ error: 'downstream_error', status: me.status, downstream: me.body });
          const claims = decodePayload(accessToken); // display only — the downstream verified it
          return json({ via: 'token-exchange', exchanged: { aud: claims.aud, azp: claims.azp, scope: claims.scope }, downstream: me.body });
        } catch (error) {
          // Keycloak's OAuth error is the useful part; tokens are NEVER part of any tool result.
          if (error instanceof KeycloakError) return jsonError({ error: error.error, error_description: error.error_description });
          console.error('[10] downstream_profile failed:', error);
          return jsonError({ error: 'exchange_unavailable', error_description: 'token exchange or downstream call failed — see the server log' });
        }
      },
    );

    if (passthrough) {
      server.registerTool(
        'downstream_passthrough',
        {
          title: 'ANTI-PATTERN: forward the caller token downstream',
          description: 'Forwards your MCP access token (aud=mcp-server) to the downstream API unchanged — the confused-deputy anti-pattern. Expected result: the downstream rejects it (wrong audience). Enabled by DEMO_PASSTHROUGH=1.',
        },
        async (extra) => {
          const authInfo = extra.authInfo;
          if (!authInfo) return jsonError({ error: 'unauthenticated', error_description: 'no token on this session' });
          try {
            const me = await callMe(authInfo.token);
            if (me.status !== 200) return jsonError({ error: 'downstream_error', status: me.status, www_authenticate: me.wwwAuthenticate, downstream: me.body });
            return json({ via: 'passthrough', downstream: me.body }); // would mean audience isolation is broken
          } catch (error) {
            console.error('[10] downstream_passthrough failed:', error);
            return jsonError({ error: 'downstream_unreachable', error_description: 'could not reach the downstream API' });
          }
        },
      );
    }
    return server;
  };

  mountMcp(app, {
    createServer,
    // No requiredScopes here (SEP-835): the 401 carries resource_metadata but no scope=.
    auth: requireBearerAuth({ verifier, resourceMetadataUrl }),
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(await buildApp(), { port: PORT, name: '10-token-exchange-downstream' });
}
