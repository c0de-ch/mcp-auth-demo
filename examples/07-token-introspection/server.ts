/**
 * 07 — RFC 7662 token introspection: STATEFUL token validation.
 *
 * The resource server never parses the access token (no jose import here — a lint test enforces
 * it). Instead it asks Keycloak "is this token active?" on every request, through the realm's
 * introspection endpoint, authenticating as the confidential client `mcp-server`
 * (client_secret_basic). Keycloak consults its live session state, so a revoked token or an
 * ended session is rejected on the NEXT request — example 04 (JWKS signature validation) keeps
 * accepting the same token until `exp`. The price: one AS round trip per request, softened by a
 * small TTL cache (`INTROSPECTION_TTL_SECONDS`), which re-introduces exactly that much
 * revocation latency. `npm run ex:07:revoke -- alice` makes the contrast observable.
 */
import { env, isMain, keycloak, port, publicUrl } from '../../src/shared/env.ts';
import { createHash } from 'node:crypto';
import type { Express } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { InsufficientScopeError, InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { mountProtectedResourceMetadata } from '../../src/shared/prm.ts';
import { KC, audiences, discoverKeycloak, introspect as introspectKeycloak, type IntrospectionResponse, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { authInfoFromPayload, headerSafe, keycloakEffectiveScopes } from '../../src/shared/jwt.ts';
import { SCOPE_ADMIN, SCOPE_TOOLS, createDemoServer } from '../../src/shared/tools.ts';

export const PORT = port('PORT_07', port('MCP_PORT', 4107));

/** Positive verdicts are cached for this long (0 = ask Keycloak on every request). */
function ttlFromEnv(): number {
  const raw = env('INTROSPECTION_TTL_SECONDS', '10');
  const ttl = Number(raw);
  if (!Number.isFinite(ttl) || ttl < 0) throw new Error(`INTROSPECTION_TTL_SECONDS=${raw} is not a non-negative number`);
  return ttl;
}

export interface IntrospectionVerifierOptions {
  /** Secret of the introspecting client (`mcp-server`) — introspection requires authentication. */
  clientSecret: string;
  clientId?: string;
  /** Discovery document (for the introspection endpoint URL); fetched lazily when omitted. */
  metadata?: KeycloakMetadata;
  /** RFC 7662 call — replaced by a stub in the hermetic tests. */
  introspectFn?: typeof introspectKeycloak;
  /** How long a positive answer is trusted (= worst-case revocation latency). Default 10. */
  ttlSeconds?: number;
  /** How long `active: false` is remembered, shielding Keycloak from garbage-token floods. Default 2. */
  negativeTtlSeconds?: number;
  /** Accepted `aud` values (default MCP_AUDIENCE | ['mcp-server']). */
  audience?: string[];
  /** Scopes the caller must hold after the role policy (default ['mcp:tools']). */
  requiredScopes?: string[];
}

interface CacheEntry {
  /** The (possibly still pending) introspection answer — concurrent requests share one call. */
  response: Promise<IntrospectionResponse>;
  expiresAtMs: number;
}

/** Longer than the introspection HTTP timeout, so an in-flight entry always settles before it expires. */
const IN_FLIGHT_MS = 15_000;
const CACHE_PRUNE_THRESHOLD = 5000;

/**
 * OAuthTokenVerifier for requireBearerAuth() that validates by introspection instead of signature.
 * Cache key: sha256(token) — the raw token is never stored (nor logged; only the hash prefix is).
 * Positive entries live until min(exp, now + ttl); negative ones for negativeTtlSeconds.
 * A failed introspection call (Keycloak down, wrong MCP_SERVER_CLIENT_SECRET) is OUR outage, not
 * the client's fault: it becomes ServerError → 500 WITHOUT WWW-Authenticate, so SDK clients do
 * not start refresh/re-authorization loops — and it is never cached.
 */
export class IntrospectionVerifier implements OAuthTokenVerifier {
  private readonly cache = new Map<string, CacheEntry>();
  private readonly options: Required<Pick<IntrospectionVerifierOptions, 'clientId' | 'ttlSeconds' | 'negativeTtlSeconds' | 'audience' | 'requiredScopes'>> & IntrospectionVerifierOptions;

  constructor(options: IntrospectionVerifierOptions) {
    // Not a plain spread: an explicitly-undefined option (buildApp forwards overrides as-is)
    // must fall back to the default, which `{ ...defaults, ...options }` would not do.
    this.options = {
      ...options,
      clientId: options.clientId ?? KC.clients.server,
      ttlSeconds: options.ttlSeconds ?? ttlFromEnv(),
      negativeTtlSeconds: options.negativeTtlSeconds ?? 2,
      audience: options.audience ?? audiences(),
      requiredScopes: options.requiredScopes ?? [SCOPE_TOOLS],
    };
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const key = createHash('sha256').update(token).digest('hex');
    let response: IntrospectionResponse;
    try {
      response = await this.lookup(key, token);
    } catch (error) {
      console.error('[introspection] endpoint unavailable:', error instanceof Error ? error.message : error);
      throw new ServerError('introspection unavailable'); // 500, no WWW-Authenticate: fail closed
    }

    // RFC 7662 §2.2: anything but `active: true` means the token is dead — revoked, expired,
    // unknown, or (Keycloak) issued for an audience that does not include the introspecting client.
    if (response.active !== true) throw new InvalidTokenError('token inactive');

    // Defence in depth: Keycloak already answers active:false when `mcp-server` is missing from
    // `aud`, but another AS (or a misconfigured realm) might not — never skip the audience check.
    const aud = Array.isArray(response.aud) ? response.aud : typeof response.aud === 'string' ? [response.aud] : [];
    if (!this.options.audience.some((accepted) => aud.includes(accepted))) throw new InvalidTokenError('wrong audience');

    // The response body is a claims set (sub, username, client_id, scope, exp, realm_access, …):
    // reuse the JWT mapping, including the role policy (mcp:admin needs the mcp-admin realm role).
    const authInfo = authInfoFromPayload(response, token, keycloakEffectiveScopes);
    // `exp` is OPTIONAL in RFC 7662 (Keycloak always sends it); without it, trust the answer for
    // exactly one cache window — requireBearerAuth rejects an AuthInfo without expiresAt.
    if (typeof authInfo.expiresAt !== 'number') authInfo.expiresAt = Math.floor(Date.now() / 1000) + Math.max(this.options.ttlSeconds, 1);

    const missing = this.options.requiredScopes.filter((scope) => !authInfo.scopes.includes(scope));
    if (missing.length > 0) throw new InsufficientScopeError(headerSafe(`missing scope: ${missing.join(' ')}`));
    return authInfo;
  }

  /** Cached introspection answer for the token behind `key`; one in-flight call per token. */
  private lookup(key: string, token: string): Promise<IntrospectionResponse> {
    const now = Date.now();
    const hit = this.cache.get(key);
    if (hit && hit.expiresAtMs > now) return hit.response;

    const { clientId, clientSecret, metadata, ttlSeconds, negativeTtlSeconds } = this.options;
    const introspectFn = this.options.introspectFn ?? introspectKeycloak;
    const entry: CacheEntry = { response: undefined as never, expiresAtMs: now + IN_FLIGHT_MS };
    entry.response = introspectFn(token, { clientId, clientSecret, metadata }).then(
      (response) => {
        const nowSec = Date.now() / 1000;
        const validForSec =
          response.active === true
            ? Math.max(Math.min(ttlSeconds, typeof response.exp === 'number' ? response.exp - nowSec : Infinity), 0)
            : negativeTtlSeconds;
        entry.expiresAtMs = Date.now() + validForSec * 1000;
        if (process.env.MCP_LOG !== '0') {
          console.error(`[introspection] token ${key.slice(0, 8)} → ${response.active === true ? 'active' : 'inactive'} (cached ${validForSec.toFixed(1)}s)`);
        }
        return response;
      },
      (error: unknown) => {
        if (this.cache.get(key) === entry) this.cache.delete(key); // outages are never cached
        throw error;
      },
    );
    this.cache.set(key, entry);
    this.prune(now);
    return entry.response;
  }

  /** Bound memory when someone floods unique garbage tokens (negative entries expire after 2 s). */
  private prune(nowMs: number): void {
    if (this.cache.size <= CACHE_PRUNE_THRESHOLD) return;
    for (const [key, entry] of this.cache) {
      if (entry.expiresAtMs <= nowMs) this.cache.delete(key);
    }
  }
}

export interface Overrides {
  /** Stub for the RFC 7662 call (hermetic tests). Skips Keycloak discovery at startup. */
  introspect?: typeof introspectKeycloak;
  ttlSeconds?: number;
  negativeTtlSeconds?: number;
  metadata?: KeycloakMetadata;
  /** Authorization server advertised in the PRM (default: discovered / derived issuer). */
  issuer?: string;
  clientSecret?: string;
  audience?: string[];
}

export async function buildApp(overrides: Overrides = {}): Promise<Express> {
  // Discovery at startup (fail fast when Keycloak is down) — skipped when a stub introspect is
  // injected, so the negative-matrix tests run without any Keycloak.
  const metadata = overrides.metadata ?? (overrides.introspect ? undefined : await discoverKeycloak());
  const issuer = overrides.issuer ?? metadata?.issuer ?? keycloak().issuer;
  const resourceUrl = publicUrl(PORT);

  const app = createApp();
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [issuer],
    // SEP-835: the 401 names no scope (no requiredScopes on requireBearerAuth), so the SDK client
    // requests everything listed here — bob can obtain mcp:admin, the role policy gates alice.
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN],
    resourceName: '07-token-introspection',
  });

  const verifier = new IntrospectionVerifier({
    clientSecret: overrides.clientSecret ?? env('MCP_SERVER_CLIENT_SECRET'),
    metadata,
    introspectFn: overrides.introspect,
    ttlSeconds: overrides.ttlSeconds,
    negativeTtlSeconds: overrides.negativeTtlSeconds,
    audience: overrides.audience,
  });

  mountMcp(app, {
    createServer: () => createDemoServer({ name: '07-token-introspection' }),
    auth: requireBearerAuth({ verifier, resourceMetadataUrl }),
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(await buildApp(), { port: PORT, name: '07-token-introspection' });
}
