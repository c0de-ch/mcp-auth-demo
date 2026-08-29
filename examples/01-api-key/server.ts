/**
 * 01 — API key: a static shared secret sent as `Authorization: Bearer <key>` (RFC 6750 §2.1).
 *
 * The baseline server plus ONE middleware: requireBearerAuth() with a verifier that looks the
 * presented key up in a table of SHA-256 digests (MCP_API_KEYS = "key:principal:scope scope;…").
 * There is no authorization server, so the 401 carries no resource_metadata — nothing to discover.
 *
 *   presented key ──sha256──▶ digest ──timingSafeEqual against EVERY entry──▶ { principal, scopes }
 *                                                                            └▶ AuthInfo (expiresAt synthesised)
 */
import { env, isMain, port } from '../../src/shared/env.ts';
import { createHash, timingSafeEqual } from 'node:crypto';
import { InsufficientScopeError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { SCOPE_TOOLS, createDemoServer } from '../../src/shared/tools.ts';

export const PORT = port('PORT_01', port('MCP_PORT', 4101));

/** The two DEMO keys of `.env.example` — used when MCP_API_KEYS is unset. Rotate before any real use. */
export const DEMO_API_KEYS = 'demo-api-key-alice:alice:mcp:tools;demo-api-key-bob:bob:mcp:tools mcp:admin';

export interface ApiKeyEntry {
  principal: string;
  scopes: string[];
}

/** What the server keeps: hex SHA-256 digest of the key → owner. The keys themselves are never stored. */
export type ApiKeyTable = Map<string, ApiKeyEntry>;

export const hashApiKey = (key: string): string => createHash('sha256').update(key).digest('hex');

/** Parses `key:principal:scope scope;…` (MCP_API_KEYS). Error messages never echo an entry — it contains the key. */
export function parseApiKeys(spec: string): ApiKeyTable {
  const table: ApiKeyTable = new Map();
  for (const entry of spec.split(';').map((e) => e.trim()).filter(Boolean)) {
    const match = /^([^:\s]+):([^:\s]+):(.*)$/.exec(entry); // scopes may contain ':' (mcp:tools), keys/principals may not
    if (!match) throw new Error('MCP_API_KEYS: every entry must look like key:principal:scope[ scope…]');
    const [, key, principal, scopes] = match;
    table.set(hashApiKey(key), { principal, scopes: scopes.split(/\s+/).filter(Boolean) });
  }
  if (table.size === 0) throw new Error('MCP_API_KEYS: no keys configured');
  return table;
}

/**
 * Constant-work lookup: the presented key is hashed once, then its digest is compared with EVERY
 * stored digest through crypto.timingSafeEqual — no early exit, no `===` — so the response time
 * reveals neither which entry matched nor how close a guess was. Digests are always 32 bytes, so
 * timingSafeEqual never throws on length and the length of the real keys is not observable either.
 */
export function lookupApiKey(keys: ApiKeyTable, presented: string): ApiKeyEntry | undefined {
  const digest = Buffer.from(hashApiKey(presented), 'hex');
  let found: ApiKeyEntry | undefined;
  for (const [hash, entry] of keys) {
    if (timingSafeEqual(digest, Buffer.from(hash, 'hex'))) found = entry;
  }
  return found;
}

/**
 * OAuthTokenVerifier for requireBearerAuth() — the "token" is the API key. `keys` is read on every
 * request, so removing an entry from the (mutable) table revokes that key immediately.
 * Error messages are static strings: bearerAuth.js copies them unescaped into WWW-Authenticate.
 */
export function createApiKeyVerifier(keys: ApiKeyTable): OAuthTokenVerifier {
  return {
    async verifyAccessToken(token): Promise<AuthInfo> {
      const entry = lookupApiKey(keys, token);
      if (!entry) throw new InvalidTokenError('unknown API key');
      // A key may exist but not be allowed to use this resource at all → 403, not 401.
      if (!entry.scopes.includes(SCOPE_TOOLS)) throw new InsufficientScopeError('missing scope: mcp:tools');
      return {
        token,
        clientId: entry.principal,
        scopes: entry.scopes,
        // Synthesised: the SDK insists on an expiry (seconds). Meaningless for a static key — the
        // table is consulted again on every request — but requireBearerAuth refuses AuthInfo without it.
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        extra: { sub: entry.principal, kind: 'api-key' },
      };
    },
  };
}

export interface Overrides {
  /** Key table; default = MCP_API_KEYS (or the DEMO keys). Mutable on purpose — see createApiKeyVerifier. */
  keys?: ApiKeyTable;
}

/** Builds the Express app; exported so tests can run it on an ephemeral port with their own table. */
export function buildApp({ keys = parseApiKeys(env('MCP_API_KEYS', DEMO_API_KEYS)) }: Overrides = {}) {
  const app = createApp();
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '01-api-key' }),
    // The one line that differs from 00-baseline. No resourceMetadataUrl (an API key cannot take
    // part in PRM/AS discovery) and no requiredScopes here — the scope check lives in the verifier,
    // so the 401 advertises neither a metadata URL nor a scope to request.
    auth: requireBearerAuth({ verifier: createApiKeyVerifier(keys) }),
  });
  return app;
}

if (isMain(import.meta)) {
  const keys = parseApiKeys(env('MCP_API_KEYS', DEMO_API_KEYS));
  const who = [...keys.values()].map((e) => `${e.principal} [${e.scopes.join(' ')}]`).join(', ');
  const source = process.env.MCP_API_KEYS?.trim() ? 'MCP_API_KEYS' : 'built-in DEMO table';
  console.error(`[01-api-key] ${keys.size} API key(s) from ${source}: ${who} — keys are hashed, never logged`);
  await listen(buildApp({ keys }), { port: PORT, name: '01-api-key' });
}
