/**
 * env.ts — the single place every URL, port and host name comes from.
 *
 * IMPORT-ORDER RULE (structural, not optional):
 *   `import '../../src/shared/env.ts'` (or a named import from it) MUST be the FIRST
 *   import of every entrypoint, and every shared module that touches the SDK imports it
 *   first as well. Reasons:
 *   1. `.env` (always the repo-root one) must be loaded before anything reads process.env.
 *   2. `@modelcontextprotocol/sdk/server/auth/router.js` reads
 *      MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL exactly ONCE, at module-evaluation time.
 *      Our issuer URLs are plain http://192.168.x.x (LAN testing), which the SDK refuses
 *      unless that flag is set. ES modules evaluate depth-first in import order, so putting
 *      this module first guarantees the flag exists before router.js is evaluated.
 */
import { config as loadDotenv } from 'dotenv';
import { networkInterfaces } from 'node:os';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Absolute path of the repository root (this file lives in <root>/src/shared). */
export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

// Always the repo-root .env, whatever the current working directory is (`dotenv/config` would
// look in process.cwd()). Existing process.env values win, as with dotenv's defaults.
loadDotenv({ path: resolve(REPO_ROOT, '.env'), quiet: true });

// Demo only: allows http:// issuers on LAN addresses. Never do this in production.
process.env.MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL ??= '1';

/** Read an env variable; throw a helpful error when it is missing and no fallback is given. */
export function env(name: string, fallback?: string): string {
  const value = process.env[name]?.trim();
  if (value) return value;
  if (fallback !== undefined) return fallback;
  throw new Error(`Missing required environment variable ${name} (see .env.example)`);
}

/** Read a numeric port from the environment. */
export function port(envName: string, fallback: number): number {
  const raw = process.env[envName]?.trim();
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`${envName}=${raw} is not a valid port`);
  return n;
}

/** First non-internal IPv4 address of this machine (what other LAN machines can reach). */
export function detectLanAddress(): string | undefined {
  for (const addrs of Object.values(networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.family === 'IPv4' && !a.internal) return a.address;
    }
  }
  return undefined;
}

/** Where PUBLIC_HOST came from — shown in the startup banner so surprises are visible. */
export function publicHostSource(): 'env' | 'auto-detected' | 'fallback' {
  if (process.env.PUBLIC_HOST?.trim()) return 'env';
  return detectLanAddress() ? 'auto-detected' : 'fallback';
}

/**
 * Host name or IP that OTHER machines use to reach this box. Never "localhost": the
 * browser/client in this demo usually runs on a different machine than the servers.
 */
export function publicHost(): string {
  return process.env.PUBLIC_HOST?.trim() || detectLanAddress() || '127.0.0.1';
}

/**
 * The ONE canonical public URL of a server: `http://<PUBLIC_HOST>:<port><path>`, no trailing
 * slash. Everything that ends up in metadata or tokens (PRM `resource`, issuer, `aud`,
 * redirect URIs) must be built from this so that all copies compare equal.
 * `scheme` is `https` only for the mTLS example (08).
 */
export function publicUrl(portNumber: number, path = '/mcp', scheme: 'http' | 'https' = 'http'): string {
  const cleanPath = path.replace(/\/+$/, '');
  return `${scheme}://${publicHost()}:${portNumber}${cleanPath}`;
}

export interface KeycloakEndpoints {
  baseUrl: string;
  realm: string;
  issuer: string;
  discoveryUrl: string;
  jwksUri: string;
  tokenEndpoint: string;
  authorizationEndpoint: string;
  introspectionEndpoint: string;
  registrationEndpoint: string;
}

/**
 * Keycloak endpoints derived from KEYCLOAK_URL (default http://<publicHost>:<KEYCLOAK_PORT|8180>)
 * and KEYCLOAK_REALM (default "mcp"). The issuer must be byte-identical to what Keycloak puts
 * into `iss` — `keycloak/docker-compose.yml` pins KC_HOSTNAME to exactly this value.
 */
export function keycloak(): KeycloakEndpoints {
  const baseUrl = env('KEYCLOAK_URL', `http://${publicHost()}:${port('KEYCLOAK_PORT', 8180)}`).replace(/\/+$/, '');
  const realm = env('KEYCLOAK_REALM', 'mcp');
  const issuer = `${baseUrl}/realms/${realm}`;
  const oidc = `${issuer}/protocol/openid-connect`;
  return {
    baseUrl,
    realm,
    issuer,
    discoveryUrl: `${issuer}/.well-known/openid-configuration`,
    jwksUri: `${oidc}/certs`,
    tokenEndpoint: `${oidc}/token`,
    authorizationEndpoint: `${oidc}/auth`,
    introspectionEndpoint: `${oidc}/token/introspect`,
    registrationEndpoint: `${issuer}/clients-registrations/openid-connect`,
  };
}

/**
 * True when `meta` belongs to the script that was started directly (`tsx file.ts`), false when
 * the file was merely imported (tests import `server.ts` to build the app without listening).
 */
export function isMain(meta: ImportMeta): boolean {
  if (typeof meta.main === 'boolean') return meta.main;
  return process.argv[1] !== undefined && process.argv[1] === fileURLToPath(meta.url);
}
