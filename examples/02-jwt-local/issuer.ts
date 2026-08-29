/**
 * 02 — local token issuer: a tiny RS256 "token vending machine" for the demo.
 *
 * This is NOT an OAuth authorization server. It has no discovery document, no PKCE, no consent and
 * no client registration — it just checks a demo username/password and hands back a signed JWT.
 * Its ONE job is to own a signing key and publish the matching public key as a JWKS so the MCP
 * server (server.ts) can verify tokens offline. Example 04 replaces it with Keycloak and adds the
 * OAuth machinery this deliberately omits.
 *
 *   GET  /.well-known/jwks.json   the public verification key(s)
 *   POST /token                   form username/password -> { access_token, token_type, expires_in }
 *
 * The private key is generated once into <MCP_AUTH_STORE_DIR|.mcp-auth>/02-issuer-keys.json (0600)
 * and reused on restart; `--rotate` throws it away and generates a fresh one (see the docs page's
 * "break it" section on key rotation).
 */
import { REPO_ROOT, isMain, port, publicUrl } from '../../src/shared/env.ts';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { exportJWK, generateKeyPair, importJWK, SignJWT, type JWK } from 'jose';
import express, { type Express } from 'express';
import { createApp, listen } from '../../src/shared/http.ts';
import { SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';

/** MCP server port (the token audience) and the issuer's own port. */
export const PORT = port('PORT_02', 4102);
export const ISSUER_PORT = port('PORT_02_ISSUER', 4192);

/** The `iss` claim and JWKS origin: `http://<PUBLIC_HOST>:4192` (canonical, no trailing slash). */
export const issuerUrl = (): string => publicUrl(ISSUER_PORT, '/');
/** The `aud` every token targets: the MCP server's exact canonical URL `http://<PUBLIC_HOST>:4102/mcp`. */
export const audienceUrl = (): string => publicUrl(PORT);
/** Absolute URL of the JWKS the MCP server fetches. */
export const jwksUrl = (): string => `${issuerUrl()}/.well-known/jwks.json`;

export interface IssuerKeys {
  kid: string;
  /** RS256 private key as a JWK (has `d`); never leaves this process except to sign. */
  privateJwk: JWK;
  /** RS256 public key as a JWK (kid/alg/use), the only thing published at /.well-known/jwks.json. */
  publicJwk: JWK;
}

/** Demo user table. A real issuer would look users up in a directory and check a password hash. */
interface DemoUser {
  password: string;
  scope: string;
  roles: string[];
}
function demoUsers(): Record<string, DemoUser> {
  const password = process.env.DEMO_PASSWORD?.trim() || 'password';
  return {
    // alice is a plain user; bob additionally carries mcp:admin so admin_only succeeds for him.
    alice: { password, scope: SCOPE_TOOLS, roles: ['mcp-user'] },
    bob: { password, scope: `${SCOPE_TOOLS} ${SCOPE_ADMIN}`, roles: ['mcp-user', 'mcp-admin'] },
  };
}

function storeFile(): string {
  const dir = process.env.MCP_AUTH_STORE_DIR?.trim() || join(REPO_ROOT, '.mcp-auth');
  return join(dir, '02-issuer-keys.json');
}

/** A fresh RS256 signing key pair (private exportable so it can be persisted and reloaded). */
export async function generateIssuerKeys(): Promise<IssuerKeys> {
  const kid = randomUUID();
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const publicJwk: JWK = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
  return { kid, privateJwk, publicJwk };
}

function persist(keys: IssuerKeys): void {
  const file = storeFile();
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(keys, null, 2), { mode: 0o600 });
  chmodSync(file, 0o600); // the mode above only applies when the file is first created
}

/** Loads the persisted key pair, generating (and persisting) one on first use. `rotate` forces a new pair. */
export async function loadIssuerKeys({ rotate = false }: { rotate?: boolean } = {}): Promise<IssuerKeys> {
  const file = storeFile();
  if (!rotate && existsSync(file)) return JSON.parse(readFileSync(file, 'utf8')) as IssuerKeys;
  const keys = await generateIssuerKeys();
  persist(keys);
  return keys;
}

export interface MintTokenOptions {
  sub: string;
  scope: string;
  roles?: string[];
  /** Time-to-live in seconds (default 300). Negative values (expired tokens) are allowed for the demo. */
  ttlSec?: number;
  audience?: string;
  issuer?: string;
  username?: string;
  keys?: IssuerKeys;
}

/**
 * The issuer's clean signing routine: a well-formed RS256 token with the real signing key.
 * (mint.ts has its OWN routine for the deliberately-broken tokens, so this one stays honest.)
 */
export async function mintToken(options: MintTokenOptions): Promise<string> {
  const keys = options.keys ?? (await loadIssuerKeys());
  const key = await importJWK(keys.privateJwk, 'RS256');
  const now = Math.floor(Date.now() / 1000);
  const ttl = options.ttlSec ?? 300;
  return new SignJWT({
    scope: options.scope,
    preferred_username: options.username ?? options.sub,
    realm_access: { roles: options.roles ?? ['mcp-user'] },
    typ: 'Bearer',
  })
    .setProtectedHeader({ alg: 'RS256', kid: keys.kid })
    .setIssuer(options.issuer ?? issuerUrl())
    .setAudience(options.audience ?? audienceUrl())
    .setSubject(options.sub)
    .setIssuedAt(now)
    .setExpirationTime(now + ttl)
    .sign(key);
}

/** Builds the issuer Express app (JWKS + /token). Exported so tests can run it on an ephemeral port. */
export function buildIssuerApp(keys: IssuerKeys): Express {
  const app = createApp();

  // The public half of the signing key. RFC 7517 JWK Set — jose's createRemoteJWKSet fetches this.
  app.get('/.well-known/jwks.json', (_req, res) => {
    res.json({ keys: [keys.publicJwk] });
  });

  // Demo password grant. Not OAuth: no client auth, no grant_type, no discovery — just user -> token.
  app.post('/token', express.urlencoded({ extended: false }), async (req, res) => {
    const { username, password, ttl } = (req.body ?? {}) as Record<string, string | undefined>;
    const user = username ? demoUsers()[username] : undefined;
    if (!user || user.password !== password) {
      // Deliberately vague: never reveal whether the username or the password was wrong.
      res.status(401).json({ error: 'invalid_credentials' });
      return;
    }
    // TTL from the request is honoured (including negative = already expired, for the --expired demo)
    // only in unsafe demo mode, which is the default; MCP_DEMO_UNSAFE_TTL=0 pins a safe 300 s.
    const unsafeTtl = process.env.MCP_DEMO_UNSAFE_TTL !== '0';
    const requested = ttl !== undefined ? Number.parseInt(ttl, 10) : undefined;
    const ttlSec = unsafeTtl && requested !== undefined && Number.isFinite(requested) ? requested : 300;
    const token = await mintToken({ sub: username!, username: username!, scope: user.scope, roles: user.roles, ttlSec, keys });
    res.json({ access_token: token, token_type: 'Bearer', expires_in: ttlSec });
  });

  return app;
}

if (isMain(import.meta)) {
  const rotate = process.argv.includes('--rotate');
  const keys = await loadIssuerKeys({ rotate });
  if (rotate) console.error(`[02-jwt-local issuer] rotated signing key — new kid=${keys.kid}; restart the MCP server (or wait for its JWKS cache to expire) so old tokens are refused`);
  console.error(`[02-jwt-local issuer] signing kid=${keys.kid}; JWKS at ${jwksUrl()}`);
  await listen(buildIssuerApp(keys), { port: ISSUER_PORT, name: '02-jwt-local issuer', path: '/token' });
}
