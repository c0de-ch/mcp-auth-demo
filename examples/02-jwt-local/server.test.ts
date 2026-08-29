import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportSPKI, SignJWT, type JSONWebKeySet } from 'jose';
import { createApp } from '../../src/shared/http.ts';
import {
  connectClient,
  initializeSession,
  mintLocalJwt,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type TestKeyPair,
  type TestServer,
} from '../../src/shared/testing.ts';
import { buildApp } from './server.ts';

// Fixed, canonical-shaped strings so the tests control iss/aud exactly (issuerUrl() has no trailing
// slash; the audience is the MCP server's exact /mcp URL — RFC 8707 style).
const ISSUER = 'http://issuer.test:4192';
const AUDIENCE = 'http://mcp.test:4102/mcp';
const b64 = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const nowSec = (): number => Math.floor(Date.now() / 1000);

let kp: TestKeyPair;
let server: TestServer;
let mcpUrl: string;

/** A well-formed token from our test key; overrides tweak individual claims. */
const mint = (over: Partial<Parameters<typeof mintLocalJwt>[0]> = {}) =>
  mintLocalJwt({ key: kp.privateKey, kid: kp.kid, issuer: ISSUER, audience: AUDIENCE, sub: 'alice', username: 'alice', scope: 'mcp:tools', ...over });

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
const challenge = (res: Parameters<typeof wwwAuthenticate>[0]) => wwwAuthenticate(res);

beforeAll(async () => {
  kp = await testKeyPair('RS256'); // kid 'test-rs256'
  server = await startTestServer(buildApp({ issuer: ISSUER, audience: AUDIENCE, jwks: kp.jwks }));
  mcpUrl = `${server.baseUrl}/mcp`;
});

afterAll(async () => {
  await server.close();
});

describe('02-jwt-local — accepted tokens', () => {
  it('accepts a valid token; alice gets mcp:tools and admin_only is denied', async () => {
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(await mint()) });
    try {
      const who = (await client.callTool({ name: 'whoami' })) as { content: { text: string }[] };
      const info = JSON.parse(who.content[0].text) as { scopes: string[]; extra: { username?: string; sub?: string } };
      expect(info.scopes).toEqual(['mcp:tools']);
      expect(info.extra.username).toBe('alice');
      expect(info.extra.sub).toBe('alice');
      const admin = (await client.callTool({ name: 'admin_only' })) as { isError?: boolean };
      expect(admin.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('lets bob (token carries mcp:admin) call admin_only', async () => {
    const token = await mint({ sub: 'bob', username: 'bob', scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(token) });
    try {
      const admin = (await client.callTool({ name: 'admin_only' })) as { isError?: boolean };
      expect(admin.isError).toBeFalsy();
    } finally {
      await close();
    }
  });
});

describe('02-jwt-local — rejected tokens (negative matrix)', () => {
  it('no credentials → 401 invalid_token, and NO resource_metadata / scope (nothing to discover)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expect(response.status).toBe(401);
    const c = challenge(response);
    expect(c.scheme?.toLowerCase()).toBe('bearer');
    expect(c.error).toBe('invalid_token');
    expect(c.resource_metadata).toBeUndefined();
    expect(c.scope).toBeUndefined();
  });

  it('expired token → 401 "token expired"', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ expiresIn: '-1m' })));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('expired');
  });

  it('not-yet-valid token (future nbf) → 401', async () => {
    const token = await new SignJWT({ scope: 'mcp:tools', preferred_username: 'alice' })
      .setProtectedHeader({ alg: 'RS256', kid: kp.kid })
      .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject('alice')
      .setIssuedAt().setNotBefore('2m').setExpirationTime('10m')
      .sign(kp.privateKey);
    const { response } = await initializeSession(mcpUrl, bearer(token));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('nbf');
  });

  it('wrong issuer → 401 "wrong issuer"', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ issuer: 'http://evil.test:4192' })));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('wrong issuer');
  });

  it('wrong audience → 401 "wrong audience"', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ audience: 'http://other.test:4102/mcp' })));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('wrong audience');
  });

  it('audience with a trailing slash → 401 (exact-match policy, no normalisation)', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ audience: `${AUDIENCE}/` })));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('wrong audience');
  });

  it('alg:none (unsigned) → 401', async () => {
    const n = nowSec();
    const token = `${b64({ alg: 'none', kid: kp.kid })}.${b64({ iss: ISSUER, aud: AUDIENCE, sub: 'alice', scope: 'mcp:tools', iat: n, exp: n + 300 })}.`;
    const { response } = await initializeSession(mcpUrl, bearer(token));
    expect(response.status).toBe(401);
    expect(challenge(response).error).toBe('invalid_token');
  });

  it('HS256 signed with the public key (algorithm confusion) → 401', async () => {
    const pem = await exportSPKI(kp.publicKey);
    const token = await new SignJWT({ scope: 'mcp:tools', preferred_username: 'alice' })
      .setProtectedHeader({ alg: 'HS256', kid: kp.kid })
      .setIssuer(ISSUER).setAudience(AUDIENCE).setSubject('alice')
      .setIssuedAt().setExpirationTime('5m')
      .sign(new TextEncoder().encode(pem));
    const { response } = await initializeSession(mcpUrl, bearer(token));
    expect(response.status).toBe(401);
    expect(challenge(response).error).toBe('invalid_token');
  });

  it('tampered payload (privilege escalation) → 401 "bad signature"', async () => {
    const [h, p, s] = (await mint()).split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<string, unknown>;
    claims.scope = 'mcp:tools mcp:admin';
    const { response } = await initializeSession(mcpUrl, bearer(`${h}.${b64(claims)}.${s}`));
    expect(response.status).toBe(401);
    expect(challenge(response).error_description).toContain('bad signature');
  });

  it('valid signature but missing mcp:tools → 403 insufficient_scope', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ scope: 'profile email' })));
    expect(response.status).toBe(403);
    const c = challenge(response);
    expect(c.error).toBe('insufficient_scope');
    expect(c.error_description).toBe('missing scope: mcp:tools'); // static message from the shared verifier
    expect(c.scope).toBeUndefined(); // requireBearerAuth carries no requiredScopes here
  });
});

// The unknown-kid and rotation rows exercise the REAL remote JWKS resolver (jose createRemoteJWKSet),
// so they use a small HTTP endpoint whose key set we mutate, rather than an in-memory JWK set.
describe('02-jwt-local — remote JWKS: unknown kid and key rotation', () => {
  let jwksServer: TestServer;
  let served: JSONWebKeySet;

  beforeAll(async () => {
    const app = createApp({ log: false });
    app.get('/.well-known/jwks.json', (_req, res) => {
      res.json(served);
    });
    jwksServer = await startTestServer(app);
  });

  afterAll(async () => {
    await jwksServer.close();
  });

  const jwksUrl = () => `${jwksServer.baseUrl}/.well-known/jwks.json`;

  it('unknown kid → 401 (JWKS is fetched, no key matches)', async () => {
    const signer = await testKeyPair('RS256', 'kid-A');
    served = signer.jwks;
    const rs = await startTestServer(buildApp({ issuer: ISSUER, audience: AUDIENCE, jwks: jwksUrl() }));
    try {
      const token = await mintLocalJwt({ key: signer.privateKey, kid: 'kid-unknown', issuer: ISSUER, audience: AUDIENCE });
      const { response } = await initializeSession(`${rs.baseUrl}/mcp`, bearer(token));
      expect(response.status).toBe(401);
      expect(challenge(response).error_description).toContain('no matching signing key');
    } finally {
      await rs.close();
    }
  });

  it('key rotation → a token from the retired key is 401 once the JWKS serves only the new key', async () => {
    const oldKey = await testKeyPair('RS256', 'kid-old');
    const newKey = await testKeyPair('RS256', 'kid-new');
    const oldToken = await mintLocalJwt({ key: oldKey.privateKey, kid: 'kid-old', issuer: ISSUER, audience: AUDIENCE });

    // Before rotation: JWKS serves the old key, so the old token verifies.
    served = oldKey.jwks;
    const before = await startTestServer(buildApp({ issuer: ISSUER, audience: AUDIENCE, jwks: jwksUrl() }));
    try {
      expect((await initializeSession(`${before.baseUrl}/mcp`, bearer(oldToken))).response.status).toBe(200);
    } finally {
      await before.close();
    }

    // After rotation the JWKS serves ONLY the new key. A server whose JWKS cache has refreshed
    // (modelled here by a fresh verifier — equivalently a restart or jose's cacheMaxAge expiring)
    // rejects the retired token and accepts tokens from the new key.
    served = newKey.jwks;
    const after = await startTestServer(buildApp({ issuer: ISSUER, audience: AUDIENCE, jwks: jwksUrl() }));
    try {
      const rejected = await initializeSession(`${after.baseUrl}/mcp`, bearer(oldToken));
      expect(rejected.response.status).toBe(401);
      expect(challenge(rejected.response).error_description).toContain('no matching signing key');

      const newToken = await mintLocalJwt({ key: newKey.privateKey, kid: 'kid-new', issuer: ISSUER, audience: AUDIENCE });
      expect((await initializeSession(`${after.baseUrl}/mcp`, bearer(newToken))).response.status).toBe(200);
    } finally {
      await after.close();
    }
  });
});
