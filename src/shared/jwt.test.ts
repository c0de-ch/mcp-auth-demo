import './env.ts'; // always first (see README: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JWK } from 'jose';
import { InsufficientScopeError, InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { authInfoFromPayload, createJwtVerifier, describeJoseError, headerSafe, isKeyRetrievalError, keycloakEffectiveScopes } from './jwt.ts';
import { createApp } from './http.ts';
import { initializeSession, startTestServer, type TestServer } from './testing.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp';
const AUDIENCE = 'mcp-server';

let privateKey: CryptoKey;
let publicJwk: JWK;
let otherPrivateKey: CryptoKey;

beforeAll(async () => {
  const pair = await generateKeyPair('RS256');
  privateKey = pair.privateKey;
  publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' };
  otherPrivateKey = (await generateKeyPair('RS256')).privateKey;
});

interface MintOptions {
  issuer?: string;
  audience?: string;
  expiresIn?: string;
  scope?: string;
  roles?: string[];
  key?: CryptoKey;
}

/** Mints a Keycloak-shaped access token with our local test key. */
async function mint({ issuer = ISSUER, audience = AUDIENCE, expiresIn = '5m', scope = 'mcp:tools', roles = ['mcp-user'], key }: MintOptions = {}) {
  return new SignJWT({ scope, azp: 'mcp-cli', preferred_username: 'alice', realm_access: { roles } })
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject('user-1')
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(key ?? privateKey);
}

const verifier = () =>
  createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [publicJwk] }, effectiveScopes: keycloakEffectiveScopes });

describe('createJwtVerifier', () => {
  it('accepts a valid token and maps it to AuthInfo', async () => {
    const info = await verifier().verifyAccessToken(await mint());
    expect(info.clientId).toBe('mcp-cli');
    expect(info.scopes).toEqual(['mcp:tools']);
    expect(typeof info.expiresAt).toBe('number');
    expect(info.expiresAt! * 1000).toBeGreaterThan(Date.now());
    expect(info.extra).toMatchObject({ sub: 'user-1', username: 'alice', roles: ['mcp-user'] });
    expect(info.resource).toBeUndefined(); // "mcp-server" is not a URL
  });

  it('rejects an expired token with InvalidTokenError', async () => {
    const token = await mint({ expiresIn: '-1m' });
    await expect(verifier().verifyAccessToken(token)).rejects.toThrow(InvalidTokenError);
    await expect(verifier().verifyAccessToken(token)).rejects.toThrow(/expired/);
  });

  it('rejects a wrong issuer', async () => {
    const token = await mint({ issuer: 'http://evil.example/realms/mcp' });
    await expect(verifier().verifyAccessToken(token)).rejects.toThrow(/wrong issuer/);
  });

  it('rejects a wrong audience', async () => {
    const token = await mint({ audience: 'some-other-api' });
    await expect(verifier().verifyAccessToken(token)).rejects.toThrow(/wrong audience/);
  });

  it('rejects a token signed by an unknown key', async () => {
    const token = await mint({ key: otherPrivateKey });
    await expect(verifier().verifyAccessToken(token)).rejects.toThrow(InvalidTokenError);
  });

  it('rejects a missing required scope with InsufficientScopeError (403)', async () => {
    const strict = createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: { keys: [publicJwk] }, requiredScopes: ['mcp:admin'] });
    await expect(strict.verifyAccessToken(await mint({ scope: 'mcp:tools' }))).rejects.toThrow(InsufficientScopeError);
  });

  it('accepts a single JWK as the key source', async () => {
    const single = createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: publicJwk });
    await expect(single.verifyAccessToken(await mint())).resolves.toMatchObject({ clientId: 'mcp-cli' });
  });

  it('never copies text from the (unverified) token into the error message', async () => {
    // jose quotes unknown `crit` header names in its message; our message must stay header-safe.
    const critName = 'x"\r\ninjected: yes';
    const token = forgeToken({ alg: 'RS256', kid: 'test-key', crit: [critName], [critName]: true });
    const failure = await verifier().verifyAccessToken(token).catch((e: Error) => e);
    expect(failure).toBeInstanceOf(InvalidTokenError);
    expect((failure as Error).message).toBe('JWT rejected: ERR_JOSE_NOT_SUPPORTED');
    expect((failure as Error).message).not.toMatch(/["\r\n]/);
  });
});

describe('unreachable JWKS', () => {
  it('is a ServerError (500 without WWW-Authenticate), not invalid_token', async () => {
    // 192.0.2.0/24 is TEST-NET: nothing answers, and Node's fetch fails fast with a TypeError.
    const unreachable = createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: 'http://127.0.0.1:9/certs' });
    await expect(unreachable.verifyAccessToken(await mint())).rejects.toThrow(ServerError);
    expect(isKeyRetrievalError(new TypeError('fetch failed'))).toBe(true);
    expect(isKeyRetrievalError(new Error('x'))).toBe(false);
  });

  it('surfaces as a 500 through requireBearerAuth so clients do not loop on re-authorization', async () => {
    const app = createApp({ log: false });
    app.post('/mcp', requireBearerAuth({ verifier: createJwtVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks: 'http://127.0.0.1:9/certs' }) }), (_req, res) => {
      res.json({ ok: true });
    });
    const server = await startTestServer(app);
    try {
      const { response } = await initializeSession(`${server.baseUrl}/mcp`, { authorization: `Bearer ${await mint()}` });
      expect(response.status).toBe(500);
      expect(response.headers['www-authenticate']).toBeUndefined();
      expect(response.json()).toEqual({ error: 'server_error', error_description: 'token verification unavailable' });
    } finally {
      await server.close();
    }
  });
});

describe('describeJoseError / headerSafe', () => {
  it('maps non-jose errors to a fixed string', () => {
    expect(describeJoseError(new Error('fetch failed: "quoted"\r\n'))).toBe('verification failed');
  });

  it('strips quotes, backslashes and control characters', () => {
    expect(headerSafe('a"b\\c\r\nd\x00e')).toBe('a b c  d e');
  });
});

/** An unsigned token with an arbitrary protected header (jose rejects it before checking the signature). */
function forgeToken(header: Record<string, unknown>): string {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  return `${b64(header)}.${b64({ iss: ISSUER, aud: AUDIENCE, exp: 4102444800 })}.AAAA`;
}

describe('requireBearerAuth + createJwtVerifier (end to end)', () => {
  let server: TestServer;
  let mcpUrl: string;

  beforeAll(async () => {
    const app = createApp({ log: false });
    app.post('/mcp', requireBearerAuth({ verifier: verifier(), requiredScopes: ['mcp:tools'] }), (_req, res) => {
      res.json({ ok: true });
    });
    server = await startTestServer(app);
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server.close();
  });

  it('answers 401 with a well-formed WWW-Authenticate for a token with a crafted header', async () => {
    const critName = 'x"\r\nSet-Cookie: pwned=1';
    const token = forgeToken({ alg: 'RS256', crit: [critName], [critName]: true });
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${token}` });
    expect(response.status).toBe(401); // a 500 here would stop SDK clients from starting OAuth discovery
    expect(response.headers['www-authenticate']).toBe('Bearer error="invalid_token", error_description="JWT rejected: ERR_JOSE_NOT_SUPPORTED", scope="mcp:tools"');
    expect(response.headers['set-cookie']).toBeUndefined();
  });

  it('answers 401 for an expired token and 200 for a valid one', async () => {
    const expired = await initializeSession(mcpUrl, { authorization: `Bearer ${await mint({ expiresIn: '-1m' })}` });
    expect(expired.response.status).toBe(401);
    expect(expired.response.headers['www-authenticate']).toContain('token expired');
    expect((await initializeSession(mcpUrl, { authorization: `Bearer ${await mint()}` })).response.status).toBe(200);
  });
});

describe('keycloakEffectiveScopes', () => {
  it('keeps mcp:admin only for users holding the mcp-admin role', async () => {
    const bob = await verifier().verifyAccessToken(await mint({ scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] }));
    expect(bob.scopes).toEqual(['mcp:tools', 'mcp:admin']);

    const alice = await verifier().verifyAccessToken(await mint({ scope: 'mcp:tools mcp:admin', roles: ['mcp-user'] }));
    expect(alice.scopes).toEqual(['mcp:tools']); // scope granted to the client, but the user lacks the role
  });
});

describe('authInfoFromPayload', () => {
  it('turns a URL audience into AuthInfo.resource', () => {
    const info = authInfoFromPayload({ aud: ['http://192.0.2.10:4104/mcp'], exp: 1, sub: 's', scope: 'a b' }, 'tok');
    expect(info.resource?.href).toBe('http://192.0.2.10:4104/mcp');
    expect(info.scopes).toEqual(['a', 'b']);
    expect(info.clientId).toBe('s');
  });
});
