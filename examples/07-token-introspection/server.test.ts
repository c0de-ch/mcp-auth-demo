import { publicUrl } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  connectClient,
  expectOAuth401,
  initializeSession,
  isKeycloakUp,
  keycloakPasswordToken,
  rawCallTool,
  rawRequest,
  startTestServer,
  wwwAuthenticate,
  type TestServer,
} from '../../src/shared/testing.ts';
import { runDemo } from '../../src/shared/client/run.ts';
import { resourceMetadataUrl } from '../../src/shared/prm.ts';
import { KC, adminLogoutUser, createKeycloakVerifier, revokeToken, type IntrospectionResponse } from '../../src/shared/keycloak.ts';
import { buildApp, PORT } from './server.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp'; // TEST-NET: never dialled by the hermetic tests
const PRM_URL = resourceMetadataUrl(publicUrl(PORT));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** A Keycloak-shaped RFC 7662 answer (field names verified against the live realm). */
const activeResponse = (over: Partial<IntrospectionResponse> = {}): IntrospectionResponse => ({
  active: true,
  iss: ISSUER,
  aud: 'mcp-server',
  sub: 'user-alice',
  azp: 'mcp-cli',
  client_id: 'mcp-cli',
  username: 'alice',
  preferred_username: 'alice',
  scope: 'profile email mcp:tools',
  realm_access: { roles: ['mcp-user'] },
  exp: Math.floor(Date.now() / 1000) + 900,
  token_type: 'Bearer',
  ...over,
});

/** Introspection stub: answers per token, counts invocations; unknown tokens are inactive. */
function stubIntrospect(responses: Record<string, IntrospectionResponse | (() => IntrospectionResponse)> = {}) {
  const calls: string[] = [];
  const count = (token: string) => calls.filter((t) => t === token).length;
  const fn = async (token: string): Promise<IntrospectionResponse> => {
    calls.push(token);
    if (token === 'boom') throw new Error('kaboom: introspection endpoint unreachable');
    const answer = responses[token];
    if (!answer) return { active: false };
    return typeof answer === 'function' ? answer() : answer;
  };
  return { fn, calls, count };
}

// ---------------------------------------------------------------- hermetic negative matrix (§6.7)

describe('07-token-introspection (hermetic, stubbed introspection)', () => {
  const stub = stubIntrospect({
    'alice-token': activeResponse({ scope: 'profile email mcp:tools mcp:admin' }), // client granted admin, user lacks the role
    'bob-token': activeResponse({ sub: 'user-bob', username: 'bob', preferred_username: 'bob', scope: 'mcp:tools mcp:admin', realm_access: { roles: ['mcp-user', 'mcp-admin'] } }),
    'aud-mismatch': activeResponse({ aud: ['account'] }),
    'scope-email': activeResponse({ scope: 'profile email' }),
    cached: activeResponse(),
  });
  let server: TestServer;
  let mcpUrl: string;

  beforeAll(async () => {
    server = await startTestServer(await buildApp({ introspect: stub.fn, ttlSeconds: 10, issuer: ISSUER, clientSecret: 'stub-secret' }));
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server.close();
  });

  it('server.ts never parses the token: no jose import, no JWT decoding', () => {
    const source = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8');
    expect(source).not.toMatch(/from\s+['"]jose['"]/);
    expect(source).not.toMatch(/\bjwtVerify\b|\bdecodeJwt\b|\bdecodeProtectedHeader\b|\bcreateRemoteJWKSet\b/);
  });

  it('401 without a token: resource_metadata, error=invalid_token, and NO scope parameter (SEP-835)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).scope).toBeUndefined(); // the client takes scopes from the PRM instead
  });

  it('serves the PRM at the path-aware well-known URL and NO authorization-server mirror', async () => {
    const prm = await rawRequest(`${server.baseUrl}${new URL(PRM_URL).pathname}`);
    expect(prm.status).toBe(200);
    expect(prm.json()).toEqual({
      resource: publicUrl(PORT),
      authorization_servers: [ISSUER],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: '07-token-introspection',
      bearer_methods_supported: ['header'],
    });
    expect((await rawRequest(`${server.baseUrl}/.well-known/oauth-authorization-server`)).status).toBe(404);
  });

  it('active:false → 401 "token inactive", negative-cached: two bad calls within 2 s → one introspection', async () => {
    const first = await initializeSession(mcpUrl, bearer('dead-token'));
    expectOAuth401(first.response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(first.response).error_description).toBe('token inactive');
    const second = await initializeSession(mcpUrl, bearer('dead-token'));
    expect(second.response.status).toBe(401);
    expect(stub.count('dead-token')).toBe(1);
  });

  it('active but aud lacks mcp-server → 401 "wrong audience" (defence in depth)', async () => {
    const { response } = await initializeSession(mcpUrl, bearer('aud-mismatch'));
    expect(response.status).toBe(401);
    expect(wwwAuthenticate(response).error_description).toBe('wrong audience');
  });

  it('active with scope "profile email" only → 403 insufficient_scope "missing scope: mcp:tools"', async () => {
    const { response } = await initializeSession(mcpUrl, bearer('scope-email'));
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: mcp:tools');
    expect(challenge.scope).toBeUndefined();
  });

  it('introspection outage → 500 server_error, NO WWW-Authenticate, and never cached', async () => {
    const first = await initializeSession(mcpUrl, bearer('boom'));
    expect(first.response.status).toBe(500);
    expect(first.response.headers['www-authenticate']).toBeUndefined();
    expect(first.response.json()).toEqual({ error: 'server_error', error_description: 'introspection unavailable' });
    const second = await initializeSession(mcpUrl, bearer('boom'));
    expect(second.response.status).toBe(500);
    expect(stub.count('boom')).toBe(2); // an outage must not poison the cache
  });

  it('two requests within the TTL → one introspection call', async () => {
    expect((await initializeSession(mcpUrl, bearer('cached'))).response.status).toBe(200);
    expect((await initializeSession(mcpUrl, bearer('cached'))).response.status).toBe(200);
    expect(stub.count('cached')).toBe(1);
  });

  it('maps the introspection response like a JWT: whoami, effective scopes, admin via realm role', async () => {
    const alice = await connectClient(mcpUrl, { headers: bearer('alice-token') });
    try {
      const result = await runDemo(alice.client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: 'mcp-cli', extra: { sub: 'user-alice', username: 'alice', roles: ['mcp-user'] } });
      expect((result.whoami.json as { scopes: string[] }).scopes).toContain('mcp:tools');
      expect((result.whoami.json as { scopes: string[] }).scopes).not.toContain('mcp:admin'); // granted scope, missing role
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await alice.close();
    }

    const bob = await connectClient(mcpUrl, { headers: bearer('bob-token') });
    try {
      expect((await runDemo(bob.client, { print: () => undefined })).adminOnly.isError).toBe(false); // role mcp-admin
    } finally {
      await bob.close();
    }
  });

  it("refuses bob's token on alice's session (session ↔ subject binding)", async () => {
    const { sessionId } = await initializeSession(mcpUrl, bearer('alice-token'));
    expect(sessionId).toBeDefined();
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer('alice-token'))).response.status).toBe(200);
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer('bob-token'))).response.status).toBe(403);
  });

  it('TTL 0 → every request introspects; an active answer without exp is trusted for one window', async () => {
    const ttl0 = stubIntrospect({ fresh: activeResponse(), 'no-exp': activeResponse({ exp: undefined }) });
    const app = await startTestServer(await buildApp({ introspect: ttl0.fn, ttlSeconds: 0, issuer: ISSUER, clientSecret: 'stub-secret' }));
    try {
      const url = `${app.baseUrl}/mcp`;
      expect((await initializeSession(url, bearer('fresh'))).response.status).toBe(200);
      expect((await initializeSession(url, bearer('fresh'))).response.status).toBe(200);
      expect(ttl0.count('fresh')).toBe(2);
      expect((await initializeSession(url, bearer('no-exp'))).response.status).toBe(200); // RFC 7662: exp is OPTIONAL
    } finally {
      await app.close();
    }
  });

  it('a positive cache entry never outlives the token exp, even with a large TTL', async () => {
    const short = stubIntrospect({ 'short-lived': () => activeResponse({ exp: Math.floor(Date.now() / 1000) + 1 }) });
    const app = await startTestServer(await buildApp({ introspect: short.fn, ttlSeconds: 60, issuer: ISSUER, clientSecret: 'stub-secret' }));
    try {
      const url = `${app.baseUrl}/mcp`;
      expect((await initializeSession(url, bearer('short-lived'))).response.status).toBe(200);
      await sleep(1200); // past exp → the cached verdict must be gone
      expect((await initializeSession(url, bearer('short-lived'))).response.status).toBe(200);
      expect(short.count('short-lived')).toBe(2);
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------- against the real Keycloak

const keycloakUp = await isKeycloakUp();

describe.skipIf(!keycloakUp)('07-token-introspection against Keycloak', () => {
  let server: TestServer;
  let mcpUrl: string;

  beforeAll(async () => {
    // TTL 0: revocation must be visible on the very next request in these tests.
    server = await startTestServer(await buildApp({ ttlSeconds: 0 }));
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server.close();
  });

  it('accepts an mcp-test token for alice; admin stays denied without the role', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools mcp:admin' });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: KC.clients.test, extra: { username: 'alice', roles: ['mcp-user'] } });
      expect((result.whoami.json as { scopes: string[] }).scopes).not.toContain('mcp:admin');
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }

    const bob = await keycloakPasswordToken({ username: 'bob', password: 'password', scope: 'mcp:tools mcp:admin' });
    const bobClient = await connectClient(mcpUrl, { headers: bearer(bob.access_token) });
    try {
      expect((await runDemo(bobClient.client, { print: () => undefined })).adminOnly.isError).toBe(false);
    } finally {
      await bobClient.close();
    }
  });

  it('adminLogoutUser(alice): the next request is 401 while a JWKS verifier still accepts the token', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    expect((await initializeSession(mcpUrl, bearer(tokens.access_token))).response.status).toBe(200);

    await adminLogoutUser('alice');

    const after = await initializeSession(mcpUrl, bearer(tokens.access_token));
    expectOAuth401(after.response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(after.response).error_description).toBe('token inactive');

    // The revocation-visibility contrast (example 04's validation): same token, still fine there.
    const jwksVerifier = await createKeycloakVerifier();
    await expect(jwksVerifier.verifyAccessToken(tokens.access_token)).resolves.toMatchObject({ clientId: KC.clients.test });
  });

  it('RFC 7009 revocation of the access token → 401 on the next request', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    expect((await initializeSession(mcpUrl, bearer(tokens.access_token))).response.status).toBe(200);
    await revokeToken(tokens.access_token, { clientId: KC.clients.test, tokenTypeHint: 'access_token' });
    const after = await initializeSession(mcpUrl, bearer(tokens.access_token));
    expect(after.response.status).toBe(401);
    expect(wwwAuthenticate(after.response).error_description).toBe('token inactive');
  });

  it('wrong MCP_SERVER_CLIENT_SECRET → 500 server_error (our outage), never a 401', async () => {
    const broken = await startTestServer(await buildApp({ clientSecret: 'wrong-secret', ttlSeconds: 0 }));
    try {
      const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password' });
      const { response } = await initializeSession(`${broken.baseUrl}/mcp`, bearer(tokens.access_token));
      expect(response.status).toBe(500);
      expect(response.headers['www-authenticate']).toBeUndefined();
      expect(response.json()).toEqual({ error: 'server_error', error_description: 'introspection unavailable' });
    } finally {
      await broken.close();
    }
  });

  it('the cache TTL is the worst-case revocation latency', async () => {
    const cached = await startTestServer(await buildApp({ ttlSeconds: 3 }));
    try {
      const url = `${cached.baseUrl}/mcp`;
      const tokens = await keycloakPasswordToken({ username: 'bob', password: 'password' });
      expect((await initializeSession(url, bearer(tokens.access_token))).response.status).toBe(200); // verdict cached
      await adminLogoutUser('bob');
      expect((await initializeSession(url, bearer(tokens.access_token))).response.status).toBe(200); // revoked, but still cached
      await sleep(3200);
      expect((await initializeSession(url, bearer(tokens.access_token))).response.status).toBe(401); // cache expired → visible
    } finally {
      await cached.close();
    }
  });
});
