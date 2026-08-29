import { keycloak, publicUrl } from '../../src/shared/env.ts'; // always first (import-order rule)
import { spawnSync } from 'node:child_process';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import express from 'express';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  connectClient,
  expectOAuth401,
  freePort,
  initializeSession,
  isKeycloakUp,
  keycloakPasswordToken,
  mintLocalJwt,
  rawCallTool,
  rawRequest,
  spawnExample,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type SpawnedExample,
  type TestServer,
} from '../../src/shared/testing.ts';
import { runDemo } from '../../src/shared/client/run.ts';

/**
 * 11 — the Python (mcp 2.1.1) resource server, spawned as a real `uv run … server.py` process.
 *
 * Suite 1 is hermetic: KEYCLOAK_URL points at a local stub that serves only the realm JWKS path,
 * so locally minted RS256 tokens are "Keycloak" tokens — that is how the wrong-issuer /
 * wrong-audience / expired / scope rows run without Docker. Suite 2 uses the real Keycloak
 * (password grant on `mcp-test`) and the real TS SDK client — the interop proof.
 */

const SERVER_SCRIPT = 'examples/11-python-mcp-keycloak/server.py';
const uvAvailable = spawnSync('uv', ['--version'], { stdio: 'ignore' }).status === 0;
if (!uvAvailable) process.stderr.write('\nskipped: uv is not installed — example 11 needs it (https://docs.astral.sh/uv/)\n');
const keycloakUp = uvAvailable && (await isKeycloakUp());

const HERMETIC_ISSUER_PATH = '/realms/mcp'; // the stub mirrors Keycloak's realm layout
const prmShape = (resource: string, issuer: string) => ({
  resource,
  authorization_servers: [issuer],
  scopes_supported: ['mcp:tools', 'mcp:admin'],
  bearer_methods_supported: ['header'],
  resource_name: '11-python-mcp-keycloak',
});

describe.skipIf(!uvAvailable)('11-python-mcp-keycloak (hermetic: local JWKS stub)', async () => {
  const keys = await testKeyPair();
  let stub: TestServer;
  let server: SpawnedExample;
  let issuer: string;
  let mcpUrl: string;
  let baseUrl: string;

  const mint = (overrides: Partial<Parameters<typeof mintLocalJwt>[0]> = {}) =>
    mintLocalJwt({ key: keys.privateKey, issuer, audience: 'mcp-server', sub: 'alice-sub', username: 'alice', scope: 'mcp:tools mcp:admin', roles: ['mcp-user'], ...overrides });

  const init = (token?: string) => initializeSession(mcpUrl, token ? { authorization: `Bearer ${token}` } : {});

  beforeAll(async () => {
    const jwksApp = express();
    jwksApp.get(`${HERMETIC_ISSUER_PATH}/protocol/openid-connect/certs`, (_req, res) => void res.json(keys.jwks));
    stub = await startTestServer(jwksApp);
    issuer = `${stub.baseUrl}${HERMETIC_ISSUER_PATH}`;
    const port = await freePort();
    baseUrl = `http://${new URL(publicUrl(port)).host}`;
    mcpUrl = publicUrl(port);
    server = await spawnExample(SERVER_SCRIPT, { PORT_11: String(port), KEYCLOAK_URL: stub.baseUrl, MCP_LOG: '0' }, { port });
  });

  afterAll(async () => {
    await server?.stop();
    await stub?.close();
  });

  it('serves the RFC 9728 PRM field-by-field identical to example 04 shape', async () => {
    const res = await rawRequest(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    expect(res.json()).toEqual(prmShape(mcpUrl, issuer)); // exact document: no extra fields, no mirror data
  });

  it('does not mirror AS metadata on the resource-server origin', async () => {
    expect((await rawRequest(`${baseUrl}/.well-known/oauth-authorization-server`)).status).toBe(404);
  });

  it('401 without a token carries resource_metadata and NO scope (SEP-835: the PRM drives scopes)', async () => {
    const { response } = await init();
    expectOAuth401(response, { resourceMetadata: `${baseUrl}/.well-known/oauth-protected-resource/mcp` });
    expect(wwwAuthenticate(response).scope).toBeUndefined(); // a pinned scope would stop bob from ever getting mcp:admin
  });

  it('accepts a valid token; effective scopes drop mcp:admin without the mcp-admin role', async () => {
    const token = await mint();
    const { sessionId, response } = await init(token);
    expect(response.status).toBe(200);
    const whoami = await rawCallTool(mcpUrl, sessionId!, 'whoami', {}, { authorization: `Bearer ${token}` });
    const info = JSON.parse((whoami.result!.content as Array<{ text: string }>)[0].text) as Record<string, any>;
    expect(info.username).toBe('alice');
    expect(info.subject).toBe('alice-sub');
    expect(info.scopes).toEqual(['mcp:tools']); // mcp:admin granted to the client but the user lacks the role
    const admin = await rawCallTool(mcpUrl, sessionId!, 'admin_only', {}, { authorization: `Bearer ${token}` });
    expect(admin.result?.isError).toBe(true);
  });

  it('grants admin_only when the mcp-admin role backs the mcp:admin scope', async () => {
    const token = await mint({ sub: 'bob-sub', username: 'bob', roles: ['mcp-user', 'mcp-admin'] });
    const { sessionId } = await init(token);
    const admin = await rawCallTool(mcpUrl, sessionId!, 'admin_only', {}, { authorization: `Bearer ${token}` });
    expect(admin.result?.isError).toBe(false);
    expect((admin.result!.content as Array<{ text: string }>)[0].text).toContain('admin ok');
  });

  it('rejects a wrong-audience token with 401', async () => {
    const { response } = await init(await mint({ audience: 'account' }));
    expectOAuth401(response, { resourceMetadata: `${baseUrl}/.well-known/oauth-protected-resource/mcp` });
  });

  it('rejects a wrong-issuer token with 401', async () => {
    const { response } = await init(await mint({ issuer: 'http://192.0.2.99:8180/realms/mcp' }));
    expect(response.status).toBe(401);
  });

  it('rejects an expired token with 401', async () => {
    const { response } = await init(await mint({ expiresIn: '-1m' }));
    expect(response.status).toBe(401);
  });

  it('rejects a tampered token with 401', async () => {
    const [header, , signature] = (await mint()).split('.');
    const payload = Buffer.from(JSON.stringify({ sub: 'admin', scope: 'mcp:admin mcp:tools', iss: issuer, aud: 'mcp-server', exp: Math.floor(Date.now() / 1000) + 300 })).toString('base64url');
    const { response } = await init(`${header}.${payload}.${signature}`);
    expect(response.status).toBe(401);
  });

  it('answers 403 insufficient_scope for a valid token without mcp:tools (scope email)', async () => {
    const { response } = await init(await mint({ scope: 'email' }));
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toContain('mcp:tools');
    expect(challenge.resource_metadata).toBe(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
  });

  it("rejects another principal's token on an existing session (as an unknown session, 404)", async () => {
    const alice = await mint();
    const bob = await mint({ sub: 'bob-sub', username: 'bob' });
    const { sessionId } = await init(alice);
    const res = await rawCallTool(mcpUrl, sessionId!, 'whoami', {}, { authorization: `Bearer ${bob}` });
    expect(res.response.status).toBe(404); // the TS shared server answers 403; the Python SDK hides the session
  });

  it('rejects a forged Host header (DNS-rebinding protection) with 421', async () => {
    const token = await mint();
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${token}`, host: 'evil.example' });
    expect(response.status).toBe(421); // Python SDK's status for an invalid Host (TS twin uses 403)
  });

  it('reports healthy on /healthz', async () => {
    expect((await rawRequest(`${baseUrl}/healthz`)).json()).toEqual({ ok: true });
  });
});

describe.skipIf(!keycloakUp)('11-python-mcp-keycloak (against the real Keycloak)', () => {
  let server: SpawnedExample;
  let mcpUrl: string;
  let baseUrl: string;

  beforeAll(async () => {
    const port = await freePort();
    mcpUrl = publicUrl(port);
    baseUrl = `http://${new URL(mcpUrl).host}`;
    server = await spawnExample(SERVER_SCRIPT, { PORT_11: String(port), MCP_LOG: '0' }, { port });
  });

  afterAll(async () => {
    await server?.stop();
  });

  /** The SDK transport presents whatever tokens() returns — a provider pre-loaded with mcp-test tokens. */
  const staticProvider = (tokens: OAuthTokens): OAuthClientProvider => ({
    get redirectUrl() { return 'http://127.0.0.1:1/callback'; }, // loopback-ok: never dialled — tokens are pre-loaded
    get clientMetadata() { return { client_name: 'test', redirect_uris: [], response_types: ['code'], grant_types: ['authorization_code'], token_endpoint_auth_method: 'none' }; },
    clientInformation: (): OAuthClientInformationMixed => ({ client_id: 'mcp-test' }),
    saveClientInformation: () => undefined,
    tokens: () => tokens,
    saveTokens: () => undefined,
    redirectToAuthorization: () => { throw new Error('unexpected redirect: the pre-loaded token was not accepted'); },
    saveCodeVerifier: () => undefined,
    codeVerifier: () => { throw new Error('no PKCE flow in this test'); },
    state: () => 'unused',
  });

  it('PRM advertises the real Keycloak issuer', async () => {
    const res = await rawRequest(`${baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(res.json()).toEqual(prmShape(mcpUrl, keycloak().issuer));
  });

  it('full TS SDK round trip: alice (password grant) → whoami identity, admin denied', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools mcp:admin' });
    const { client, close } = await connectClient(mcpUrl, { authProvider: staticProvider(tokens) });
    try {
      const demo = await runDemo(client, { print: () => undefined });
      expect(demo.tools.sort()).toEqual(['add', 'admin_only', 'whoami']);
      const whoami = demo.whoami.json as Record<string, any>;
      expect(whoami.username).toBe('alice');
      expect(whoami.extra.username).toBe('alice');
      expect(typeof whoami.subject).toBe('string');
      expect(whoami.extra.claims.aud).toBe('mcp-server');
      expect(whoami.scopes).not.toContain('mcp:admin'); // alice has no mcp-admin role
      expect(demo.add.text).toBe('5');
      expect(demo.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('full TS SDK round trip: bob → admin_only ok', async () => {
    const tokens = await keycloakPasswordToken({ username: 'bob', password: 'password', scope: 'mcp:tools mcp:admin' });
    const { client, close } = await connectClient(mcpUrl, { authProvider: staticProvider(tokens) });
    try {
      const demo = await runDemo(client, { print: () => undefined });
      expect((demo.whoami.json as Record<string, any>).username).toBe('bob');
      expect(demo.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('a locally minted JWT (right shape, unknown key) is rejected with 401 against the real JWKS', async () => {
    const keys = await testKeyPair();
    const forged = await mintLocalJwt({ key: keys.privateKey, issuer: keycloak().issuer, audience: 'mcp-server' });
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${forged}` });
    expectOAuth401(response, { resourceMetadata: `${baseUrl}/.well-known/oauth-protected-resource/mcp` });
  });
});
