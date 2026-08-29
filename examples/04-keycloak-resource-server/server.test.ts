/**
 * 04 — negative matrix (design §6.4). Hermetic rows run with an injected issuer + local JWKS
 * (192.0.2.x is TEST-NET: nothing is ever dialled); Keycloak-backed rows verify the same server
 * against real realm tokens and the SDK's discovery, skipped when Keycloak is down
 * (`npm run test:kc` turns the skip into a failure).
 *
 * SEP-835 note (differs from the original §6.4 wording): requireBearerAuth carries NO
 * requiredScopes, so the 401 has resource_metadata but no scope=, and a token without mcp:tools
 * is a 403 from the VERIFIER with error_description "missing scope: mcp:tools" (no scope= there
 * either). The PRM's scopes_supported is what drives the client's scope request — asserted in the
 * stub-AS discovery test below.
 */
import { keycloak, publicUrl } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import express from 'express';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { discoverOAuthServerInfo, UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import { printResult, runDemo } from '../../src/shared/client/run.ts';
import { KC } from '../../src/shared/keycloak.ts';
import { resourceMetadataUrl } from '../../src/shared/prm.ts';
import {
  connectClient,
  decodeJwtPayload,
  expectOAuth401,
  initializeSession,
  isKeycloakUp,
  keycloakClientCredentials,
  keycloakPasswordToken,
  mintLocalJwt,
  rawCallTool,
  rawRequest,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type MintOptions,
  type TestKeyPair,
  type TestServer,
} from '../../src/shared/testing.ts';
import { buildApp, PORT } from './server.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp'; // TEST-NET-1 — never reachable, never dialled
const RESOURCE_URL = publicUrl(PORT); // what the server advertises, whatever the test dials
const PRM_URL = resourceMetadataUrl(RESOURCE_URL);
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const keycloakUp = await isKeycloakUp();

describe('04-keycloak-resource-server (hermetic: local JWKS, offline issuer)', () => {
  let keys: TestKeyPair;
  let server: TestServer;
  let mcpUrl: string;

  const mint = (opts: Partial<MintOptions> = {}) =>
    mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: ISSUER, audience: KC.audience, ...opts });

  beforeAll(async () => {
    keys = await testKeyPair();
    server = await startTestServer(await buildApp({ issuer: ISSUER, jwks: keys.jwks, audience: [KC.audience] }));
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server.close();
  });

  it('401 without a token carries resource_metadata but NO scope (SEP-835)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).scope).toBeUndefined();
  });

  it('serves the exact PRM document at the path-aware well-known URL', async () => {
    const res = await rawRequest(`${server.baseUrl}${new URL(PRM_URL).pathname}`);
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({
      resource: RESOURCE_URL,
      authorization_servers: [ISSUER],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: '04-keycloak-resource-server',
      bearer_methods_supported: ['header'],
    });
  });

  it('does NOT mirror the AS metadata on the resource-server origin (404)', async () => {
    expect((await rawRequest(`${server.baseUrl}/.well-known/oauth-authorization-server`)).status).toBe(404);
    expect((await rawRequest(`${server.baseUrl}/.well-known/oauth-authorization-server/realms/mcp`)).status).toBe(404);
  });

  it('rejects garbage instead of a JWT with 401', async () => {
    const { response } = await initializeSession(mcpUrl, bearer('not-a-jwt'));
    expectOAuth401(response, { resourceMetadata: PRM_URL });
  });

  it("rejects a token whose aud is ['account'] (wrong audience)", async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ audience: ['account'] })));
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).error_description).toBe('JWT rejected: wrong audience');
  });

  it('rejects a token from another issuer', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ issuer: 'http://192.0.2.99:8180/realms/other' })));
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).error_description).toBe('JWT rejected: wrong issuer');
  });

  it('rejects an expired token', async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ expiresIn: '-10m' })));
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).error_description).toBe('JWT rejected: token expired');
  });

  it('rejects a tampered token (payload upgraded to admin, signature unchanged)', async () => {
    const [header, payload, signature] = (await mint({ sub: 'alice' })).split('.');
    const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<string, unknown>;
    claims.scope = 'mcp:tools mcp:admin';
    claims.realm_access = { roles: ['mcp-user', 'mcp-admin'] };
    const forged = [header, Buffer.from(JSON.stringify(claims)).toString('base64url'), signature].join('.');
    const { response } = await initializeSession(mcpUrl, bearer(forged));
    expectOAuth401(response, { resourceMetadata: PRM_URL });
    expect(wwwAuthenticate(response).error_description).toBe('JWT rejected: bad signature');
  });

  it("403 insufficient_scope for a valid token without mcp:tools — static message, no scope=", async () => {
    const { response } = await initializeSession(mcpUrl, bearer(await mint({ scope: 'profile email' })));
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: mcp:tools');
    expect(challenge.scope).toBeUndefined(); // SEP-835: nothing pins the client to a scope list
    expect(challenge.resource_metadata).toBe(PRM_URL);
  });

  it('alice: mcp:admin in scope but role mcp-user only → effective scopes drop it, admin denied', async () => {
    const token = await mint({ sub: 'alice', username: 'alice', scope: 'mcp:tools mcp:admin', roles: ['mcp-user'] });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      const whoami = result.whoami.json as { clientId: string; scopes: string[]; extra: { username?: string; roles?: string[] } };
      expect(whoami).toMatchObject({ clientId: 'mcp-cli', extra: { username: 'alice', roles: ['mcp-user'] } });
      expect(whoami.scopes).toEqual(['mcp:tools']); // scope = client grant, role = user right
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
      expect(printResult('04', result, undefined, () => undefined)).toBe(0);
    } finally {
      await close();
    }
  });

  it('bob: realm role mcp-admin keeps the mcp:admin scope, admin ok', async () => {
    const token = await mint({ sub: 'bob', username: 'bob', scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect((result.whoami.json as { scopes: string[] }).scopes).toEqual(['mcp:tools', 'mcp:admin']);
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it("rejects bob's token on alice's session with 403 (session ↔ subject binding)", async () => {
    const alice = await mint({ sub: 'alice' });
    const bob = await mint({ sub: 'bob', roles: ['mcp-user', 'mcp-admin'] });
    const { sessionId } = await initializeSession(mcpUrl, bearer(alice));
    expect(sessionId).toBeDefined();
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer(alice))).response.status).toBe(200);
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer(bob))).response.status).toBe(403);
  });
});

describe('SDK client discovery against a stub AS (hermetic)', () => {
  let stubAs: TestServer;
  let asOrigin = '';
  let rsServer: TestServer;
  let keys: TestKeyPair;
  const fetchLog: string[] = [];
  let registeredScope: string | undefined;

  beforeAll(async () => {
    keys = await testKeyPair();
    // A minimal RFC 8414 authorization server: metadata + Dynamic Client Registration. The flow
    // deliberately ends at the authorization redirect — no browser runs in tests.
    const stub = express();
    stub.get('/.well-known/oauth-authorization-server', (_req, res) => {
      res.json({
        issuer: asOrigin,
        authorization_endpoint: `${asOrigin}/authorize`,
        token_endpoint: `${asOrigin}/token`,
        registration_endpoint: `${asOrigin}/register`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        code_challenge_methods_supported: ['S256'],
        token_endpoint_auth_methods_supported: ['none'],
      });
    });
    stub.post('/register', express.json(), (req, res) => {
      registeredScope = (req.body as { scope?: string }).scope;
      res.status(201).json({ ...(req.body as Record<string, unknown>), client_id: 'stub-client-id' });
    });
    stubAs = await startTestServer(stub);
    asOrigin = stubAs.baseUrl;
    rsServer = await startTestServer(await buildApp({ issuer: asOrigin, jwks: keys.jwks, audience: [KC.audience] }));
  });

  afterAll(async () => {
    await rsServer.close();
    await stubAs.close();
  });

  // The server advertises its canonical public URL; the test listens on an ephemeral loopback
  // port. Dial the canonical URL and rewrite only the host at fetch time — exactly what DNS would
  // do — so PRM/resource/aud comparisons run against the real production strings.
  const rewritingFetch: FetchLike = (input, init) => {
    fetchLog.push(`${init?.method ?? 'GET'} ${String(input)}`);
    const url = new URL(String(input));
    if (url.host === new URL(RESOURCE_URL).host) url.host = new URL(rsServer.baseUrl).host;
    return fetch(url, init);
  };

  it('walks 401 → PRM → AS metadata → DCR and reaches the stub authorization endpoint', async () => {
    let authorizeUrl: URL | undefined;
    let clientInfo: OAuthClientInformationMixed | undefined;
    const provider: OAuthClientProvider = {
      get redirectUrl() {
        return 'http://127.0.0.1:4199/callback'; // never bound — the flow stops at the redirect
      },
      get clientMetadata() {
        return {
          client_name: '04 discovery test',
          redirect_uris: ['http://127.0.0.1:4199/callback'],
          grant_types: ['authorization_code'],
          response_types: ['code'],
          token_endpoint_auth_method: 'none',
        };
      },
      state: () => 'discovery-test-state',
      clientInformation: () => clientInfo,
      saveClientInformation: (info) => {
        clientInfo = info;
      },
      tokens: () => undefined,
      saveTokens: () => undefined,
      redirectToAuthorization: (url) => {
        authorizeUrl = url;
      },
      saveCodeVerifier: () => undefined,
      codeVerifier: () => 'unused',
    };

    const client = new Client({ name: 'discovery-test', version: '0.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(RESOURCE_URL), { authProvider: provider, fetch: rewritingFetch });
    await expect(client.connect(transport)).rejects.toThrow(UnauthorizedError);
    await client.close().catch(() => undefined);

    // Discovery order (RFC 9728 → RFC 8414 → RFC 7591), all through the transport's fetch:
    const at = (predicate: (line: string) => boolean) => fetchLog.findIndex(predicate);
    const mcpPost = at((l) => l === `POST ${RESOURCE_URL}`);
    const prmGet = at((l) => l.startsWith('GET') && l.includes(new URL(PRM_URL).pathname));
    const asMetadata = at((l) => l.startsWith('GET') && l.includes('/.well-known/oauth-authorization-server'));
    const register = at((l) => l === `POST ${asOrigin}/register`);
    expect(mcpPost, fetchLog.join('\n')).toBeGreaterThanOrEqual(0);
    expect(prmGet).toBeGreaterThan(mcpPost);
    expect(asMetadata).toBeGreaterThan(prmGet);
    expect(register).toBeGreaterThan(asMetadata);

    // SEP-835: with no scope= on the 401, the PRM's scopes_supported drives DCR and authorize.
    expect(registeredScope).toBe('mcp:tools mcp:admin');
    expect(clientInfo?.client_id).toBe('stub-client-id');
    expect(authorizeUrl).toBeDefined();
    expect(`${authorizeUrl!.origin}${authorizeUrl!.pathname}`).toBe(`${asOrigin}/authorize`);
    const q = authorizeUrl!.searchParams;
    expect(q.get('client_id')).toBe('stub-client-id');
    expect(q.get('response_type')).toBe('code');
    expect(q.get('code_challenge_method')).toBe('S256');
    expect(q.get('scope')).toBe('mcp:tools mcp:admin');
    expect(q.get('resource')).toBe(RESOURCE_URL); // RFC 8707, sent even though Keycloak ignores it
    expect(q.get('state')).toBe('discovery-test-state');
  });
});

describe.skipIf(!keycloakUp)('04-keycloak-resource-server against the real realm', () => {
  let server: TestServer;
  let mcpUrl: string;

  beforeAll(async () => {
    server = await startTestServer(await buildApp()); // real discovery, real JWKS
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server?.close();
  });

  it('alice: requested mcp:admin, still denied — the role decides at BOTH ends', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools mcp:admin' });
    // First line of defence — Keycloak: the mcp:admin client scope maps role mcp-admin, which
    // alice lacks, so the realm already leaves mcp:admin out of her `scope` claim at issuance.
    expect(decodeJwtPayload(tokens.access_token).scope).not.toContain('mcp:admin');
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      const whoami = result.whoami.json as { clientId: string; scopes: string[]; extra: { username?: string; roles?: string[]; claims: Record<string, unknown> } };
      expect(whoami).toMatchObject({ clientId: KC.clients.test, extra: { username: 'alice', roles: ['mcp-user'] } });
      expect(whoami.scopes).toContain('mcp:tools');
      // Second line — this server: keycloakEffectiveScopes() would drop mcp:admin for a roleless
      // user even if an AS DID mint it (proven hermetically above — never trust AS config alone).
      expect(whoami.scopes).not.toContain('mcp:admin');
      expect(whoami.extra.claims.aud).toBe(KC.audience);
      expect(whoami.extra.claims.iss).toBe(keycloak().issuer);
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('bob: realm role mcp-admin → admin_only ok', async () => {
    const tokens = await keycloakPasswordToken({ username: 'bob', password: 'password', scope: 'mcp:tools mcp:admin' });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect((result.whoami.json as { scopes: string[] }).scopes).toContain('mcp:admin');
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('mcp-service (client_credentials) is accepted as a plain user, admin denied', async () => {
    const tokens = await keycloakClientCredentials({
      clientId: KC.clients.service,
      clientSecret: process.env.MCP_SERVICE_CLIENT_SECRET ?? 'mcp-service-secret-demo',
    });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: KC.clients.service });
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it("the SDK's discoverOAuthServerInfo resolves the PRM to the Keycloak metadata", async () => {
    const local = new URL(PRM_URL);
    local.host = new URL(server.baseUrl).host; // dial the test listener, keep the advertised path
    const info = await discoverOAuthServerInfo(RESOURCE_URL, { resourceMetadataUrl: local });
    expect(info.resourceMetadata?.resource).toBe(RESOURCE_URL);
    expect(info.resourceMetadata?.authorization_servers).toEqual([keycloak().issuer]);
    expect(info.authorizationServerUrl).toBe(keycloak().issuer);
    expect(info.authorizationServerMetadata?.issuer).toBe(keycloak().issuer);
    expect(info.authorizationServerMetadata?.registration_endpoint).toBe(keycloak().registrationEndpoint);
    expect(info.authorizationServerMetadata?.code_challenge_methods_supported).toContain('S256');
  });
});
