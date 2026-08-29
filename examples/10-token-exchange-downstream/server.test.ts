import { env, publicUrl } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import {
  callTool,
  connectClient,
  decodeJwtPayload,
  expectOAuth401,
  initializeSession,
  isKeycloakUp,
  keycloakPasswordToken,
  mintLocalJwt,
  rawRequest,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type TestKeyPair,
  type TestServer,
} from '../../src/shared/testing.ts';
import { exchangeToken, KC, KeycloakError } from '../../src/shared/keycloak.ts';
import { resourceMetadataUrl } from '../../src/shared/prm.ts';
import { buildDownstreamApp } from './downstream.ts';
import { buildApp, PORT } from './server.ts';

const up = await isKeycloakUp();
const STUB_ISSUER = 'http://192.0.2.10:8180/realms/mcp'; // TEST-NET-1 — never dialled

// ---------------------------------------------------------------- downstream verifier (hermetic)

describe('downstream API verifier (hermetic)', () => {
  let keys: TestKeyPair;
  let downstream: TestServer;

  beforeAll(async () => {
    keys = await testKeyPair();
    downstream = await startTestServer(await buildDownstreamApp({ issuer: STUB_ISSUER, jwks: keys.jwks }));
  });
  afterAll(async () => {
    await downstream.close();
  });

  /** An exchanged-shaped token: aud=downstream-api, azp=mcp-server, scope=downstream-api. */
  const mint = (overrides: Partial<Parameters<typeof mintLocalJwt>[0]> = {}) =>
    mintLocalJwt({
      key: keys.privateKey,
      kid: keys.kid,
      issuer: STUB_ISSUER,
      audience: 'downstream-api',
      scope: 'downstream-api',
      azp: 'mcp-server',
      sub: 'user-1',
      ...overrides,
    });

  it('answers /healthz and echoes the exchanged identity on /me', async () => {
    expect((await rawRequest(`${downstream.baseUrl}/healthz`)).status).toBe(200);
    const res = await rawRequest(`${downstream.baseUrl}/me`, { headers: { authorization: `Bearer ${await mint()}` } });
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({ sub: 'user-1', azp: 'mcp-server', aud: 'downstream-api', scope: 'downstream-api', roles: ['mcp-user'] });
  });

  it('401 without a token', async () => {
    const res = await rawRequest(`${downstream.baseUrl}/me`);
    expectOAuth401(res, { resourceMetadata: false }); // a plain API — no PRM to advertise
  });

  it('401 for an MCP token (aud=mcp-server): audience isolation', async () => {
    const res = await rawRequest(`${downstream.baseUrl}/me`, { headers: { authorization: `Bearer ${await mint({ audience: 'mcp-server' })}` } });
    expectOAuth401(res, { resourceMetadata: false });
    expect(wwwAuthenticate(res).error_description).toContain('wrong audience');
  });

  it('401 for an expired token', async () => {
    const res = await rawRequest(`${downstream.baseUrl}/me`, { headers: { authorization: `Bearer ${await mint({ expiresIn: '-10m' })}` } });
    expectOAuth401(res, { resourceMetadata: false });
    expect(wwwAuthenticate(res).error_description).toContain('expired');
  });

  it('403 when the downstream-api scope is missing', async () => {
    const res = await rawRequest(`${downstream.baseUrl}/me`, { headers: { authorization: `Bearer ${await mint({ scope: 'profile email' })}` } });
    expect(res.status).toBe(403);
    const challenge = wwwAuthenticate(res);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: downstream-api');
  });
});

// ------------------------------------------------- MCP server (hermetic: PRM, SEP-835, cache)

describe('MCP server (hermetic: PRM, SEP-835 wiring, cache lifetime)', () => {
  let keys: TestKeyPair;
  let downstream: TestServer;
  let mcp: TestServer;
  let mcpUrl: string;
  let fakeNow = Math.floor(Date.now() / 1000);
  // Stubbed exchange: answers like Keycloak's token endpoint, minting a downstream-shaped token.
  const exchangeStub = vi.fn(async () =>
    Response.json({
      access_token: await mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: STUB_ISSUER, audience: 'downstream-api', scope: 'downstream-api', azp: 'mcp-server', sub: 'cache-user', expiresIn: '15m' }),
      token_type: 'Bearer',
      expires_in: 900,
    }),
  );

  beforeAll(async () => {
    keys = await testKeyPair();
    downstream = await startTestServer(await buildDownstreamApp({ issuer: STUB_ISSUER, jwks: keys.jwks }));
    mcp = await startTestServer(
      await buildApp({
        issuer: STUB_ISSUER,
        jwks: keys.jwks,
        audience: ['mcp-server'],
        downstreamUrl: downstream.baseUrl,
        clientSecret: 'test-secret',
        exchangeFetch: exchangeStub as unknown as typeof fetch,
        now: () => fakeNow,
      }),
    );
    mcpUrl = `${mcp.baseUrl}/mcp`;
  });
  afterAll(async () => {
    await mcp.close();
    await downstream.close();
  });

  it('serves the PRM document and no authorization-server mirror', async () => {
    const res = await rawRequest(`${mcp.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({
      resource: publicUrl(PORT),
      authorization_servers: [STUB_ISSUER],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: '10-token-exchange-downstream',
      bearer_methods_supported: ['header'],
    });
    expect((await rawRequest(`${mcp.baseUrl}/.well-known/oauth-authorization-server`)).status).toBe(404);
  });

  it('401 without a token carries resource_metadata and no scope parameter (SEP-835)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(publicUrl(PORT)) });
    expect(wwwAuthenticate(response).scope).toBeUndefined();
  });

  it('403 with the static description for a token without mcp:tools', async () => {
    const token = await mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: STUB_ISSUER, audience: 'mcp-server', scope: 'profile email' });
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${token}` });
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: mcp:tools');
    expect(challenge.scope).toBeUndefined();
  });

  it('caches per subject token and drops the entry once the subject expiry passes', async () => {
    // Subject token valid for 60 s (real clock — requireBearerAuth accepts it throughout);
    // the CACHE uses the injected clock, so the expiry can "pass" without waiting.
    const subject = await mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: STUB_ISSUER, audience: 'mcp-server', scope: 'mcp:tools', sub: 'cache-user', expiresIn: '60s' });
    const { client, close } = await connectClient(mcpUrl, { headers: { authorization: `Bearer ${subject}` } });
    try {
      expect((await callTool(client, 'downstream_profile')).isError).toBe(false);
      expect(exchangeStub).toHaveBeenCalledTimes(1);
      expect((await callTool(client, 'downstream_profile')).isError).toBe(false);
      expect(exchangeStub).toHaveBeenCalledTimes(1); // cache hit — no second exchange
      fakeNow += 120; // past min(subject exp = +60 s, exchanged exp = +900 s)
      expect((await callTool(client, 'downstream_profile')).isError).toBe(false);
      expect(exchangeStub).toHaveBeenCalledTimes(2); // entry dropped → fresh exchange
    } finally {
      await close();
      fakeNow = Math.floor(Date.now() / 1000);
    }
  });
});

// ---------------------------------------------------------------- with Keycloak (skipIf)

describe.skipIf(!up)('with Keycloak: RFC 8693 exchange end-to-end', () => {
  let downstream: TestServer;
  let mcp: TestServer;
  let mcpUrl: string;
  let alice: OAuthTokens;
  let aliceSub: string;
  const serverSecret = env('MCP_SERVER_CLIENT_SECRET', 'mcp-server-secret-demo'); // DEMO
  const exchangeSpy = vi.fn(fetch); // real fetch, counted
  const exchanges = () => exchangeSpy.mock.calls.length;

  beforeAll(async () => {
    downstream = await startTestServer(await buildDownstreamApp());
    mcp = await startTestServer(
      await buildApp({ downstreamUrl: downstream.baseUrl, exchangeFetch: exchangeSpy as unknown as typeof fetch, passthrough: true, clientSecret: serverSecret }),
    );
    mcpUrl = `${mcp.baseUrl}/mcp`;
    alice = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    aliceSub = String(decodeJwtPayload(alice.access_token).sub);
  });
  afterAll(async () => {
    await mcp?.close();
    await downstream?.close();
  });

  const asAlice = () => connectClient(mcpUrl, { headers: { authorization: `Bearer ${alice.access_token}` } });

  it('downstream_profile acts on behalf of alice: her sub, exchanged by mcp-server, for downstream-api', async () => {
    const { client, close } = await asAlice();
    try {
      const tools = (await client.listTools()).tools.map((t) => t.name).sort();
      expect(tools).toEqual(['add', 'admin_only', 'downstream_passthrough', 'downstream_profile', 'whoami']);
      const whoami = await callTool(client, 'whoami');
      expect((whoami.json as { extra?: { username?: string } }).extra?.username).toBe('alice'); // as 04
      const profile = await callTool(client, 'downstream_profile');
      expect(profile.isError).toBe(false);
      const body = profile.json as { via: string; exchanged: Record<string, unknown>; downstream: Record<string, unknown> };
      expect(body.via).toBe('token-exchange');
      expect(body.exchanged).toEqual({ aud: 'downstream-api', azp: 'mcp-server', scope: 'downstream-api' });
      expect(body.downstream.sub).toBe(aliceSub); // still the USER
      expect(body.downstream.azp).toBe('mcp-server'); // obtained by the SERVER
      expect(body.downstream.aud).toBe('downstream-api');
      expect(body.downstream.scope).toBe('downstream-api');
      expect(body.downstream.roles).toContain('mcp-user');
    } finally {
      await close();
    }
  });

  it('reuses the cached exchanged token — no second exchange for the same subject token', async () => {
    const { client, close } = await asAlice();
    try {
      const before = exchanges();
      expect((await callTool(client, 'downstream_profile')).isError).toBe(false);
      const afterFirst = exchanges();
      expect(afterFirst).toBeLessThanOrEqual(before + 1); // 0 extra if alice's token is already cached
      expect((await callTool(client, 'downstream_profile')).isError).toBe(false);
      expect(exchanges()).toBe(afterFirst);
    } finally {
      await close();
    }
  });

  it('the passthrough anti-pattern fails: the downstream refuses the MCP token with 401', async () => {
    const { client, close } = await asAlice();
    try {
      const outcome = await callTool(client, 'downstream_passthrough');
      expect(outcome.isError).toBe(true);
      const body = outcome.json as { error: string; status: number; www_authenticate?: string };
      expect(body.status).toBe(401);
      expect(body.www_authenticate).toContain('invalid_token');
    } finally {
      await close();
    }
  });

  it('the exchanged token is rejected at /mcp: its aud lacks mcp-server', async () => {
    const exchanged = await exchangeToken({
      subjectToken: alice.access_token,
      audience: KC.clients.downstream,
      scope: KC.scopes.downstream,
      clientId: KC.clients.server,
      clientSecret: serverSecret,
    });
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${exchanged.access_token}` });
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(publicUrl(PORT)) });
    expect(wwwAuthenticate(response).error_description).toContain('wrong audience');
  });

  it('the inbound MCP token is rejected at /me: its aud lacks downstream-api', async () => {
    const res = await rawRequest(`${downstream.baseUrl}/me`, { headers: { authorization: `Bearer ${alice.access_token}` } });
    expectOAuth401(res, { resourceMetadata: false });
    expect(wwwAuthenticate(res).error_description).toContain('wrong audience');
  });

  it('exchange without scope= → invalid_request naming the unavailable audience', async () => {
    const error = await exchangeToken({
      subjectToken: alice.access_token,
      audience: KC.clients.downstream, // note: NO scope
      clientId: KC.clients.server,
      clientSecret: serverSecret,
    }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(KeycloakError);
    expect((error as KeycloakError).error).toBe('invalid_request');
    expect((error as KeycloakError).error_description).toContain('audience');
  });

  it('exchange by a client without standard token exchange enabled is refused', async () => {
    const error = await exchangeToken({
      subjectToken: alice.access_token,
      audience: KC.clients.downstream,
      scope: KC.scopes.downstream,
      clientId: KC.clients.service, // mcp-service has no standard.token.exchange.enabled
      clientSecret: env('MCP_SERVICE_CLIENT_SECRET', 'mcp-service-secret-demo'), // DEMO
    }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(KeycloakError);
    expect((error as KeycloakError).error_description).toContain('not enabled');
  });

  it('pins why "subject token without the requester in aud" stays docs-only: mcp:tools is a default scope of mcp-test', async () => {
    // Keycloak refuses to exchange a subject token that does not list the requesting client
    // (mcp-server) in aud. mcp-test cannot mint such a token — mcp:tools (whose audience mapper
    // adds mcp-server) is one of its DEFAULT scopes — so the rule is documented, not asserted.
    const minimal = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'email' });
    const payload = decodeJwtPayload(minimal.access_token);
    expect(payload.aud).toBe('mcp-server');
    expect(String(payload.scope)).toContain('mcp:tools');
  });
});
