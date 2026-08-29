import { REPO_ROOT, env, publicUrl } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { existsSync, readFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { resolve } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { ClientCredentialsProvider, PrivateKeyJwtProvider } from '@modelcontextprotocol/sdk/client/auth-extensions.js';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { InvalidClientError, UnauthorizedClientError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { listen } from '../../src/shared/http.ts';
import { KC } from '../../src/shared/keycloak.ts';
import { resourceMetadataUrl } from '../../src/shared/prm.ts';
import { createClient, runDemo } from '../../src/shared/client/run.ts';
import {
  callTool,
  connectClient,
  decodeJwtPayload,
  expectOAuth401,
  freePort,
  initializeSession,
  isKeycloakUp,
  keycloakPasswordToken,
  mintLocalJwt,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type TestKeyPair,
  type TestServer,
  type ToolOutcome,
} from '../../src/shared/testing.ts';
import { PORT, buildApp } from './server.ts';

const NAME = '05-keycloak-client-credentials';
// DEMO fallback mirrors .env.example; only used when the Keycloak-backed block actually runs.
const serviceSecret = () => env('MCP_SERVICE_CLIENT_SECRET', 'mcp-service-secret-demo');
const JWT_KEY_PATH = resolve(REPO_ROOT, 'keycloak/.generated/mcp-service-jwt.key');
const hasJwtKey = existsSync(JWT_KEY_PATH);

/** whoami's JSON payload (formatAuthInfo) with the fields these tests assert on. */
interface WhoamiView {
  clientId: string;
  scopes: string[];
  extra: { sub?: string; username?: string; roles?: string[]; claims?: Record<string, unknown> };
}
const who = (outcome: ToolOutcome): WhoamiView => outcome.json as WhoamiView;

// ---------------------------------------------------------------- hermetic (no Keycloak)

describe('05-keycloak-client-credentials (hermetic)', () => {
  const ISSUER = 'http://192.0.2.10:8180/realms/mcp'; // TEST-NET-1: never routed, never fetched
  let keys: TestKeyPair;
  let server: TestServer;
  let mcpUrl: string;

  const mintService = (over: Partial<Parameters<typeof mintLocalJwt>[0]> = {}) =>
    mintLocalJwt({
      key: keys.privateKey,
      kid: keys.kid,
      issuer: ISSUER,
      audience: 'mcp-server',
      azp: KC.clients.service,
      sub: 'svc-uuid-1',
      username: 'service-account-mcp-service',
      scope: 'mcp:tools',
      roles: ['mcp-user'],
      ...over,
    });

  beforeAll(async () => {
    keys = await testKeyPair();
    server = await startTestServer(await buildApp({ issuer: ISSUER, jwks: keys.jwks, audience: ['mcp-server'] }));
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server.close();
  });

  it('401 without a token: resource_metadata, but no scope= (SEP-835 wiring, as in 04)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(publicUrl(PORT)) });
    expect(wwwAuthenticate(response).scope).toBeUndefined();
  });

  it('serves the PRM document and NO authorization-server mirror on the RS origin', async () => {
    const prm = await fetch(`${server.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(prm.status).toBe(200);
    expect(await prm.json()).toEqual({
      resource: publicUrl(PORT),
      authorization_servers: [ISSUER],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: NAME,
      bearer_methods_supported: ['header'],
    });
    const mirror = await fetch(`${server.baseUrl}/.well-known/oauth-authorization-server`);
    expect(mirror.status).toBe(404);
  });

  it('service_only authorizes on client identity — a user client with role AND scope is still refused', async () => {
    // bob-shaped token: everything a human admin can have (scope mcp:admin + role mcp-admin)…
    const userToken = await mintLocalJwt({
      key: keys.privateKey,
      kid: keys.kid,
      issuer: ISSUER,
      audience: 'mcp-server',
      azp: KC.clients.cli,
      sub: 'bob-uuid-1',
      scope: 'mcp:tools mcp:admin',
      roles: ['mcp-user', 'mcp-admin'],
    });
    const asUser = await connectClient(mcpUrl, { headers: { authorization: `Bearer ${userToken}` } });
    try {
      expect((await callTool(asUser.client, 'admin_only')).isError).toBe(false); // …admin_only: yes
      const serviceOnly = await callTool(asUser.client, 'service_only'); // …service_only: never
      expect(serviceOnly.isError).toBe(true);
      expect(serviceOnly.text).toContain('forbidden_client');
    } finally {
      await asUser.close();
    }

    // the service client passes the identity gate but has no role for admin_only
    const asService = await connectClient(mcpUrl, { headers: { authorization: `Bearer ${await mintService()}` } });
    try {
      expect((await callTool(asService.client, 'service_only')).isError).toBe(false);
      expect((await callTool(asService.client, 'admin_only')).isError).toBe(true);
    } finally {
      await asService.close();
    }
  });

  it('a token without mcp:tools → 403 insufficient_scope with the static error_description', async () => {
    const token = await mintService({ scope: 'profile email' });
    const { response } = await initializeSession(mcpUrl, { authorization: `Bearer ${token}` });
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: mcp:tools');
    expect(challenge.scope).toBeUndefined(); // no requiredScopes on requireBearerAuth (SEP-835)
    expect(challenge.resource_metadata).toBe(resourceMetadataUrl(publicUrl(PORT)));
  });

  it('a garbage token → 401 invalid_token', async () => {
    const { response } = await initializeSession(mcpUrl, { authorization: 'Bearer not-a-jwt' });
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(publicUrl(PORT)) });
  });

  it('the allow-list is configuration: buildApp({ allowedClients }) evicts mcp-service too', async () => {
    const strict = await startTestServer(await buildApp({ issuer: ISSUER, jwks: keys.jwks, audience: ['mcp-server'], allowedClients: ['robot-9'] }));
    try {
      const { client, close } = await connectClient(`${strict.baseUrl}/mcp`, { headers: { authorization: `Bearer ${await mintService()}` } });
      try {
        const serviceOnly = await callTool(client, 'service_only');
        expect(serviceOnly.isError).toBe(true);
        expect(serviceOnly.text).toContain('robot-9');
      } finally {
        await close();
      }
    } finally {
      await strict.close();
    }
  });
});

// ---------------------------------------------------------------- Keycloak-backed (§6.5 matrix)

const up = await isKeycloakUp();

describe.skipIf(!up)('05-keycloak-client-credentials (Keycloak)', () => {
  let server: Server;
  let mcpUrl: string;

  const serviceProvider = (over: { clientId?: string; clientSecret?: string; scope?: string } = {}) =>
    new ClientCredentialsProvider({ clientId: KC.clients.service, clientSecret: serviceSecret(), scope: KC.scopes.tools, ...over });

  /** Counts POSTs to the realm's token endpoint; everything else passes through untouched. */
  const tokenCounter = () => {
    const counter = { grants: 0 };
    const fetchSpy: typeof fetch = (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url.includes('/protocol/openid-connect/token')) counter.grants += 1;
      return fetch(input, init);
    };
    return { counter, fetchSpy };
  };

  beforeAll(async () => {
    // The SDK client checks the PRM `resource` against the URL it dials (RFC 8707), so the test
    // server must advertise its own ephemeral 127.0.0.1 URL — hence freePort + resourceUrl.
    const port = await freePort();
    mcpUrl = `http://127.0.0.1:${port}/mcp`;
    server = (await listen(await buildApp({ resourceUrl: mcpUrl }), { port, name: `${NAME}-test`, host: '127.0.0.1' })) as Server;
  });

  afterAll(async () => {
    server.closeAllConnections?.();
    await new Promise<void>((done) => server.close(() => done()));
  });

  it('401 without a token points at this server’s PRM (what smoke’s negative probe checks)', async () => {
    const { response } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(mcpUrl) });
  });

  it('ClientCredentialsProvider: whoami shows the service identity; admin denied; service_only ok', async () => {
    const { client, close } = await connectClient(mcpUrl, { authProvider: serviceProvider() });
    try {
      const demo = await runDemo(client, { print: () => undefined });
      expect(demo.tools.sort()).toEqual(['add', 'admin_only', 'service_only', 'whoami']);
      const identity = who(demo.whoami);
      expect(identity.clientId).toBe(KC.clients.service); // azp
      // Design §6.5 expected `username: undefined`; the live realm's mcp:tools scope carries a
      // username mapper, and Keycloak names a service-account user service-account-<clientId>.
      expect(identity.extra.username).toBe('service-account-mcp-service');
      expect(identity.extra.roles).toEqual(['mcp-user']);
      expect(identity.scopes).toEqual(['mcp:tools']);
      expect(identity.extra.claims?.aud).toBe('mcp-server');
      expect(demo.add.text).toBe('5');
      expect(demo.adminOnly.isError).toBe(true); // no mcp-admin role, no mcp:admin scope
      expect((await callTool(client, 'service_only')).isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('a user token (alice via mcp-test) uses the tools but service_only is denied', async () => {
    const { access_token } = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    const { client, close } = await connectClient(mcpUrl, { headers: { authorization: `Bearer ${access_token}` } });
    try {
      const whoami = await callTool(client, 'whoami');
      expect(who(whoami).clientId).toBe(KC.clients.test);
      expect(who(whoami).extra.username).toBe('alice');
      expect((await callTool(client, 'add', { a: 2, b: 3 })).text).toBe('5');
      const serviceOnly = await callTool(client, 'service_only');
      expect(serviceOnly.isError).toBe(true);
      expect(serviceOnly.text).toContain('forbidden_client');
    } finally {
      await close();
    }
  });

  it('wrong secret: auth() rejects with UnauthorizedClientError (Keycloak answers unauthorized_client)', async () => {
    // Design §6.5 predicted InvalidClientError; live Keycloak 26.7.2 distinguishes: a KNOWN client
    // with bad credentials → 401 `unauthorized_client`, an UNKNOWN client_id → 401 `invalid_client`
    // (next test). auth() treats both as recoverable, retries once, then rethrows the same class.
    const provider = serviceProvider({ clientSecret: 'definitely-wrong' });
    const error = await auth(provider, { serverUrl: mcpUrl }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(UnauthorizedClientError);
    expect(provider.tokens()).toBeUndefined(); // nothing was minted
  });

  it('unknown client id: auth() rejects with InvalidClientError', async () => {
    const provider = serviceProvider({ clientId: 'no-such-client' });
    const error = await auth(provider, { serverUrl: mcpUrl }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(InvalidClientError);
  });

  it('requesting mcp:admin: Keycloak withholds the scope (service account lacks the role) and admin stays denied', async () => {
    // Design §6.5 expected the token to CONTAIN mcp:admin with the role missing. Live Keycloak
    // 26.7.2 already filters the scope claim by the client scope's role scope mapping
    // (mcp:admin → mcp-admin), so the scope never reaches the token — the same policy
    // keycloakEffectiveScopes() would apply is enforced at issuance. admin_only is denied either way.
    const provider = serviceProvider({ scope: 'mcp:tools mcp:admin' });
    await auth(provider, { serverUrl: mcpUrl });
    const payload = decodeJwtPayload(provider.tokens()!.access_token);
    const granted = String(payload.scope).split(' ');
    expect(granted).toContain('mcp:tools');
    expect(granted).not.toContain('mcp:admin');
    const { client, close } = await connectClient(mcpUrl, { authProvider: provider });
    try {
      expect(who(await callTool(client, 'whoami')).scopes).toEqual(['mcp:tools']);
      expect((await callTool(client, 'admin_only')).isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('a stale stored token costs exactly ONE re-grant on the 401, then the request succeeds', async () => {
    const provider = serviceProvider();
    provider.saveTokens({ access_token: 'garbage-expired-long-ago', token_type: 'Bearer' });
    const { counter, fetchSpy } = tokenCounter();
    const client = createClient('05-regrant-test');
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), { authProvider: provider, fetch: fetchSpy });
    await client.connect(transport); // 401 → client_credentials grant → replay → 200
    try {
      expect(counter.grants).toBe(1);
      expect(who(await callTool(client, 'whoami')).clientId).toBe(KC.clients.service);
    } finally {
      await transport.terminateSession().catch(() => undefined);
      await client.close();
    }
  });

  it('a second rejected token in a row trips the circuit breaker: StreamableHTTPError 401, only one grant', async () => {
    // A provider that keeps handing the transport garbage even after a successful grant — the SDK
    // must not loop on the token endpoint: one re-grant, then it gives up with a hard error.
    class BrokenSaveProvider extends ClientCredentialsProvider {
      override saveTokens(_tokens: OAuthTokens): void {
        super.saveTokens({ access_token: 'still-garbage', token_type: 'Bearer' });
      }
    }
    const provider = new BrokenSaveProvider({ clientId: KC.clients.service, clientSecret: serviceSecret(), scope: KC.scopes.tools });
    provider.saveTokens({ access_token: 'garbage', token_type: 'Bearer' });
    const { counter, fetchSpy } = tokenCounter();
    const client = createClient('05-circuit-breaker-test');
    const transport = new StreamableHTTPClientTransport(new URL(mcpUrl), { authProvider: provider, fetch: fetchSpy });
    const error = await client.connect(transport).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(StreamableHTTPError);
    expect((error as StreamableHTTPError).code).toBe(401);
    expect((error as StreamableHTTPError).message).toContain('after successful authentication');
    expect(counter.grants).toBe(1); // the breaker kept the client from hammering the token endpoint
  });

  it.skipIf(!hasJwtKey)('private_key_jwt: mcp-service-jwt authenticates with a signed assertion (no shared secret)', async () => {
    const provider = new PrivateKeyJwtProvider({
      clientId: KC.clients.serviceJwt,
      privateKey: readFileSync(JWT_KEY_PATH, 'utf8'),
      algorithm: 'RS256',
      jwtLifetimeSeconds: 60,
      scope: KC.scopes.tools,
    });
    const { client, close } = await connectClient(mcpUrl, { authProvider: provider });
    try {
      const identity = who(await callTool(client, 'whoami'));
      expect(identity.clientId).toBe(KC.clients.serviceJwt);
      expect(identity.extra.roles).toEqual(['mcp-user']);
      expect(identity.extra.claims?.aud).toBe('mcp-server');
      expect((await callTool(client, 'service_only')).isError).toBe(false);
      expect((await callTool(client, 'admin_only')).isError).toBe(true);
    } finally {
      await close();
    }
  });
});
