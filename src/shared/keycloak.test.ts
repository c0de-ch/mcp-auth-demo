/**
 * The shared foundation against the REAL Keycloak realm: discovery, JWKS verification, the
 * effective-scope policy, session ↔ subject binding, introspection, token exchange, revocation,
 * admin logout, and the realm deltas (mcp-test, mcp-service-jwt). Skipped (with a message) when
 * Keycloak is not running; `npm run test:kc` turns the skip into a failure.
 */
import { keycloak } from './env.ts'; // always first (see README: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { importPKCS8, SignJWT } from 'jose';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { REPO_ROOT } from './env.ts';
import { createApp, mountMcp } from './http.ts';
import { KC, adminLogoutUser, audiences, createKeycloakVerifier, discoverKeycloak, exchangeToken, introspect, KeycloakError, revokeToken } from './keycloak.ts';
import { createDemoServer } from './tools.ts';
import { connectClient, decodeJwtPayload, expectOAuth401, initializeSession, isKeycloakUp, keycloakClientCredentials, keycloakPasswordToken, rawCallTool, startTestServer, type TestServer } from './testing.ts';
import { runDemo } from './client/run.ts';

const keycloakUp = await isKeycloakUp();
const SERVER_SECRET = process.env.MCP_SERVER_CLIENT_SECRET ?? 'mcp-server-secret-demo';
const SERVICE_SECRET = process.env.MCP_SERVICE_CLIENT_SECRET ?? 'mcp-service-secret-demo';

describe.skipIf(!keycloakUp)('shared foundation against Keycloak', () => {
  let server: TestServer;
  let mcpUrl: string;

  beforeAll(async () => {
    const verifier = await createKeycloakVerifier();
    const app = createApp({ log: false });
    mountMcp(app, { createServer: () => createDemoServer({ name: 'kc-test' }), auth: requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'] }) });
    server = await startTestServer(app);
    mcpUrl = `${server.baseUrl}/mcp`;
  });

  afterAll(async () => {
    await server?.close();
  });

  const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

  it('discovers the realm: issuer equals keycloak().issuer, S256, jwks/introspection/revocation endpoints', async () => {
    const md = await discoverKeycloak();
    const kc = keycloak();
    expect(md.issuer).toBe(kc.issuer);
    expect(md.jwks_uri).toBe(kc.jwksUri);
    expect(md.introspection_endpoint).toBe(kc.introspectionEndpoint);
    expect(md.registration_endpoint).toBe(kc.registrationEndpoint);
    expect(md.revocation_endpoint).toBe(`${kc.issuer}/protocol/openid-connect/revoke`);
    expect(md.code_challenge_methods_supported).toContain('S256');
    expect(md.grant_types_supported).toEqual(expect.arrayContaining(['client_credentials', 'urn:ietf:params:oauth:grant-type:token-exchange']));
    expect(await discoverKeycloak()).toBe(md); // cached
    expect(audiences()).toEqual([KC.audience]);
  });

  it('rejects missing and garbage tokens with 401 + WWW-Authenticate', async () => {
    const missing = await initializeSession(mcpUrl);
    expectOAuth401(missing.response, { resourceMetadata: false, scope: 'mcp:tools' });

    const garbage = await initializeSession(mcpUrl, bearer('not.a.jwt'));
    expect(garbage.response.status).toBe(401);
    expect(garbage.response.headers['www-authenticate']).toMatch(/JWT rejected/);
  });

  it('mints test tokens with mcp-test only: mcp-cli refuses the password grant', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ azp: KC.clients.test, aud: KC.audience, preferred_username: 'alice' });
    await expect(keycloakPasswordToken({ username: 'alice', password: 'password', clientId: KC.clients.cli })).rejects.toThrow(/unauthorized_client/);
  });

  it('accepts alice (mcp:tools) and rejects admin_only', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools' });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: KC.clients.test, extra: { username: 'alice', roles: ['mcp-user'] } });
      expect((result.whoami.json as { scopes: string[] }).scopes).toContain('mcp:tools');
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('grants mcp:admin to bob (role mcp-admin) and not to alice, who may ask for it', async () => {
    const bob = await keycloakPasswordToken({ username: 'bob', password: 'password', scope: 'mcp:tools mcp:admin' });
    expect(decodeJwtPayload(bob.access_token).scope).toContain('mcp:admin');
    const bobClient = await connectClient(mcpUrl, { headers: bearer(bob.access_token) });
    try {
      expect((await runDemo(bobClient.client, { print: () => undefined })).adminOnly.isError).toBe(false);
    } finally {
      await bobClient.close();
    }

    // Alice asks for the same scope. The realm's role scope mapping (mcp:admin -> mcp-admin) makes
    // Keycloak refuse to issue it, so the scope never reaches the token — the authorization server
    // enforces the scope/role agreement itself. See docs/keycloak.md.
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools mcp:admin' });
    expect(decodeJwtPayload(alice.access_token).scope).not.toContain('mcp:admin');
    const aliceClient = await connectClient(mcpUrl, { headers: bearer(alice.access_token) });
    try {
      const result = await runDemo(aliceClient.client, { print: () => undefined });
      expect((result.whoami.json as { scopes: string[] }).scopes).not.toContain('mcp:admin');
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await aliceClient.close();
    }
  });

  it('accepts a service account token (client_credentials with a shared secret)', async () => {
    const tokens = await keycloakClientCredentials({ clientId: KC.clients.service, clientSecret: SERVICE_SECRET });
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(tokens.access_token) });
    try {
      expect((await runDemo(client, { print: () => undefined })).whoami.json).toMatchObject({ clientId: KC.clients.service, extra: { roles: ['mcp-user'] } });
    } finally {
      await close();
    }
  });

  it('accepts a service account token obtained with private_key_jwt (mcp-service-jwt)', async () => {
    const keyFile = join(REPO_ROOT, 'keycloak/.generated/mcp-service-jwt.key');
    if (!existsSync(keyFile)) return; // realm was rendered elsewhere (CI copies .env only) — covered by kc.sh keys
    const md = await discoverKeycloak();
    const key = await importPKCS8(readFileSync(keyFile, 'utf8'), 'RS256');
    const assertion = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuer(KC.clients.serviceJwt)
      .setSubject(KC.clients.serviceJwt)
      .setAudience(md.token_endpoint)
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(key);
    const res = await fetch(md.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', scope: 'mcp:tools', client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion }),
    });
    const tokens = (await res.json()) as { access_token: string; error?: string };
    expect(tokens.error).toBeUndefined();
    expect(decodeJwtPayload(tokens.access_token)).toMatchObject({ azp: KC.clients.serviceJwt, aud: KC.audience });
    expect((await initializeSession(mcpUrl, bearer(tokens.access_token))).response.status).toBe(200);
  });

  it("refuses to reuse alice's session with bob's token", async () => {
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    const bob = await keycloakPasswordToken({ username: 'bob', password: 'password' });
    const { sessionId } = await initializeSession(mcpUrl, bearer(alice.access_token));
    expect(sessionId).toBeDefined();
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer(alice.access_token))).response.status).toBe(200);
    expect((await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer(bob.access_token))).response.status).toBe(403);
  });

  it('introspects an mcp-test token as active (aud mcp-server, scope, username)', async () => {
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    const info = await introspect(alice.access_token, { clientId: KC.clients.server, clientSecret: SERVER_SECRET });
    expect(info).toMatchObject({ active: true, aud: KC.audience, username: 'alice', client_id: KC.clients.test });
    expect(info.scope).toContain('mcp:tools');
    expect(await introspect('garbage', { clientId: KC.clients.server, clientSecret: SERVER_SECRET })).toEqual({ active: false });
    await expect(introspect(alice.access_token, { clientId: KC.clients.server, clientSecret: 'wrong' })).rejects.toThrow(KeycloakError);
  });

  it('exchanges a user token for a downstream-api token (RFC 8693), only with scope=downstream-api', async () => {
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    const subject = decodeJwtPayload(alice.access_token).sub;
    const exchanged = await exchangeToken({ subjectToken: alice.access_token, audience: KC.clients.downstream, scope: KC.scopes.downstream, clientId: KC.clients.server, clientSecret: SERVER_SECRET });
    expect(decodeJwtPayload(exchanged.access_token)).toMatchObject({ aud: KC.clients.downstream, azp: KC.clients.server, sub: subject, scope: KC.scopes.downstream });

    const failure = await exchangeToken({ subjectToken: alice.access_token, audience: KC.clients.downstream, clientId: KC.clients.server, clientSecret: SERVER_SECRET }).catch((e: KeycloakError) => e);
    expect(failure).toBeInstanceOf(KeycloakError);
    expect((failure as KeycloakError).error).toBe('invalid_request');
    expect((failure as KeycloakError).error_description).toContain('audience');

    // the exchanged token must NOT be accepted by the MCP server (aud lacks mcp-server)
    const res = await initializeSession(mcpUrl, bearer(exchanged.access_token));
    expect(res.response.status).toBe(401);
    expect(res.response.headers['www-authenticate']).toContain('wrong audience');
  });

  it('revokes a token (RFC 7009) — introspection sees it immediately, the JWT verifier does not', async () => {
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    await revokeToken(alice.access_token, { clientId: KC.clients.test });
    expect((await introspect(alice.access_token, { clientId: KC.clients.server, clientSecret: SERVER_SECRET })).active).toBe(false);
    expect((await initializeSession(mcpUrl, bearer(alice.access_token))).response.status).toBe(200); // still a valid signature until exp
  });

  it('adminLogoutUser() ends the user sessions (introspection turns inactive)', async () => {
    const bob = await keycloakPasswordToken({ username: 'bob', password: 'password' });
    expect((await introspect(bob.access_token, { clientId: KC.clients.server, clientSecret: SERVER_SECRET })).active).toBe(true);
    await adminLogoutUser('bob');
    expect((await introspect(bob.access_token, { clientId: KC.clients.server, clientSecret: SERVER_SECRET })).active).toBe(false);
    await expect(adminLogoutUser('nobody')).rejects.toThrow(/not found/);
  });
});
