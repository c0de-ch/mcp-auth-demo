/**
 * 06 — negative matrix of design §6.6.
 *
 * Hermetic part: a stub upstream (metadata + fetch spy) proves what the facade validates
 * LOCALLY (client_id, redirect_uri), what it forwards VERBATIM (/register, /token, /revoke),
 * and what its metadata/PRM/401 look like — no Keycloak, no browser, no fixed ports.
 * Keycloak part (skipIf): the same flows against the real realm — DCR passthrough persistence,
 * the documented 500 for a bogus code, mcp-test tokens at /mcp, refresh through the facade.
 */
import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { createHash } from 'node:crypto';
import type { Server } from 'node:http';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationFull, OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import { jsonRpcErrorHandler, notFoundHandler } from '../../src/shared/http.ts';
import { KC, discoverKeycloak, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { runDemo } from '../../src/shared/client/run.ts';
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
  testKeyPair,
  wwwAuthenticate,
  type RawResponse,
  type TestKeyPair,
} from '../../src/shared/testing.ts';
import { buildApp, seededCliClient, type Overrides } from './server.ts';

const keycloakUp = await isKeycloakUp();

// ---------------------------------------------------------------- helpers

interface Facade {
  baseUrl: string;
  mcpUrl: string;
  close(): Promise<void>;
}

/** buildApp() on a known ephemeral port so the facade's advertised URLs equal the dialled ones. */
async function startFacade(overrides: Overrides = {}): Promise<Facade> {
  const port = await freePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  const app = await buildApp({ resourceUrl: `${baseUrl}/mcp`, ...overrides });
  app.use(notFoundHandler);
  app.use(jsonRpcErrorHandler);
  const server = await new Promise<Server>((resolve, reject) => {
    const s = app.listen(port, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  return {
    baseUrl,
    mcpUrl: `${baseUrl}/mcp`,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections?.();
        server.close(() => done());
      }),
  };
}

const form = (url: string, fields: Record<string, string>): Promise<RawResponse> =>
  rawRequest(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

const authorizeQuery = (fields: Record<string, string>) =>
  new URLSearchParams({ response_type: 'code', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', state: 'test-state', ...fields }).toString();

// ---------------------------------------------------------------- hermetic: stub upstream

const UPSTREAM = {
  issuer: 'http://192.0.2.10:8180/realms/mcp',
  authorization_endpoint: 'http://192.0.2.10:8180/realms/mcp/protocol/openid-connect/auth',
  token_endpoint: 'http://192.0.2.10:8180/realms/mcp/protocol/openid-connect/token',
  registration_endpoint: 'http://192.0.2.10:8180/realms/mcp/clients-registrations/openid-connect',
  revocation_endpoint: 'http://192.0.2.10:8180/realms/mcp/protocol/openid-connect/revoke',
  jwks_uri: 'http://192.0.2.10:8180/realms/mcp/protocol/openid-connect/certs',
  response_types_supported: ['code'],
  code_challenge_methods_supported: ['S256'],
} satisfies KeycloakMetadata;

interface UpstreamCall {
  url: string;
  body: string;
}

/** Fake Keycloak for the endpoints the provider dials; every call is recorded. */
function upstreamStub() {
  const calls: UpstreamCall[] = [];
  const json = (status: number, body: unknown) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const fetchFn: FetchLike = async (url, init) => {
    const call: UpstreamCall = { url: String(url), body: typeof init?.body === 'string' ? init.body : '' };
    calls.push(call);
    if (call.url === UPSTREAM.registration_endpoint) {
      const requested = JSON.parse(call.body) as OAuthClientMetadata & { client_name?: string };
      if (requested.client_name === 'reject-me') return json(400, { error: 'invalid_client_metadata' });
      // Echo like Keycloak: request metadata + an upstream-issued id + management fields the
      // SDK's strip-schema must remove (they must never reach the MCP client).
      return json(201, {
        ...requested,
        client_id: `kc-dcr-${calls.length}`,
        client_id_issued_at: 1_700_000_000,
        registration_access_token: 'upstream-management-secret',
        registration_client_uri: `${UPSTREAM.registration_endpoint}/kc-dcr-${calls.length}`,
      });
    }
    if (call.url === UPSTREAM.token_endpoint) {
      const fields = new URLSearchParams(call.body);
      if (fields.get('grant_type') === 'refresh_token' && fields.get('refresh_token') === 'good-refresh') {
        return json(200, { access_token: 'upstream-access', token_type: 'Bearer', expires_in: 900, refresh_token: 'rotated-refresh', scope: 'mcp:tools' });
      }
      return json(400, { error: 'invalid_grant', error_description: 'Code not valid' });
    }
    if (call.url === UPSTREAM.revocation_endpoint) return json(200, {});
    return json(404, { error: 'not_found' });
  };
  return { calls, fetchFn };
}

/** Minimal in-memory OAuthClientProvider: records the authorization URL instead of a browser. */
class RecordingProvider implements OAuthClientProvider {
  authorizationUrl?: URL;
  private info?: OAuthClientInformationMixed;
  private storedTokens?: OAuthTokens;
  private verifier?: string;
  constructor(readonly redirectUrl: string) {}
  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: '06-test-provider',
      redirect_uris: [this.redirectUrl],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
    };
  }
  state = () => 'recording-state';
  clientInformation = () => this.info;
  saveClientInformation = (info: OAuthClientInformationMixed) => void (this.info = info);
  tokens = () => this.storedTokens;
  saveTokens = (tokens: OAuthTokens) => void (this.storedTokens = tokens);
  redirectToAuthorization = (url: URL) => void (this.authorizationUrl = url);
  saveCodeVerifier = (verifier: string) => void (this.verifier = verifier);
  codeVerifier = () => this.verifier ?? '';
}

describe('06-oauth-proxy-keycloak (hermetic, stub upstream)', () => {
  let facade: Facade;
  let keys: TestKeyPair;
  let upstream: ReturnType<typeof upstreamStub>;
  const cli = seededCliClient();
  const registeredRedirect = cli.redirect_uris[1]; // http://127.0.0.1:<OAUTH_CALLBACK_PORT>/callback

  const mint = (claims: Partial<Parameters<typeof mintLocalJwt>[0]> = {}) =>
    mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: UPSTREAM.issuer, audience: KC.audience, ...claims });

  beforeAll(async () => {
    keys = await testKeyPair();
    upstream = upstreamStub();
    facade = await startFacade({ metadata: UPSTREAM, jwks: keys.jwks, fetch: upstream.fetchFn });
  });

  afterAll(async () => {
    await facade?.close();
  });

  it('401 without a token carries resource_metadata but NO scope (SEP-835: the PRM drives scope selection)', async () => {
    const { response } = await initializeSession(facade.mcpUrl);
    expectOAuth401(response, { resourceMetadata: `${facade.baseUrl}/.well-known/oauth-protected-resource/mcp` });
    expect(wwwAuthenticate(response).scope).toBeUndefined();
  });

  it('PRM names the FACADE as the only authorization server', async () => {
    const res = await rawRequest(`${facade.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    expect(res.json()).toEqual({
      resource: facade.mcpUrl,
      authorization_servers: [`${facade.baseUrl}/`],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: '06-oauth-proxy-keycloak',
    });
  });

  it('AS metadata puts every endpoint on the facade origin and never leaks the upstream', async () => {
    const res = await rawRequest(`${facade.baseUrl}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const doc = res.json<Record<string, unknown>>();
    expect(doc.issuer).toBe(`${facade.baseUrl}/`);
    expect(doc.authorization_endpoint).toBe(`${facade.baseUrl}/authorize`);
    expect(doc.token_endpoint).toBe(`${facade.baseUrl}/token`);
    expect(doc.registration_endpoint).toBe(`${facade.baseUrl}/register`);
    expect(doc.revocation_endpoint).toBe(`${facade.baseUrl}/revoke`);
    expect(doc.token_endpoint_auth_methods_supported).toEqual(['client_secret_post', 'none']);
    expect(doc.code_challenge_methods_supported).toEqual(['S256']);
    expect(doc.scopes_supported).toEqual(['mcp:tools', 'mcp:admin']);
    expect(res.text).not.toContain('192.0.2.10'); // Keycloak stays invisible
  });

  it('/authorize with an unknown client_id → 400 invalid_client, nothing sent upstream', async () => {
    const before = upstream.calls.length;
    const res = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: 'unknown', redirect_uri: registeredRedirect })}`);
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: 'invalid_client' });
    expect(upstream.calls.length).toBe(before);
  });

  it('/authorize with an unregistered redirect_uri → 400 invalid_request, nothing sent upstream', async () => {
    const before = upstream.calls.length;
    const res = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: cli.client_id, redirect_uri: 'http://192.0.2.99:4199/callback' })}`);
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: 'invalid_request' });
    expect(upstream.calls.length).toBe(before);
  });

  it('documented sharp edge: a loopback redirect_uri on ANOTHER port passes the local RFC 8252 check (302) — Keycloak would still reject it', async () => {
    const res = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: cli.client_id, redirect_uri: 'http://127.0.0.1:59999/callback' })}`);
    expect(res.status).toBe(302);
    expect(res.headers.location).toMatch(new RegExp(`^${UPSTREAM.authorization_endpoint}`));
  });

  it('/authorize without a code_challenge → error redirect back to the client (never upstream)', async () => {
    const res = await rawRequest(`${facade.baseUrl}/authorize?client_id=${cli.client_id}&response_type=code&redirect_uri=${encodeURIComponent(registeredRedirect)}&state=s1`);
    expect(res.status).toBe(302);
    const location = new URL(res.headers.location as string);
    expect(`${location.origin}${location.pathname}`).toBe(registeredRedirect);
    expect(location.searchParams.get('error')).toBe('invalid_request');
    // SDK detail: when the request itself fails validation, state was never parsed — the error
    // redirect carries none (the CLI's callback listener answers 400 and keeps waiting).
    expect(location.searchParams.get('state')).toBeNull();
  });

  it('valid /authorize → 302 straight to Keycloak with the SAME PKCE parameters and redirect_uri', async () => {
    const res = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: cli.client_id, redirect_uri: registeredRedirect, scope: 'mcp:tools', resource: facade.mcpUrl })}`);
    expect(res.status).toBe(302);
    const target = new URL(res.headers.location as string);
    expect(`${target.origin}${target.pathname}`).toBe(UPSTREAM.authorization_endpoint);
    expect(Object.fromEntries(target.searchParams)).toMatchObject({
      client_id: cli.client_id,
      response_type: 'code',
      redirect_uri: registeredRedirect, // the browser will come back to the CLI, not to the facade
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
      state: 'test-state',
      scope: 'mcp:tools',
      resource: facade.mcpUrl,
    });
  });

  it('/register forwards the metadata verbatim, persists the upstream answer and strips management fields', async () => {
    const metadata: OAuthClientMetadata = {
      client_name: 'hermetic-dcr',
      redirect_uris: ['http://127.0.0.1:4747/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'mcp:tools',
    };
    const res = await rawRequest(`${facade.baseUrl}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(metadata) });
    expect(res.status).toBe(201);
    const registered = res.json<OAuthClientInformationFull>();
    expect(registered.client_id).toMatch(/^kc-dcr-/); // the UPSTREAM issued the id (clientIdGeneration: false)
    expect(res.text).not.toContain('registration_access_token'); // stripped by the SDK schema

    const forwarded = JSON.parse(upstream.calls.at(-1)!.body) as Record<string, unknown>;
    expect(upstream.calls.at(-1)!.url).toBe(UPSTREAM.registration_endpoint);
    expect(forwarded).toMatchObject({ client_name: 'hermetic-dcr', redirect_uris: metadata.redirect_uris, scope: 'mcp:tools' });
    expect(forwarded.client_id).toBeUndefined();
    expect(forwarded.client_secret).toBeUndefined();

    // Without the persisting registerClient wrapper this next request would be invalid_client.
    const authorize = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: registered.client_id, redirect_uri: 'http://127.0.0.1:4747/callback' })}`);
    expect(authorize.status).toBe(302);
    expect(authorize.headers.location).toMatch(new RegExp(`^${UPSTREAM.authorization_endpoint}`));
  });

  it('/register upstream failure surfaces as an opaque 500 server_error (documented SDK behaviour)', async () => {
    const res = await rawRequest(`${facade.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ client_name: 'reject-me', redirect_uris: ['http://127.0.0.1:4747/callback'], token_endpoint_auth_method: 'none' }),
    });
    expect(res.status).toBe(500);
    expect(res.json()).toEqual({ error: 'server_error', error_description: 'Client registration failed: 400' });
  });

  it('/token with a bogus code → 500 server_error "Token exchange failed: 400" (upstream error body is swallowed)', async () => {
    const res = await form(`${facade.baseUrl}/token`, { grant_type: 'authorization_code', client_id: cli.client_id, code: 'bogus', code_verifier: 'a'.repeat(43), redirect_uri: registeredRedirect });
    expect(res.status).toBe(500);
    expect(res.json()).toEqual({ error: 'server_error', error_description: 'Token exchange failed: 400' });
    const fields = new URLSearchParams(upstream.calls.at(-1)!.body);
    expect(upstream.calls.at(-1)!.url).toBe(UPSTREAM.token_endpoint);
    expect(fields.get('code_verifier')).toBe('a'.repeat(43)); // PKCE is verified UPSTREAM only
  });

  it('/token for an unknown client → 400 invalid_client, nothing sent upstream', async () => {
    const before = upstream.calls.length;
    const res = await form(`${facade.baseUrl}/token`, { grant_type: 'authorization_code', client_id: 'unknown', code: 'x', code_verifier: 'y'.repeat(43) });
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: 'invalid_client' });
    expect(upstream.calls.length).toBe(before);
  });

  it('/token refuses client_credentials — the facade only proxies the code and refresh grants', async () => {
    const res = await form(`${facade.baseUrl}/token`, { grant_type: 'client_credentials', client_id: cli.client_id });
    expect(res.status).toBe(400);
    expect(res.json()).toMatchObject({ error: 'unsupported_grant_type' });
  });

  it('refresh passthrough: grant_type=refresh_token form → upstream tokens verbatim', async () => {
    const res = await form(`${facade.baseUrl}/token`, { grant_type: 'refresh_token', client_id: cli.client_id, refresh_token: 'good-refresh' });
    expect(res.status).toBe(200);
    expect(res.json()).toMatchObject({ access_token: 'upstream-access', refresh_token: 'rotated-refresh', token_type: 'Bearer' });
    const fields = new URLSearchParams(upstream.calls.at(-1)!.body);
    expect(fields.get('client_id')).toBe(cli.client_id);
  });

  it('revocation passthrough: /revoke forwards token + client_id to Keycloak', async () => {
    const res = await form(`${facade.baseUrl}/revoke`, { client_id: cli.client_id, token: 'whatever-token' });
    expect(res.status).toBe(200);
    const last = upstream.calls.at(-1)!;
    expect(last.url).toBe(UPSTREAM.revocation_endpoint);
    expect(new URLSearchParams(last.body).get('token')).toBe('whatever-token');
  });

  it('accepts a valid upstream-issued JWT at /mcp; roles gate mcp:admin (alice denied, bob ok)', async () => {
    const alice = await mint({ sub: 'alice-id', username: 'alice', scope: 'mcp:tools mcp:admin', roles: ['mcp-user'] });
    const session = await initializeSession(facade.mcpUrl, bearer(alice));
    expect(session.response.status).toBe(200);
    const whoami = await rawCallTool(facade.mcpUrl, session.sessionId!, 'whoami', {}, bearer(alice));
    const identity = JSON.parse((whoami.result!.content as Array<{ text: string }>)[0].text) as { scopes: string[]; extra: { username: string } };
    expect(identity.extra.username).toBe('alice');
    expect(identity.scopes).toEqual(['mcp:tools']); // mcp:admin dropped: no mcp-admin role
    const denied = await rawCallTool(facade.mcpUrl, session.sessionId!, 'admin_only', {}, bearer(alice));
    expect(denied.result?.isError).toBe(true);

    const bob = await mint({ sub: 'bob-id', username: 'bob', scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] });
    const bobSession = await initializeSession(facade.mcpUrl, bearer(bob));
    const ok = await rawCallTool(facade.mcpUrl, bobSession.sessionId!, 'admin_only', {}, bearer(bob));
    expect(ok.result?.isError).toBeFalsy();

    // Session ↔ subject binding: bob's valid token cannot ride alice's session.
    const foreign = await rawCallTool(facade.mcpUrl, session.sessionId!, 'whoami', {}, bearer(bob));
    expect(foreign.response.status).toBe(403);
  });

  it.each([
    ['wrong audience', { audience: 'account' }, 'wrong audience'],
    ['wrong issuer', { issuer: 'http://192.0.2.11:8180/realms/other' }, 'wrong issuer'],
    ['expired', { expiresIn: '-1h' }, 'token expired'],
  ] as const)('rejects a token with %s → 401', async (_name, claims, reason) => {
    const token = await mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: UPSTREAM.issuer, audience: KC.audience, ...claims });
    const { response } = await initializeSession(facade.mcpUrl, bearer(token));
    expect(response.status).toBe(401);
    expect(wwwAuthenticate(response).error_description).toBe(`JWT rejected: ${reason}`);
  });

  it('rejects a tampered token → 401 bad signature', async () => {
    const token = await mint({});
    const [h, p, s] = token.split('.');
    const { response } = await initializeSession(facade.mcpUrl, bearer(`${h}.${p}.${s.slice(0, -4)}AAAA`));
    expect(response.status).toBe(401);
  });

  it('a token without mcp:tools → 403 insufficient_scope with the static description and no scope= parameter', async () => {
    const token = await mint({ scope: 'profile email' });
    const { response } = await initializeSession(facade.mcpUrl, bearer(token));
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.error_description).toBe('missing scope: mcp:tools');
    expect(challenge.scope).toBeUndefined();
    expect(challenge.resource_metadata).toBe(`${facade.baseUrl}/.well-known/oauth-protected-resource/mcp`);
  });

  it('SDK client end-to-end: discovery → DCR via the facade → authorization URL ON the facade → 302 to Keycloak', async () => {
    const provider = new RecordingProvider(`http://127.0.0.1:${await freePort()}/callback`); // never bound
    await expect(connectClient(facade.mcpUrl, { authProvider: provider })).rejects.toThrow(UnauthorizedError);

    // What the facade forwarded upstream on DCR: the SEP-835 scope from the PRM, no client_id.
    const dcr = JSON.parse(upstream.calls.findLast((c) => c.url === UPSTREAM.registration_endpoint)!.body) as Record<string, unknown>;
    expect(dcr.scope).toBe('mcp:tools mcp:admin');
    expect(dcr.client_id).toBeUndefined();

    // The client was pointed at the FACADE's /authorize…
    const authorizationUrl = provider.authorizationUrl!;
    expect(authorizationUrl.origin).toBe(facade.baseUrl);
    expect(authorizationUrl.pathname).toBe('/authorize');
    expect(authorizationUrl.searchParams.get('client_id')).toMatch(/^kc-dcr-/);
    expect(authorizationUrl.searchParams.get('scope')).toBe('mcp:tools mcp:admin');
    expect(authorizationUrl.searchParams.get('resource')).toBe(facade.mcpUrl);

    // …which relays the browser to Keycloak with the client's own PKCE challenge.
    const relay = await rawRequest(authorizationUrl.href);
    expect(relay.status).toBe(302);
    const target = new URL(relay.headers.location as string);
    expect(`${target.origin}${target.pathname}`).toBe(UPSTREAM.authorization_endpoint);
    expect(target.searchParams.get('code_challenge')).toBe(createHash('sha256').update(provider.codeVerifier()).digest('base64url'));
    expect(target.searchParams.get('redirect_uri')).toBe(provider.redirectUrl);
  });
});

// ---------------------------------------------------------------- against the real Keycloak

describe.skipIf(!keycloakUp)('06-oauth-proxy-keycloak against Keycloak', () => {
  let facade: Facade;
  let metadata: KeycloakMetadata;
  const upstreamCalls: UpstreamCall[] = [];
  const spyFetch: FetchLike = async (url, init) => {
    upstreamCalls.push({ url: String(url), body: typeof init?.body === 'string' ? init.body : '' });
    return fetch(url, init);
  };

  beforeAll(async () => {
    metadata = await discoverKeycloak();
    // mcp-test is seeded so the refresh test has a client whose refresh tokens exist without a
    // browser (password grant, TEST ONLY); the realm's mcp-cli is always seeded by default.
    facade = await startFacade({ metadata, fetch: spyFetch, clients: [{ client_id: KC.clients.test, redirect_uris: [], token_endpoint_auth_method: 'none' }] });
  });

  afterAll(async () => {
    await facade?.close();
  });

  it('/register is a real Keycloak DCR: upstream client_id, persisted, /authorize relays to Keycloak', async () => {
    const res = await rawRequest(`${facade.baseUrl}/register`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        client_name: '06-proxy-test-client',
        redirect_uris: ['http://127.0.0.1:4747/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope: 'mcp:tools',
      }),
    });
    expect(res.status).toBe(201);
    const registered = res.json<OAuthClientInformationFull>();
    expect(registered.client_id).toBeDefined();
    expect(registered.client_id).not.toBe('06-proxy-test-client');
    expect(res.text).not.toContain('registration_access_token'); // Keycloak sends one; the facade strips it
    expect(upstreamCalls.some((c) => c.url === metadata.registration_endpoint)).toBe(true);

    const authorize = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: registered.client_id, redirect_uri: 'http://127.0.0.1:4747/callback', scope: 'mcp:tools' })}`);
    expect(authorize.status).toBe(302);
    expect(authorize.headers.location).toMatch(new RegExp(`^${metadata.authorization_endpoint}`));
    expect(new URL(authorize.headers.location as string).searchParams.get('client_id')).toBe(registered.client_id);
  });

  it('/authorize with an unknown client or a foreign redirect_uri fails locally — Keycloak sees nothing', async () => {
    const before = upstreamCalls.length;
    const unknown = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: 'no-such-client', redirect_uri: 'http://127.0.0.1:4747/callback' })}`);
    expect(unknown.status).toBe(400);
    expect(unknown.json()).toMatchObject({ error: 'invalid_client' });
    const foreign = await rawRequest(`${facade.baseUrl}/authorize?${authorizeQuery({ client_id: KC.clients.cli, redirect_uri: 'http://192.0.2.99:4199/callback' })}`);
    expect(foreign.status).toBe(400);
    expect(foreign.json()).toMatchObject({ error: 'invalid_request' });
    expect(upstreamCalls.length).toBe(before);
  });

  it('/token with a bogus code → Keycloak 400 becomes the documented 500 server_error', async () => {
    const res = await form(`${facade.baseUrl}/token`, {
      grant_type: 'authorization_code',
      client_id: KC.clients.cli,
      code: 'bogus-code',
      code_verifier: 'b'.repeat(43),
      redirect_uri: seededCliClient().redirect_uris[1],
    });
    expect(res.status).toBe(500);
    expect(res.json()).toEqual({ error: 'server_error', error_description: 'Token exchange failed: 400' });
  });

  it('accepts real Keycloak tokens at /mcp: alice (no role) denied admin, bob ok', async () => {
    const alice = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools mcp:admin' });
    const session = await connectClient(facade.mcpUrl, { headers: bearer(alice.access_token) });
    try {
      const result = await runDemo(session.client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: KC.clients.test, extra: { username: 'alice', roles: ['mcp-user'] } });
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await session.close();
    }

    const bob = await keycloakPasswordToken({ username: 'bob', password: 'password', scope: 'mcp:tools mcp:admin' });
    const bobSession = await connectClient(facade.mcpUrl, { headers: bearer(bob.access_token) });
    try {
      const result = await runDemo(bobSession.client, { print: () => undefined });
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await bobSession.close();
    }
  });

  it('refresh through the facade: a real refresh token is exchanged upstream and the new token works at /mcp', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password', scope: 'mcp:tools' });
    const res = await form(`${facade.baseUrl}/token`, { grant_type: 'refresh_token', client_id: KC.clients.test, refresh_token: tokens.refresh_token! });
    expect(res.status).toBe(200);
    const refreshed = res.json<OAuthTokens>();
    expect(refreshed.access_token).toBeDefined();
    expect(refreshed.access_token).not.toBe(tokens.access_token);
    const { response } = await initializeSession(facade.mcpUrl, bearer(refreshed.access_token));
    expect(response.status).toBe(200);
  });

  it('401 without a token points discovery at the facade PRM', async () => {
    const { response } = await initializeSession(facade.mcpUrl);
    expectOAuth401(response, { resourceMetadata: `${facade.baseUrl}/.well-known/oauth-protected-resource/mcp` });
    const prm = await rawRequest(`${facade.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(prm.json<{ authorization_servers: string[] }>().authorization_servers).toEqual([`${facade.baseUrl}/`]);
  });
});
