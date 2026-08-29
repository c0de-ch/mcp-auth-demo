/**
 * 03 — vitest matrix for the embedded authorization server (design §6.3).
 *
 * Everything here is hermetic: the app listens on an ephemeral 127.0.0.1 port whose origin is
 * injected as issuer/resource, the "browser" is plain fetch with redirect:'manual', and no
 * loopback callback port is ever bound (the registered redirect URI points at port 9 / discard —
 * codes are read from the Location header, never delivered). MCP_RATE_LIMIT=0 comes from
 * vitest.config.ts; the one rate-limit test builds its own app with limits forced on.
 */
import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { createHash, randomBytes } from 'node:crypto';
import type { Server } from 'node:http';
import type { Express } from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { jsonRpcErrorHandler, notFoundHandler } from '../../src/shared/http.ts';
import { connectClient, expectOAuth401, freePort, initializeSession, rawCallTool, wwwAuthenticate } from '../../src/shared/testing.ts';
import { runDemo } from '../../src/shared/client/run.ts';
import { DemoAuthorizationServer, type DemoAuthorizationServerOptions } from './provider.ts';
import { buildApp } from './server.ts';

/** Registered for mcp-cli via loopback port relaxation; port 9 (discard) is never dialled. */
const REDIRECT = 'http://127.0.0.1:9/callback';

// ---------------------------------------------------------------- harness

interface As {
  origin: string;
  mcpUrl: string;
  provider: DemoAuthorizationServer;
  close(): Promise<void>;
}

/** buildApp() needs the origin before listen(), so reserve a port first (design §4.3 variant). */
async function startAs(opts: { rateLimit?: boolean; ttls?: Partial<DemoAuthorizationServerOptions> } = {}): Promise<As> {
  const port = await freePort();
  const origin = `http://127.0.0.1:${port}`;
  const provider = new DemoAuthorizationServer({ resource: `${origin}/mcp`, ...opts.ttls });
  const app = buildApp({ origin, provider, rateLimit: opts.rateLimit });
  app.use(notFoundHandler);
  app.use(jsonRpcErrorHandler);
  const server = await new Promise<Server>((resolve, reject) => {
    const s = (app as Express).listen(port, '127.0.0.1', () => resolve(s));
    s.on('error', reject);
  });
  return {
    origin,
    mcpUrl: `${origin}/mcp`,
    provider,
    close: () =>
      new Promise<void>((done) => {
        server.closeAllConnections?.();
        server.close(() => done());
      }),
  };
}

interface Browsed {
  status: number;
  location?: string;
  text: string;
  headers: Headers;
}

/** One "browser" request: never follows redirects, returns the Location for the test to judge. */
async function req(url: string, init: RequestInit = {}): Promise<Browsed> {
  const res = await fetch(url, { redirect: 'manual', ...init });
  return { status: res.status, location: res.headers.get('location') ?? undefined, text: await res.text(), headers: res.headers };
}

const postForm = (url: string, fields: Record<string, string>) =>
  req(url, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields).toString() });

/** Value of a hidden form input (pages.ts renders name="…" value="…" in this order). */
const input = (html: string, name: string): string | undefined => html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1];

const pkce = () => {
  const verifier = randomBytes(32).toString('base64url');
  return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
};

interface FlowOptions {
  clientId?: string;
  redirectUri?: string;
  scope?: string;
  state?: string;
  resource?: string;
  user?: string;
  password?: string;
  decision?: 'accept' | 'cancel';
  challenge: string;
}

const authorizeUrl = (origin: string, o: FlowOptions): string => {
  const q = new URLSearchParams({
    response_type: 'code',
    client_id: o.clientId ?? 'mcp-cli',
    redirect_uri: o.redirectUri ?? REDIRECT,
    scope: o.scope ?? 'mcp:tools mcp:admin',
    state: o.state ?? 'test-state',
    code_challenge: o.challenge,
    code_challenge_method: 'S256',
  });
  if (o.resource) q.set('resource', o.resource);
  return `${origin}/authorize?${q.toString()}`;
};

/** Scripted login + consent: what browser-login.py does headlessly, here with fetch. */
async function browserFlow(origin: string, o: FlowOptions) {
  const authz = await req(authorizeUrl(origin, o));
  expect(authz.status).toBe(302);
  expect(authz.location).toMatch(/^\/login\?txn=/);
  const login = await req(`${origin}${authz.location}`);
  expect(login.status).toBe(200);
  const txn = input(login.text, 'txn')!;
  const csrf = input(login.text, 'csrf')!;
  const authed = await postForm(`${origin}/login`, { txn, csrf, username: o.user ?? 'alice', password: o.password ?? 'password' });
  expect(authed.status).toBe(303);
  const consent = await req(`${origin}${authed.location}`);
  expect(consent.status).toBe(200);
  const decided = await postForm(`${origin}/consent`, { txn, csrf, [o.decision === 'cancel' ? 'cancel' : 'accept']: '1' });
  expect(decided.status).toBe(302);
  const callback = new URL(decided.location!);
  return {
    consentHtml: consent.text,
    location: decided.location!,
    code: callback.searchParams.get('code') ?? undefined,
    state: callback.searchParams.get('state') ?? undefined,
    error: callback.searchParams.get('error') ?? undefined,
  };
}

async function tokenRequest(origin: string, fields: Record<string, string>) {
  const res = await postForm(`${origin}/token`, fields);
  return { status: res.status, body: JSON.parse(res.text) as OAuthTokens & { error?: string; error_description?: string } };
}

/** Whole happy path: authorize (browser scripted) + PKCE code exchange → tokens. */
async function obtainTokens(origin: string, o: Omit<FlowOptions, 'challenge'> = {}) {
  const { verifier, challenge } = pkce();
  const flow = await browserFlow(origin, { ...o, challenge });
  expect(flow.code).toBeDefined();
  const { status, body } = await tokenRequest(origin, {
    grant_type: 'authorization_code',
    code: flow.code!,
    code_verifier: verifier,
    redirect_uri: o.redirectUri ?? REDIRECT,
    client_id: o.clientId ?? 'mcp-cli',
  });
  expect(status).toBe(200);
  return body;
}

async function registerClient(origin: string, metadata: Record<string, unknown>) {
  const res = await req(`${origin}/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(metadata) });
  return { status: res.status, body: JSON.parse(res.text) as Record<string, unknown> };
}

const whoamiOf = async (mcpUrl: string, accessToken: string) => {
  const { client, close } = await connectClient(mcpUrl, { headers: { authorization: `Bearer ${accessToken}` } });
  try {
    return await runDemo(client, { print: () => undefined });
  } finally {
    await close();
  }
};

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- the matrix

let as: As;

beforeAll(async () => {
  process.env.MCP_LOG = '0'; // keep the request log out of the vitest output (forked worker only)
  as = await startAs();
});

afterAll(async () => {
  await as.close();
});

describe('metadata documents and the 401 challenge', () => {
  it('serves RFC 8414 AS metadata with S256, client_secret_post/none, register + revoke', async () => {
    const res = await fetch(`${as.origin}/.well-known/oauth-authorization-server`);
    expect(res.status).toBe(200);
    const meta = (await res.json()) as Record<string, unknown>;
    expect(meta.issuer).toBe(`${as.origin}/`);
    expect(meta.authorization_endpoint).toBe(`${as.origin}/authorize`);
    expect(meta.token_endpoint).toBe(`${as.origin}/token`);
    expect(meta.registration_endpoint).toBe(`${as.origin}/register`);
    expect(meta.revocation_endpoint).toBe(`${as.origin}/revoke`);
    expect(meta.code_challenge_methods_supported).toEqual(['S256']);
    expect(meta.token_endpoint_auth_methods_supported).toEqual(['client_secret_post', 'none']);
    expect(meta.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(meta.scopes_supported).toEqual(['mcp:tools', 'mcp:admin']);
  });

  it('serves RFC 9728 protected-resource metadata naming itself as the AS', async () => {
    const res = await fetch(`${as.origin}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    const prm = (await res.json()) as Record<string, unknown>;
    expect(prm.resource).toBe(as.mcpUrl);
    expect(prm.authorization_servers).toEqual([`${as.origin}/`]);
    expect(prm.scopes_supported).toEqual(['mcp:tools', 'mcp:admin']);
    expect(prm.resource_name).toBe('03-oauth-embedded-as');
  });

  it('401 on /mcp carries resource_metadata but pins no scope (SEP-835: the PRM list drives clients)', async () => {
    const { response } = await initializeSession(as.mcpUrl);
    expectOAuth401(response, { resourceMetadata: `${as.origin}/.well-known/oauth-protected-resource/mcp` });
    expect(wwwAuthenticate(response).scope).toBeUndefined();
  });
});

describe('/authorize validation', () => {
  it('rejects an unregistered redirect_uri with a 400 JSON error, never a redirect', async () => {
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, redirectUri: 'http://evil.example/callback' }));
    expect(res.status).toBe(400);
    expect(res.location).toBeUndefined();
    expect(JSON.parse(res.text).error).toBe('invalid_request');
  });

  it('relaxes the PORT of a loopback redirect_uri (RFC 8252 §7.3)', async () => {
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, redirectUri: 'http://127.0.0.1:55555/callback' }));
    expect(res.status).toBe(302);
    expect(res.location).toMatch(/^\/login\?txn=/);
  });

  it('does NOT cross-match localhost and 127.0.0.1', async () => {
    const { body } = await registerClient(as.origin, {
      client_name: 'loopback-strict',
      redirect_uris: ['http://127.0.0.1:9/callback'],
      token_endpoint_auth_method: 'none',
    });
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, clientId: body.client_id as string, redirectUri: 'http://localhost:9/callback' }));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.text).error).toBe('invalid_request');
  });

  it('rejects an unknown client_id with 400 invalid_client', async () => {
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, clientId: 'ghost' }));
    expect(res.status).toBe(400);
    expect(JSON.parse(res.text).error).toBe('invalid_client');
  });

  it('redirects code_challenge_method=plain back to the client as an error (PKCE S256 is mandatory)', async () => {
    const url = authorizeUrl(as.origin, { challenge: 'plain-value' }).replace('code_challenge_method=S256', 'code_challenge_method=plain');
    const res = await req(url);
    expect(res.status).toBe(302);
    const redirected = new URL(res.location!);
    expect(redirected.origin + redirected.pathname).toBe(REDIRECT);
    expect(redirected.searchParams.get('error')).toBe('invalid_request');
    // Note: the SDK omits `state` here — it validates all Phase-2 params (state included) in one
    // zod parse, so a code_challenge_method failure never gets as far as extracting the state.
    expect(redirected.searchParams.get('state')).toBeNull();
  });

  it('redirects a scope outside scopes_supported as error=invalid_scope', async () => {
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, scope: 'mcp:tools payments:write' }));
    expect(res.status).toBe(302);
    expect(new URL(res.location!).searchParams.get('error')).toBe('invalid_scope');
  });

  it('redirects a foreign RFC 8707 resource as error=invalid_target', async () => {
    const res = await req(authorizeUrl(as.origin, { challenge: pkce().challenge, resource: 'http://192.0.2.7:9999/mcp' }));
    expect(res.status).toBe(302);
    expect(new URL(res.location!).searchParams.get('error')).toBe('invalid_target');
  });
});

describe('login and consent pages', () => {
  it('a wrong password re-renders the login with an error and no code; the retry still works', async () => {
    const { challenge } = pkce();
    const authz = await req(authorizeUrl(as.origin, { challenge }));
    const login = await req(`${as.origin}${authz.location}`);
    const txn = input(login.text, 'txn')!;
    const csrf = input(login.text, 'csrf')!;
    const wrong = await postForm(`${as.origin}/login`, { txn, csrf, username: 'alice', password: 'wrong' });
    expect(wrong.status).toBe(401);
    expect(wrong.location).toBeUndefined();
    expect(wrong.text).toContain('id="input-error"');
    const right = await postForm(`${as.origin}/login`, { txn, csrf, username: 'alice', password: 'password' });
    expect(right.status).toBe(303);
  });

  it('rejects a missing or wrong csrf on POST /login with 400', async () => {
    const authz = await req(authorizeUrl(as.origin, { challenge: pkce().challenge }));
    const login = await req(`${as.origin}${authz.location}`);
    const txn = input(login.text, 'txn')!;
    const res = await postForm(`${as.origin}/login`, { txn, csrf: 'forged', username: 'alice', password: 'password' });
    expect(res.status).toBe(400);
  });

  it('rejects a wrong csrf on POST /consent with 400 and issues no code', async () => {
    const { challenge } = pkce();
    const authz = await req(authorizeUrl(as.origin, { challenge }));
    const login = await req(`${as.origin}${authz.location}`);
    const txn = input(login.text, 'txn')!;
    const csrf = input(login.text, 'csrf')!;
    await postForm(`${as.origin}/login`, { txn, csrf, username: 'alice', password: 'password' });
    const forged = await postForm(`${as.origin}/consent`, { txn, csrf: 'forged', accept: '1' });
    expect(forged.status).toBe(400);
    expect(forged.location).toBeUndefined();
    const real = await postForm(`${as.origin}/consent`, { txn, csrf, accept: '1' }); // txn survived the forgery
    expect(real.status).toBe(302);
    expect(new URL(real.location!).searchParams.get('code')).toBeTruthy();
  });

  it('answers 400 for an unknown or expired transaction', async () => {
    expect((await req(`${as.origin}/login?txn=ffffffff`)).status).toBe(400);
    expect((await req(`${as.origin}/login`)).status).toBe(400);
    expect((await req(`${as.origin}/consent?txn=ffffffff`)).status).toBe(400);
  });

  it('sends /consent back to /login when nobody is signed in yet', async () => {
    const authz = await req(authorizeUrl(as.origin, { challenge: pkce().challenge }));
    const txn = new URL(`${as.origin}${authz.location}`).searchParams.get('txn')!;
    const res = await req(`${as.origin}/consent?txn=${txn}`);
    expect(res.status).toBe(303);
    expect(res.location).toBe(`/login?txn=${txn}`);
  });

  it('denying consent redirects with error=access_denied and the state', async () => {
    const flow = await browserFlow(as.origin, { challenge: pkce().challenge, state: 'deny-state', decision: 'cancel' });
    expect(flow.code).toBeUndefined();
    expect(flow.error).toBe('access_denied');
    expect(flow.state).toBe('deny-state');
  });

  it("shows alice that mcp:admin will NOT be granted, and escapes DCR'd client names (XSS)", async () => {
    const { body } = await registerClient(as.origin, {
      client_name: '<script>alert(1)</script>',
      redirect_uris: ['http://127.0.0.1:9/callback'],
      token_endpoint_auth_method: 'none',
    });
    const flow = await browserFlow(as.origin, { challenge: pkce().challenge, clientId: body.client_id as string, user: 'alice' });
    expect(flow.consentHtml).toContain('not available for this account');
    expect(flow.consentHtml).toContain('&lt;script&gt;');
    expect(flow.consentHtml).not.toContain('<script>alert');
    expect(flow.consentHtml).toContain('127.0.0.1:9/callback'); // the human sees where the browser will go
  });
});

describe('token endpoint: authorization_code + PKCE', () => {
  it('completes the full flow for alice: narrowed scope, tools yes, admin no', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'alice', state: 'alice-state' });
    expect(tokens.token_type).toBe('Bearer');
    expect(tokens.expires_in).toBe(900);
    expect(tokens.refresh_token).toBeDefined();
    expect(tokens.scope).toBe('mcp:tools'); // requested mcp:tools mcp:admin; alice may only grant mcp:tools
    const demo = await whoamiOf(as.mcpUrl, tokens.access_token);
    const whoami = demo.whoami.json as { clientId?: string; scopes?: string[]; extra?: { sub?: string } };
    expect(whoami.extra?.sub).toBe('alice');
    expect(whoami.clientId).toBe('mcp-cli');
    expect(whoami.scopes).toEqual(['mcp:tools']);
    expect(demo.adminOnly.isError).toBe(true);
  });

  it('grants bob mcp:admin — the consent page offered it and admin_only succeeds', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'bob' });
    expect(tokens.scope).toBe('mcp:tools mcp:admin');
    const demo = await whoamiOf(as.mcpUrl, tokens.access_token);
    expect((demo.whoami.json as { extra?: { sub?: string } }).extra?.sub).toBe('bob');
    expect(demo.adminOnly.isError).toBe(false);
  });

  it('rejects a wrong code_verifier with invalid_grant', async () => {
    const { challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge });
    const { status, body } = await tokenRequest(as.origin, {
      grant_type: 'authorization_code',
      code: flow.code!,
      code_verifier: 'not-the-right-verifier-at-all-0000000000000000',
      redirect_uri: REDIRECT,
      client_id: 'mcp-cli',
    });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_grant');
  });

  it('rejects a redirect_uri that differs from the authorization request', async () => {
    const { verifier, challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge });
    const { status, body } = await tokenRequest(as.origin, {
      grant_type: 'authorization_code',
      code: flow.code!,
      code_verifier: verifier,
      redirect_uri: 'http://127.0.0.1:10/callback',
      client_id: 'mcp-cli',
    });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_grant');
  });

  it('rejects a code presented by a different client — without burning the code', async () => {
    const { body: other } = await registerClient(as.origin, { client_name: 'thief', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    const { verifier, challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge });
    const stolen = await tokenRequest(as.origin, {
      grant_type: 'authorization_code',
      code: flow.code!,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
      client_id: other.client_id as string,
    });
    expect(stolen.status).toBe(400);
    expect(stolen.body.error).toBe('invalid_grant');
    const legit = await tokenRequest(as.origin, {
      grant_type: 'authorization_code',
      code: flow.code!,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
      client_id: 'mcp-cli',
    });
    expect(legit.status).toBe(200);
  });

  it('code REUSE answers invalid_grant and revokes every token issued from that code', async () => {
    const { verifier, challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge });
    const first = await tokenRequest(as.origin, { grant_type: 'authorization_code', code: flow.code!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: 'mcp-cli' });
    expect(first.status).toBe(200);
    expect((await initializeSession(as.mcpUrl, { authorization: `Bearer ${first.body.access_token}` })).response.status).toBe(200);
    const replay = await tokenRequest(as.origin, { grant_type: 'authorization_code', code: flow.code!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: 'mcp-cli' });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
    // OAuth 2.1 §4.1.2: the tokens from the first, legitimate exchange are gone now.
    const afterwards = await initializeSession(as.mcpUrl, { authorization: `Bearer ${first.body.access_token}` });
    expectOAuth401(afterwards.response);
    const refreshAfter = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: first.body.refresh_token!, client_id: 'mcp-cli' });
    expect(refreshAfter.status).toBe(400);
    expect(refreshAfter.body.error).toBe('invalid_grant');
  });

  it('rejects a token-request resource that differs from the code binding (invalid_target)', async () => {
    const { verifier, challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge, resource: as.mcpUrl });
    const { status, body } = await tokenRequest(as.origin, {
      grant_type: 'authorization_code',
      code: flow.code!,
      code_verifier: verifier,
      redirect_uri: REDIRECT,
      client_id: 'mcp-cli',
      resource: 'http://192.0.2.7:9999/mcp',
    });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_target');
  });

  it('does not serve client_credentials (embedded-AS limitation, documented)', async () => {
    const { status, body } = await tokenRequest(as.origin, { grant_type: 'client_credentials', client_id: 'mcp-cli' });
    expect(status).toBe(400);
    expect(body.error).toBe('unsupported_grant_type');
  });
});

describe('refresh-token rotation', () => {
  it('rotates on every use; replaying a rotated token revokes the whole family', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'bob' });
    const refreshed = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'mcp-cli' });
    expect(refreshed.status).toBe(200);
    expect(refreshed.body.refresh_token).not.toBe(tokens.refresh_token);
    expect(refreshed.body.scope).toBe('mcp:tools mcp:admin');
    // Replay of the OLD refresh token → theft signal → the freshly issued tokens die too.
    const replay = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'mcp-cli' });
    expect(replay.status).toBe(400);
    expect(replay.body.error).toBe('invalid_grant');
    expectOAuth401((await initializeSession(as.mcpUrl, { authorization: `Bearer ${refreshed.body.access_token}` })).response);
    const rotatedReplay = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: refreshed.body.refresh_token!, client_id: 'mcp-cli' });
    expect(rotatedReplay.status).toBe(400);
  });

  it('rejects a refresh token presented by another client_id (and keeps it valid for the owner)', async () => {
    const { body: other } = await registerClient(as.origin, { client_name: 'other', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    const tokens = await obtainTokens(as.origin, { user: 'alice' });
    const foreign = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: other.client_id as string });
    expect(foreign.status).toBe(400);
    expect(foreign.body.error).toBe('invalid_grant');
    const own = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'mcp-cli' });
    expect(own.status).toBe(200);
  });

  it('lets the scope narrow on refresh but never widen', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'bob' });
    const narrowed = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, scope: 'mcp:tools', client_id: 'mcp-cli' });
    expect(narrowed.status).toBe(200);
    expect(narrowed.body.scope).toBe('mcp:tools');
    expect((await whoamiOf(as.mcpUrl, narrowed.body.access_token)).adminOnly.isError).toBe(true);
    const widened = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: narrowed.body.refresh_token!, scope: 'mcp:tools mcp:admin', client_id: 'mcp-cli' });
    expect(widened.status).toBe(400);
    expect(widened.body.error).toBe('invalid_scope');
  });
});

describe('revocation (RFC 7009)', () => {
  it('revoking an access token turns the next /mcp request into a 401', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'alice' });
    const res = await postForm(`${as.origin}/revoke`, { token: tokens.access_token, client_id: 'mcp-cli' });
    expect(res.status).toBe(200);
    expectOAuth401((await initializeSession(as.mcpUrl, { authorization: `Bearer ${tokens.access_token}` })).response);
  });

  it('revoking a refresh token kills its whole family (access token included)', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'alice' });
    await postForm(`${as.origin}/revoke`, { token: tokens.refresh_token!, client_id: 'mcp-cli' });
    expectOAuth401((await initializeSession(as.mcpUrl, { authorization: `Bearer ${tokens.access_token}` })).response);
    const refresh = await tokenRequest(as.origin, { grant_type: 'refresh_token', refresh_token: tokens.refresh_token!, client_id: 'mcp-cli' });
    expect(refresh.status).toBe(400);
  });

  it("answers 200 for another client's token but does not revoke it", async () => {
    const { body: other } = await registerClient(as.origin, { client_name: 'other-revoker', redirect_uris: [REDIRECT], token_endpoint_auth_method: 'none' });
    const tokens = await obtainTokens(as.origin, { user: 'alice' });
    const res = await postForm(`${as.origin}/revoke`, { token: tokens.access_token, client_id: other.client_id as string });
    expect(res.status).toBe(200); // reveal nothing
    expect((await initializeSession(as.mcpUrl, { authorization: `Bearer ${tokens.access_token}` })).response.status).toBe(200);
  });
});

describe('dynamic client registration (RFC 7591)', () => {
  it('registers a public client with 201 and NO client_secret; it can authorize right away', async () => {
    const { status, body } = await registerClient(as.origin, {
      client_name: 'fresh public client',
      redirect_uris: ['http://127.0.0.1:9/callback'],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: 'mcp:tools mcp:admin',
    });
    expect(status).toBe(201);
    expect(body.client_id).toMatch(/[0-9a-f-]{36}/);
    expect(body.client_secret).toBeUndefined();
    const tokens = await obtainTokens(as.origin, { clientId: body.client_id as string, user: 'alice' });
    expect((await whoamiOf(as.mcpUrl, tokens.access_token)).whoami.text).toContain((body.client_id as string).slice(0, 8));
  });

  it('registers a confidential client with a never-expiring secret and enforces it at /token', async () => {
    const { status, body } = await registerClient(as.origin, {
      client_name: 'confidential client',
      redirect_uris: [REDIRECT],
      token_endpoint_auth_method: 'client_secret_post',
    });
    expect(status).toBe(201);
    expect(body.client_secret).toBeDefined();
    expect(body.client_secret_expires_at).toBe(0); // clientSecretExpirySeconds: 0
    const { verifier, challenge } = pkce();
    const flow = await browserFlow(as.origin, { challenge, clientId: body.client_id as string });
    const bare = await tokenRequest(as.origin, { grant_type: 'authorization_code', code: flow.code!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: body.client_id as string });
    expect(bare.status).toBe(400);
    expect(bare.body.error).toBe('invalid_client'); // client_secret_post means: secret in the form body
    const authed = await tokenRequest(as.origin, { grant_type: 'authorization_code', code: flow.code!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: body.client_id as string, client_secret: body.client_secret as string });
    expect(authed.status).toBe(200);
  });

  it('rejects dangerous redirect URI schemes with invalid_client_metadata', async () => {
    // eslint-disable-next-line no-script-url
    const { status, body } = await registerClient(as.origin, { redirect_uris: ['javascript:alert(1)'] });
    expect(status).toBe(400);
    expect(body.error).toBe('invalid_client_metadata');
  });
});

describe('resource-server behaviour of /mcp', () => {
  it('answers 403 insufficient_scope (with resource_metadata, no scope=) for a token without mcp:tools', async () => {
    const tokens = await obtainTokens(as.origin, { user: 'bob', scope: 'mcp:admin' }); // bob may grant it — but it lacks mcp:tools
    const { response } = await initializeSession(as.mcpUrl, { authorization: `Bearer ${tokens.access_token}` });
    expect(response.status).toBe(403);
    const challenge = wwwAuthenticate(response);
    expect(challenge.error).toBe('insufficient_scope');
    expect(challenge.scope).toBeUndefined();
    expect(challenge.resource_metadata).toBe(`${as.origin}/.well-known/oauth-protected-resource/mcp`);
  });

  it("binds the MCP session to the token's subject: bob's token on alice's session → 403", async () => {
    const alice = await obtainTokens(as.origin, { user: 'alice' });
    const bob = await obtainTokens(as.origin, { user: 'bob' });
    const { sessionId, response } = await initializeSession(as.mcpUrl, { authorization: `Bearer ${alice.access_token}` });
    expect(response.status).toBe(200);
    const swapped = await rawCallTool(as.mcpUrl, sessionId!, 'whoami', {}, { authorization: `Bearer ${bob.access_token}` });
    expect(swapped.response.status).toBe(403);
  });
});

describe('expiry (dedicated short-TTL servers)', () => {
  it('an expired login transaction answers 400', async () => {
    const shortAs = await startAs({ ttls: { txnTtlMs: 60 } });
    try {
      const authz = await req(authorizeUrl(shortAs.origin, { challenge: pkce().challenge }));
      expect(authz.status).toBe(302);
      await sleep(120);
      expect((await req(`${shortAs.origin}${authz.location}`)).status).toBe(400);
    } finally {
      await shortAs.close();
    }
  });

  it('an expired authorization code answers invalid_grant', async () => {
    const shortAs = await startAs({ ttls: { codeTtlMs: 60 } });
    try {
      const { verifier, challenge } = pkce();
      const flow = await browserFlow(shortAs.origin, { challenge });
      await sleep(120);
      const { status, body } = await tokenRequest(shortAs.origin, { grant_type: 'authorization_code', code: flow.code!, code_verifier: verifier, redirect_uri: REDIRECT, client_id: 'mcp-cli' });
      expect(status).toBe(400);
      expect(body.error).toBe('invalid_grant');
    } finally {
      await shortAs.close();
    }
  });

  it('an expired access token answers 401 invalid_token', async () => {
    const shortAs = await startAs({ ttls: { accessTokenTtlSec: 1 } });
    try {
      const tokens = await obtainTokens(shortAs.origin, { user: 'alice' });
      expect((await initializeSession(shortAs.mcpUrl, { authorization: `Bearer ${tokens.access_token}` })).response.status).toBe(200);
      await sleep(1300);
      expectOAuth401((await initializeSession(shortAs.mcpUrl, { authorization: `Bearer ${tokens.access_token}` })).response);
    } finally {
      await shortAs.close();
    }
  });
});

describe('SDK client round trip (proves finishAuth against our pages)', () => {
  /** A minimal OAuthClientProvider whose "browser" is the scripted fetch flow above. */
  class ScriptedBrowserProvider implements OAuthClientProvider {
    redirects = 0;
    code?: string;
    private info?: OAuthClientInformationMixed;
    private tok?: OAuthTokens;
    private verifier?: string;
    private lastState?: string;

    constructor(
      private readonly origin: string,
      private readonly user: string,
    ) {}

    get redirectUrl(): string {
      return REDIRECT;
    }
    get clientMetadata(): OAuthClientMetadata {
      return {
        client_name: 'vitest scripted browser',
        redirect_uris: [REDIRECT],
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'none',
        scope: 'mcp:tools',
      };
    }
    state(): string {
      this.lastState = randomBytes(8).toString('hex');
      return this.lastState;
    }
    clientInformation(): OAuthClientInformationMixed | undefined {
      return this.info;
    }
    saveClientInformation(info: OAuthClientInformationMixed): void {
      this.info = info;
    }
    tokens(): OAuthTokens | undefined {
      return this.tok;
    }
    saveTokens(tokens: OAuthTokens): void {
      this.tok = tokens;
    }
    saveCodeVerifier(verifier: string): void {
      this.verifier = verifier;
    }
    codeVerifier(): string {
      if (!this.verifier) throw new Error('no code verifier saved');
      return this.verifier;
    }

    async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
      this.redirects += 1;
      const authz = await req(authorizationUrl.href); // what a browser would do, scripted
      expect(authz.status).toBe(302);
      const login = await req(`${this.origin}${authz.location}`);
      const txn = input(login.text, 'txn')!;
      const csrf = input(login.text, 'csrf')!;
      const authed = await postForm(`${this.origin}/login`, { txn, csrf, username: this.user, password: 'password' });
      await req(`${this.origin}${authed.location}`); // render consent, as a browser would
      const done = await postForm(`${this.origin}/consent`, { txn, csrf, accept: '1' });
      const callback = new URL(done.location!);
      expect(callback.searchParams.get('state')).toBe(this.lastState); // CSRF check a real listener performs
      this.code = callback.searchParams.get('code') ?? undefined;
    }
  }

  const provider = { current: undefined as ScriptedBrowserProvider | undefined };

  it('discovers, registers, authorizes and exchanges the code via transport.finishAuth()', async () => {
    provider.current = new ScriptedBrowserProvider(as.origin, 'alice');
    const client = new Client({ name: 'sdk-roundtrip', version: '0.0.0' });
    let transport = new StreamableHTTPClientTransport(new URL(as.mcpUrl), { authProvider: provider.current });
    await expect(client.connect(transport)).rejects.toBeInstanceOf(UnauthorizedError);
    expect(provider.current.code).toBeDefined(); // redirectToAuthorization already ran the pages
    await transport.finishAuth(provider.current.code!);
    transport = new StreamableHTTPClientTransport(new URL(as.mcpUrl), { authProvider: provider.current }); // a fresh transport is mandatory
    await client.connect(transport);
    try {
      const demo = await runDemo(client, { print: () => undefined });
      expect((demo.whoami.json as { extra?: { sub?: string } }).extra?.sub).toBe('alice');
      expect(demo.adminOnly.isError).toBe(true);
      expect(provider.current.redirects).toBe(1);
      expect(provider.current.tokens()?.refresh_token).toBeDefined();
      expect(provider.current.tokens()?.scope).toBe('mcp:tools'); // SEP-835 requested both; alice granted one
    } finally {
      await transport.terminateSession();
      await client.close();
    }
  });

  it('reconnects silently on a dead access token: refresh grant, no new browser round', async () => {
    const scripted = provider.current!;
    const before = scripted.tokens()!;
    await postForm(`${as.origin}/revoke`, { token: before.access_token, client_id: scripted.clientInformation()!.client_id });
    const client = new Client({ name: 'sdk-refresh', version: '0.0.0' });
    const transport = new StreamableHTTPClientTransport(new URL(as.mcpUrl), { authProvider: scripted });
    await client.connect(transport); // 401 → auth() → refresh_token grant → retried, connected
    try {
      const demo = await runDemo(client, { print: () => undefined });
      expect((demo.whoami.json as { extra?: { sub?: string } }).extra?.sub).toBe('alice');
      expect(scripted.redirects).toBe(1); // still only the first browser round
      expect(scripted.tokens()!.access_token).not.toBe(before.access_token);
      expect(scripted.tokens()!.refresh_token).not.toBe(before.refresh_token); // rotation
    } finally {
      await transport.terminateSession();
      await client.close();
    }
  });
});

describe('rate limiting (SDK auth router defaults)', () => {
  it('answers 429 too_many_requests after 50 POST /token in a window', async () => {
    const limited = await startAs({ rateLimit: true });
    try {
      const statuses: number[] = [];
      for (let i = 0; i < 51; i += 1) {
        const { status } = await tokenRequest(limited.origin, { grant_type: 'authorization_code', code: 'x', code_verifier: 'y', redirect_uri: REDIRECT, client_id: 'mcp-cli' });
        statuses.push(status);
      }
      expect(statuses.slice(0, 50).every((s) => s === 400)).toBe(true);
      expect(statuses[50]).toBe(429);
      const last = await postForm(`${limited.origin}/token`, { grant_type: 'authorization_code', code: 'x', code_verifier: 'y', redirect_uri: REDIRECT, client_id: 'mcp-cli' });
      expect(JSON.parse(last.text).error).toBe('too_many_requests');
    } finally {
      await limited.close();
    }
  });
});
