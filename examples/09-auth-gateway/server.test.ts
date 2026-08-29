/**
 * 09 — auth gateway: the negative matrix of design §6.9.
 *
 * Hermetic wherever possible: the gateway runs with a LOCAL JWK Set (buildGatewayApp JWT overrides)
 * so token verification needs no Keycloak, and the internal server runs on an ephemeral port. The
 * assertions cover both halves of the trust boundary — the gateway as a conformant resource server,
 * and the internal server trusting ONLY the signed assertion (never a bearer token or a plain
 * forwarded-user header). One Keycloak-backed case (skipped when Keycloak is down) proves a real
 * alice token flows end-to-end. Nothing is left running.
 */
import { publicUrl } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createServer, request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import { SignJWT } from 'jose';
import {
  connectClient,
  decodeJwtPayload,
  expectOAuth401,
  freePort,
  initializeRequest,
  initializeSession,
  isKeycloakUp,
  keycloakPasswordToken,
  mcpPost,
  mintLocalJwt,
  rawCallTool,
  rawRequest,
  startTestServer,
  testKeyPair,
  wwwAuthenticate,
  type TestServer,
  type TestKeyPair,
} from '../../src/shared/testing.ts';
import { runDemo, toolOutcome } from '../../src/shared/client/run.ts';
import { resourceMetadataUrl } from '../../src/shared/prm.ts';
import { PORT as GATEWAY_PORT, buildGatewayApp } from './gateway.ts';
import { buildInternalApp } from './server.ts';
import { ASSERTION_AUD, ASSERTION_ISS, createAssertionVerifier, signAssertion } from './assertion.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp';
const AUDIENCE = ['mcp-server'];
const SECRET = 'test-gateway-secret';
const keycloakUp = await isKeycloakUp();

let keys: TestKeyPair;
beforeAll(async () => {
  keys = await testKeyPair();
});

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** A Keycloak-shaped access token the hermetic gateway accepts (issuer + local JWKS + aud). */
const mintToken = (over: { sub?: string; scope?: string; roles?: string[]; audience?: string | string[] } = {}) =>
  mintLocalJwt({ key: keys.privateKey, kid: keys.kid, issuer: ISSUER, audience: over.audience ?? 'mcp-server', sub: over.sub ?? 'alice-sub', scope: over.scope ?? 'mcp:tools', roles: over.roles ?? ['mcp-user'] });

/** A gateway (local JWKS) in front of a fresh internal server; both on ephemeral ports. */
async function startPair(opts: { mode?: 'assertion' | 'network'; secret?: string; replayWindowMs?: number } = {}) {
  const secret = opts.secret ?? SECRET;
  const internal = await startTestServer(buildInternalApp({ secret, mode: opts.mode ?? 'assertion', replayWindowMs: opts.replayWindowMs }));
  const internalUrl = `${internal.baseUrl}/mcp`;
  const gateway = await startTestServer(await buildGatewayApp({ internalUrl, secret, issuer: ISSUER, jwks: keys.jwks, audience: AUDIENCE }));
  return {
    internal,
    gateway,
    internalUrl,
    gatewayUrl: `${gateway.baseUrl}/mcp`,
    close: async () => {
      await gateway.close();
      await internal.close();
    },
  };
}

/** Crafts an adversarial assertion directly with jose (wrong secret / aud / iss / expiry). */
async function craftAssertion(over: { secret?: string; iss?: string; aud?: string; sub?: string; ttlSec?: number; jti?: string } = {}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ azp: 'mcp-cli', scopes: ['mcp:tools'], roles: [] })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(over.iss ?? ASSERTION_ISS)
    .setAudience(over.aud ?? ASSERTION_AUD)
    .setSubject(over.sub ?? 'bob-sub')
    .setJti(over.jti ?? randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + (over.ttlSec ?? 30))
    .sign(new TextEncoder().encode(over.secret ?? SECRET));
}

// ---------------------------------------------------------------- through the gateway

describe('through the gateway (hermetic, local JWKS)', () => {
  let pair: Awaited<ReturnType<typeof startPair>>;
  beforeAll(async () => {
    pair = await startPair();
  });
  afterAll(() => pair.close());

  it('validates the Keycloak token and the internal server sees the gateway identity (via=gateway)', async () => {
    const { client, close } = await connectClient(pair.gatewayUrl, { headers: bearer(await mintToken({ sub: 'alice-sub' })) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ extra: { sub: 'alice-sub', via: 'gateway', roles: ['mcp-user'] } });
      expect((result.whoami.json as { scopes: string[] }).scopes).toEqual(['mcp:tools']);
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true); // alice: no mcp-admin role
    } finally {
      await close();
    }
  });

  it('propagates admin scope through the assertion for a user with the role (bob)', async () => {
    const { client, close } = await connectClient(pair.gatewayUrl, { headers: bearer(await mintToken({ sub: 'bob-sub', scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] })) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect((result.whoami.json as { scopes: string[] }).scopes).toEqual(['mcp:tools', 'mcp:admin']);
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('no token → 401 whose resource_metadata points at the GATEWAY PRM', async () => {
    const { response } = await initializeSession(pair.gatewayUrl);
    expectOAuth401(response, { resourceMetadata: resourceMetadataUrl(publicUrl(GATEWAY_PORT)) });
  });

  it('wrong audience → 401 invalid_token (the gateway is the resource server)', async () => {
    const { response } = await initializeSession(pair.gatewayUrl, bearer(await mintToken({ audience: 'some-other-api' })));
    expect(response.status).toBe(401);
    expect(wwwAuthenticate(response).error_description).toContain('wrong audience');
  });

  it('token without mcp:tools → 403 insufficient_scope (static message)', async () => {
    const { response } = await initializeSession(pair.gatewayUrl, bearer(await mintToken({ scope: 'email' })));
    expect(response.status).toBe(403);
    expect(wwwAuthenticate(response).error).toBe('insufficient_scope');
    expect(wwwAuthenticate(response).error_description).toBe('missing scope: mcp:tools');
  });

  it('SSE GET stream and DELETE round-trip through the proxy with the session id preserved', async () => {
    const headers = bearer(await mintToken());
    const { sessionId, response } = await initializeSession(pair.gatewayUrl, headers);
    expect(response.status).toBe(200);
    expect(sessionId).toMatch(/[0-9a-f-]{36}/);

    // the forwarded session id reaches the same internal transport → the follow-up call works
    const call = await rawCallTool(pair.gatewayUrl, sessionId!, 'add', { a: 2, b: 3 }, headers);
    expect(call.response.status).toBe(200);
    expect(call.result?.content).toEqual([{ type: 'text', text: '5' }]);

    // the standalone GET notification stream streams through (text/event-stream, not buffered)
    const stream = await openStream(pair.gatewayUrl, { ...headers, accept: 'text/event-stream', 'mcp-session-id': sessionId! });
    expect(stream.status).toBe(200);
    expect(String(stream.headers['content-type'])).toContain('text/event-stream');
    stream.close();

    // DELETE terminates the session through the proxy
    const del = await rawRequest(pair.gatewayUrl, { method: 'DELETE', headers: { ...headers, 'mcp-session-id': sessionId! } });
    expect(del.status).toBe(200);
  });

  it('maps an unreachable internal server to 502 (not a 5xx leak of internals)', async () => {
    const deadPort = await freePort();
    const gateway = await startTestServer(await buildGatewayApp({ internalUrl: `http://127.0.0.1:${deadPort}/mcp`, secret: SECRET, issuer: ISSUER, jwks: keys.jwks, audience: AUDIENCE }));
    try {
      const { response } = await initializeSession(`${gateway.baseUrl}/mcp`, bearer(await mintToken()));
      expect(response.status).toBe(502);
      expect(response.json<{ error: { message: string } }>().error.message).toContain('Bad Gateway');
    } finally {
      await gateway.close();
    }
  });
});

// ---------------------------------------------------------------- direct to the internal server

describe('direct to the internal server (assertion mode)', () => {
  let internal: TestServer;
  let mcpUrl: string;
  beforeAll(async () => {
    internal = await startTestServer(buildInternalApp({ secret: SECRET }));
    mcpUrl = `${internal.baseUrl}/mcp`;
  });
  afterAll(() => internal.close());

  const initWith = (assertion?: string, extra: Record<string, string> = {}) => initializeSession(mcpUrl, { ...(assertion ? { 'x-gateway-assertion': assertion } : {}), ...extra });
  const expect401NoPrm = (status: number, header: unknown) => {
    expect(status).toBe(401);
    expect(header).toBeUndefined(); // the backend is NOT a public resource — no WWW-Authenticate/PRM
  };

  it('plain X-Forwarded-User with no assertion → 401 (network headers are not trusted here)', async () => {
    const { response } = await initWith(undefined, { 'x-forwarded-user': 'bob', 'x-forwarded-scopes': 'mcp:tools mcp:admin' });
    expect401NoPrm(response.status, response.headers['www-authenticate']);
  });

  it('forged assertion (wrong secret) → 401', async () => {
    const { response } = await initWith(await craftAssertion({ secret: 'not-the-secret' }));
    expect401NoPrm(response.status, response.headers['www-authenticate']);
  });

  it('expired assertion → 401', async () => {
    const { response } = await initWith(await craftAssertion({ ttlSec: -60 }));
    expect(response.status).toBe(401);
  });

  it('assertion for a different audience → 401', async () => {
    const { response } = await initWith(await craftAssertion({ aud: 'mcp-other' }));
    expect(response.status).toBe(401);
  });

  it('assertion from a different issuer → 401', async () => {
    const { response } = await initWith(await craftAssertion({ iss: 'evil-issuer' }));
    expect(response.status).toBe(401);
  });

  it('replayed jti → 401 (a captured assertion cannot be reused)', async () => {
    const assertion = await signAssertion({ sub: 'bob-sub', azp: 'mcp-cli', scopes: ['mcp:tools'], roles: [] }, SECRET);
    const first = await initWith(assertion);
    expect(first.response.status).toBe(200);
    const second = await initWith(assertion);
    expect(second.response.status).toBe(401);
  });

  it('a valid assertion is accepted and yields via=gateway', async () => {
    const assertion = await signAssertion({ sub: 'carol-sub', azp: 'mcp-cli', scopes: ['mcp:tools'], roles: ['mcp-user'] }, SECRET);
    const { response, sessionId } = await initWith(assertion);
    expect(response.status).toBe(200);
    const whoami = await rawCallTool(mcpUrl, sessionId!, 'whoami', {}, { 'x-gateway-assertion': await signAssertion({ sub: 'carol-sub', azp: 'mcp-cli', scopes: ['mcp:tools'], roles: ['mcp-user'] }, SECRET) });
    expect(toolOutcome('whoami', whoami.result!).json).toMatchObject({ extra: { sub: 'carol-sub', via: 'gateway' } });
  });
});

// ---------------------------------------------------------------- header hygiene (the strip)

describe('the gateway strips inbound identity headers', () => {
  it('the internal request carries the gateway assertion but never the client Authorization / forged headers', async () => {
    const capture = await startCaptureServer();
    const gateway = await startTestServer(await buildGatewayApp({ internalUrl: capture.url, secret: SECRET, issuer: ISSUER, jwks: keys.jwks, audience: AUDIENCE }));
    try {
      await mcpPost(`${gateway.baseUrl}/mcp`, initializeRequest(), {
        authorization: `Bearer ${await mintToken({ sub: 'alice-sub' })}`,
        'x-gateway-assertion': 'CLIENT-FORGED-ASSERTION',
        'x-forwarded-user': 'mallory',
        'x-forwarded-scopes': 'mcp:admin',
      });
      const received = await capture.received;
      expect(received.headers.authorization).toBeUndefined();
      expect(received.headers['x-forwarded-user']).toBeUndefined();
      expect(received.headers['x-forwarded-scopes']).toBeUndefined();
      const forwarded = received.headers['x-gateway-assertion'];
      expect(typeof forwarded).toBe('string');
      expect(forwarded).not.toBe('CLIENT-FORGED-ASSERTION'); // the client's forgery was dropped
      // …and what the internal server DOES receive is a real gateway assertion for the real subject
      const verified = await createAssertionVerifier(SECRET)(forwarded as string);
      expect(verified.sub).toBe('alice-sub');
      expect(received.body).toContain('initialize'); // the JSON body was forwarded intact
    } finally {
      await gateway.close();
      await capture.close();
    }
  });
});

// ---------------------------------------------------------------- the documented attack

describe('INTERNAL_TRUST_MODE=network (the deliberately insecure variant)', () => {
  it('trusts an UNSIGNED X-Forwarded-User header — forgery is accepted, admin included', async () => {
    const internal = await startTestServer(buildInternalApp({ mode: 'network' }));
    try {
      const { client, close } = await connectClient(`${internal.baseUrl}/mcp`, { headers: { 'x-forwarded-user': 'bob', 'x-forwarded-scopes': 'mcp:tools mcp:admin' } });
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ extra: { sub: 'bob', via: 'network-headers' } });
      expect(result.adminOnly.isError).toBe(false); // forged mcp:admin is trusted — the whole point
      await close();
    } finally {
      await internal.close();
    }
  });
});

// ---------------------------------------------------------------- against Keycloak

describe.skipIf(!keycloakUp)('against the real Keycloak realm', () => {
  it('alice via mcp-test flows end-to-end through the gateway (via=gateway, admin denied)', async () => {
    const tokens = await keycloakPasswordToken({ username: 'alice', password: 'password' });
    const internal = await startTestServer(buildInternalApp({ secret: SECRET }));
    const gateway = await startTestServer(await buildGatewayApp({ internalUrl: `${internal.baseUrl}/mcp`, secret: SECRET }));
    try {
      const { client, close } = await connectClient(`${gateway.baseUrl}/mcp`, { headers: bearer(tokens.access_token) });
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ extra: { via: 'gateway', sub: decodeJwtPayload(tokens.access_token).sub } });
      expect(result.adminOnly.isError).toBe(true);
      await close();
    } finally {
      await gateway.close();
      await internal.close();
    }
  });
});

// ---------------------------------------------------------------- test helpers

interface CaptureServer {
  url: string;
  received: Promise<{ headers: IncomingHttpHeaders; body: string }>;
  close(): Promise<void>;
}

/** A stand-in internal server that records the first request and returns a canned 200 JSON. */
function startCaptureServer(): Promise<CaptureServer> {
  return new Promise((resolve) => {
    let resolveReceived!: (value: { headers: IncomingHttpHeaders; body: string }) => void;
    const received = new Promise<{ headers: IncomingHttpHeaders; body: string }>((r) => (resolveReceived = r));
    const server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        resolveReceived({ headers: req.headers, body: Buffer.concat(chunks).toString('utf8') });
        res.writeHead(200, { 'content-type': 'application/json', 'mcp-session-id': 'capture-1' });
        res.end(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }));
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      resolve({
        url: `http://127.0.0.1:${port}/mcp`,
        received,
        close: () => new Promise<void>((done) => server.close(() => done())),
      });
    });
  });
}

interface OpenStream {
  status: number;
  headers: IncomingHttpHeaders;
  close(): void;
}

/** Opens a GET SSE stream, resolves on the response head, and lets the caller tear it down. */
function openStream(url: string, headers: Record<string, string>): Promise<OpenStream> {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const req = httpRequest({ hostname: target.hostname, port: target.port, path: target.pathname, method: 'GET', headers }, (res) => {
      resolve({
        status: res.statusCode ?? 0,
        headers: res.headers,
        close: () => {
          res.destroy();
          req.destroy();
        },
      });
    });
    req.on('error', reject);
    req.end();
  });
}
