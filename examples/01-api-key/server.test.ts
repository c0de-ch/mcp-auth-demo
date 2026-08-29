import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { timingSafeEqual } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { parseResultLine, printResult, runDemo } from '../../src/shared/client/run.ts';
import {
  connectClient,
  expectOAuth401,
  initializeSession,
  rawCallTool,
  rawRequest,
  startTestServer,
  wwwAuthenticate,
  type TestServer,
} from '../../src/shared/testing.ts';
import { DEMO_API_KEYS, buildApp, createApiKeyVerifier, hashApiKey, lookupApiKey, parseApiKeys } from './server.ts';

// Wrap ONLY timingSafeEqual in a spy so the constant-time suite below can count comparisons;
// everything else in node:crypto stays untouched (vi.mock is hoisted above the imports).
vi.mock('node:crypto', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:crypto')>();
  return { ...actual, timingSafeEqual: vi.fn(actual.timingSafeEqual) };
});
const realTimingSafeEqual = (await vi.importActual<typeof import('node:crypto')>('node:crypto')).timingSafeEqual;

const ALICE = 'demo-api-key-alice';
const BOB = 'demo-api-key-bob';
const bearer = (key: string) => ({ authorization: `Bearer ${key}` });

let server: TestServer;
let mcpUrl: string;

beforeAll(async () => {
  server = await startTestServer(buildApp({ keys: parseApiKeys(DEMO_API_KEYS) }));
  mcpUrl = `${server.baseUrl}/mcp`;
});

afterAll(async () => {
  await server.close();
});

describe('01-api-key: key table', () => {
  it('stores sha256 digests, never the keys themselves', () => {
    const table = parseApiKeys(DEMO_API_KEYS);
    expect([...table.keys()]).toEqual([hashApiKey(ALICE), hashApiKey(BOB)]);
    for (const hash of table.keys()) expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(table.get(hashApiKey(ALICE))).toEqual({ principal: 'alice', scopes: ['mcp:tools'] });
    expect(table.get(hashApiKey(BOB))).toEqual({ principal: 'bob', scopes: ['mcp:tools', 'mcp:admin'] });
  });

  it('rejects a malformed MCP_API_KEYS without echoing the entry (it contains the key)', () => {
    expect(() => parseApiKeys('some-secret-without-colons')).toThrow(/key:principal:scope/);
    expect(() => parseApiKeys('some-secret-without-colons')).not.toThrow(/some-secret/);
    expect(() => parseApiKeys(' ; ')).toThrow(/no keys/);
  });
});

describe('01-api-key: authenticated demo', () => {
  it('alice: whoami reports sub alice with mcp:tools, admin_only is denied', async () => {
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(ALICE) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.tools.sort()).toEqual(['add', 'admin_only', 'whoami']);
      expect(result.whoami.json).toMatchObject({
        clientId: 'alice',
        scopes: ['mcp:tools'],
        extra: { sub: 'alice', kind: 'api-key' },
      });
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
      expect(result.adminOnly.text).toContain('mcp:admin');
      expect(result.whoami.text).not.toContain(ALICE); // the raw key never comes back
    } finally {
      await close();
    }
  });

  it('bob: admin_only succeeds (mcp:admin comes from the key table)', async () => {
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(BOB) });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: 'bob', scopes: ['mcp:tools', 'mcp:admin'] });
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('synthesises an expiresAt in the near future (the SDK insists on one)', async () => {
    const info = await createApiKeyVerifier(parseApiKeys(DEMO_API_KEYS)).verifyAccessToken(ALICE);
    const now = Math.floor(Date.now() / 1000);
    expect(info.expiresAt).toBeGreaterThan(now);
    expect(info.expiresAt).toBeLessThanOrEqual(now + 3600);
  });

  it('produces the RESULT line the smoke script expects', async () => {
    const { client, close } = await connectClient(mcpUrl, { headers: bearer(ALICE) });
    const lines: string[] = [];
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(printResult('01', result, undefined, (l) => lines.push(l))).toBe(0);
    } finally {
      await close();
    }
    expect(lines.at(-1)).toMatch(/^RESULT \{"example":"01"/);
    const parsed = parseResultLine(lines.join('\n'));
    expect(parsed).toMatchObject({ example: '01', tools: ['add', 'admin_only', 'whoami'], add: '5', adminOnly: 'denied' });
    expect((parsed?.whoami as { extra?: { sub?: string } }).extra?.sub).toBe('alice');
  });
});

describe('01-api-key: negative matrix', () => {
  it('no Authorization header → 401 invalid_token WITHOUT resource_metadata (nothing to discover)', async () => {
    const { response, sessionId } = await initializeSession(mcpUrl);
    expectOAuth401(response, { resourceMetadata: false });
    expect(sessionId).toBeUndefined();
    // No requiredScopes on the middleware either: the challenge names no scope to go and obtain.
    expect(response.headers['www-authenticate']).toBe('Bearer error="invalid_token", error_description="Missing Authorization header"');
    expect(response.json()).toEqual({ error: 'invalid_token', error_description: 'Missing Authorization header' });
  });

  it.each([
    ['unknown key', 'Bearer this-key-is-not-in-the-table', 'unknown API key'],
    ['known key with one character changed', `Bearer ${ALICE.slice(0, -1)}x`, 'unknown API key'],
    ['double space after Bearer (SDK splits on a single space)', `Bearer  ${ALICE}`, "Invalid Authorization header format, expected 'Bearer TOKEN'"],
    ['empty token', 'Bearer ', "Invalid Authorization header format, expected 'Bearer TOKEN'"],
    ['wrong scheme', `Basic ${ALICE}`, "Invalid Authorization header format, expected 'Bearer TOKEN'"],
  ])('%s → 401 without resource_metadata', async (_name, authorization, description) => {
    const { response, sessionId } = await initializeSession(mcpUrl, { authorization });
    expectOAuth401(response, { resourceMetadata: false });
    expect(sessionId).toBeUndefined();
    expect(wwwAuthenticate(response).error_description).toBe(description);
  });

  it('guards GET (notification stream) and DELETE (session end) like POST', async () => {
    const get = await rawRequest(mcpUrl, { method: 'GET', headers: { accept: 'text/event-stream' } });
    expectOAuth401(get, { resourceMetadata: false });
    const del = await rawRequest(mcpUrl, { method: 'DELETE' });
    expectOAuth401(del, { resourceMetadata: false });
  });

  it('a key without mcp:tools is authenticated but not authorized: 403 insufficient_scope', async () => {
    const scopeless = await startTestServer(buildApp({ keys: parseApiKeys('metrics-key:carol:other:scope') }));
    try {
      const { response } = await initializeSession(`${scopeless.baseUrl}/mcp`, bearer('metrics-key'));
      expect(response.status).toBe(403);
      const challenge = wwwAuthenticate(response);
      expect(challenge).toMatchObject({ scheme: 'Bearer', error: 'insufficient_scope', error_description: 'missing scope: mcp:tools' });
      expect(challenge.resource_metadata).toBeUndefined();
    } finally {
      await scopeless.close();
    }
  });

  it('removing a key from the table revokes it on the very next request', async () => {
    const keys = parseApiKeys(DEMO_API_KEYS);
    const revocable = await startTestServer(buildApp({ keys }));
    try {
      const url = `${revocable.baseUrl}/mcp`;
      const { sessionId, response } = await initializeSession(url, bearer(ALICE));
      expect(response.status).toBe(200);

      keys.delete(hashApiKey(ALICE)); // rotation/revocation = mutate the table; no restart, no token to expire

      const after = await rawCallTool(url, sessionId!, 'add', { a: 1, b: 2 }, bearer(ALICE));
      expectOAuth401(after.response, { resourceMetadata: false });

      const bob = await initializeSession(url, bearer(BOB)); // other keys are untouched
      expect(bob.response.status).toBe(200);
    } finally {
      await revocable.close();
    }
  });

  it("a session initialised with alice's key cannot be reused with bob's key (403)", async () => {
    const { sessionId } = await initializeSession(mcpUrl, bearer(ALICE));
    const { response } = await rawCallTool(mcpUrl, sessionId!, 'add', { a: 1, b: 2 }, bearer(BOB));
    expect(response.status).toBe(403);
    expect(response.json<{ error: { message: string } }>().error.message).toContain('different principal');
  });

  it('the SDK client without an authProvider surfaces a rejected key as StreamableHTTPError 401', async () => {
    const error = await connectClient(mcpUrl, { headers: bearer('wrong-key') }).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(StreamableHTTPError);
    expect((error as StreamableHTTPError).code).toBe(401);
    expect((error as Error).message).toContain('unknown API key');
  });
});

describe('01-api-key: constant-time comparison', () => {
  // Five entries; ALICE is deliberately the FIRST so a match there must still cost 5 comparisons.
  const spec = [`${ALICE}:alice:mcp:tools`, 'unit-key-2:two:mcp:tools', 'unit-key-3:three:mcp:tools', `${BOB}:bob:mcp:tools mcp:admin`, 'unit-key-5:five:mcp:tools'].join(';');
  const table = parseApiKeys(spec);
  const spy = vi.mocked(timingSafeEqual);

  beforeEach(() => {
    spy.mockClear();
    spy.mockImplementation(realTimingSafeEqual);
  });

  it.each([
    ['a match on the first entry', ALICE],
    ['a match on a later entry', BOB],
    ['an unknown key', 'not-in-the-table'],
  ])('%s costs one timingSafeEqual per entry — no early exit', async (_name, key) => {
    await createApiKeyVerifier(table).verifyAccessToken(key).catch(() => undefined);
    expect(spy).toHaveBeenCalledTimes(table.size);
    for (const [a, b] of spy.mock.calls) {
      expect(a.byteLength).toBe(32); // sha256 digests are compared, never raw keys,
      expect(b.byteLength).toBe(32); // so both sides always have equal length
    }
  });

  it('the match decision rests on timingSafeEqual alone — there is no === fallback', async () => {
    spy.mockReturnValue(false); // if any === compared the digests, alice would still get in
    await expect(createApiKeyVerifier(table).verifyAccessToken(ALICE)).rejects.toThrow('unknown API key');

    spy.mockImplementation(realTimingSafeEqual);
    await expect(createApiKeyVerifier(table).verifyAccessToken(ALICE)).resolves.toMatchObject({ clientId: 'alice' });
  });

  it('the lookup source contains no equality operator at all', () => {
    expect(lookupApiKey.toString()).not.toMatch(/[!=]==?/);
  });
});
