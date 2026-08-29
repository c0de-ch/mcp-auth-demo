import { publicHost } from '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { connectClient, initializeSession, mcpPost, rawCallTool, rawRequest, startTestServer, type TestServer } from '../../src/shared/testing.ts';
import { printResult, runDemo } from '../../src/shared/client/run.ts';
import { buildApp } from './server.ts';

let server: TestServer;
let mcpUrl: string;

beforeAll(async () => {
  server = await startTestServer(buildApp());
  mcpUrl = `${server.baseUrl}/mcp`;
});

afterAll(async () => {
  await server.close();
});

describe('00-baseline-no-auth', () => {
  it('serves the demo tools to an anonymous client', async () => {
    const { client, close } = await connectClient(mcpUrl);
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.tools.sort()).toEqual(['add', 'admin_only', 'whoami']);
      expect(result.whoami.json).toEqual({ anonymous: true });
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
      expect(result.adminOnly.text).toContain('mcp:admin');
    } finally {
      await close();
    }
  });

  it('answers initialize with 200 and a session id for the public host', async () => {
    const { sessionId, response } = await initializeSession(mcpUrl, { host: `${publicHost()}:${new URL(server.baseUrl).port}` });
    expect(response.status).toBe(200);
    expect(sessionId).toMatch(/[0-9a-f-]{36}/);

    const { result } = await rawCallTool(mcpUrl, sessionId!, 'add', { a: 40, b: 2 });
    expect(result?.content).toEqual([{ type: 'text', text: '42' }]);
  });

  it('rejects a foreign Host header with 403 (DNS-rebinding protection)', async () => {
    const { response } = await initializeSession(mcpUrl, { host: 'evil.example' });
    expect(response.status).toBe(403);
    expect(response.json<{ error: { message: string } }>().error.message).toContain('evil.example');
  });

  it('rejects a non-initialize request without a session with 400', async () => {
    const response = await mcpPost(mcpUrl, { jsonrpc: '2.0', id: 1, method: 'tools/list' });
    expect(response.status).toBe(400);
  });

  it('answers 404 for an unknown session id', async () => {
    const response = await mcpPost(mcpUrl, { jsonrpc: '2.0', id: 1, method: 'tools/list' }, { 'mcp-session-id': 'does-not-exist' });
    expect(response.status).toBe(404);
  });

  it('reports healthy on /healthz', async () => {
    const res = await fetch(`${server.baseUrl}/healthz`);
    expect(await res.json()).toEqual({ ok: true });
  });

  it('never sends a WWW-Authenticate header and answers unknown routes with JSON', async () => {
    const { response } = await initializeSession(mcpUrl);
    expect(response.headers['www-authenticate']).toBeUndefined();
    const res = await rawRequest(`${server.baseUrl}/nope`);
    expect(res.status).toBe(404);
    expect(res.json()).toMatchObject({ jsonrpc: '2.0', error: { code: -32000 } });
  });

  it('produces the RESULT line the smoke script expects', async () => {
    const { client, close } = await connectClient(mcpUrl);
    const lines: string[] = [];
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(printResult('00', result, undefined, (l) => lines.push(l))).toBe(0);
    } finally {
      await close();
    }
    expect(lines.at(-1)).toBe('RESULT {"example":"00","tools":["add","admin_only","whoami"],"whoami":{"anonymous":true},"add":"5","adminOnly":"denied"}');
  });
});
