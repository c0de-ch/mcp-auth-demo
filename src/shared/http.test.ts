import './env.ts'; // always first (see README: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { request as httpRequest } from 'node:http';
import type { RequestHandler } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { allowedHostnames, createApp, mountMcp, subjectOf } from './http.ts';
import { createDemoServer } from './tools.ts';
import { connectClient, initializeSession, mcpPost, rawCallTool, rawRequest, startTestServer, type TestServer } from './testing.ts';
import { runDemo } from './client/run.ts';

/**
 * A stand-in for requireBearerAuth: the bearer token IS the subject; "admin" gets mcp:admin.
 * Lets us test the transport plumbing (sessions, subject binding, stateless mode) without an IdP.
 */
const fakeBearer: RequestHandler = (req, res, next) => {
  const token = req.header('authorization')?.replace(/^bearer /i, '');
  if (!token) {
    res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
    return;
  }
  const auth: AuthInfo = {
    token,
    clientId: 'fake-client',
    scopes: token === 'admin' ? ['mcp:tools', 'mcp:admin'] : ['mcp:tools'],
    expiresAt: Math.floor(Date.now() / 1000) + 3600,
    extra: { sub: token },
  };
  (req as typeof req & { auth?: AuthInfo }).auth = auth;
  next();
};

const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

let server: TestServer;
let statefulUrl: string;
let statelessUrl: string;

beforeAll(async () => {
  const app = createApp({ log: false });
  mountMcp(app, { createServer: () => createDemoServer({ name: 'stateful' }), auth: fakeBearer });
  mountMcp(app, { path: '/stateless', createServer: () => createDemoServer({ name: 'stateless' }), auth: fakeBearer, stateless: true });
  mountMcp(app, { path: '/short-lived', createServer: () => createDemoServer({ name: 'short-lived' }), sessionIdleMs: 100 });
  app.get('/boom', () => {
    throw new Error('secret internal detail');
  });
  server = await startTestServer(app);
  statefulUrl = `${server.baseUrl}/mcp`;
  statelessUrl = `${server.baseUrl}/stateless`;
});

afterAll(async () => {
  await server.close();
});

describe('mountMcp (stateful, with auth middleware)', () => {
  it('applies the auth middleware to POST, GET and DELETE', async () => {
    expect((await initializeSession(statefulUrl)).response.status).toBe(401);
    expect((await rawRequest(statefulUrl, { headers: { accept: 'text/event-stream' } })).status).toBe(401);
    expect((await rawRequest(statefulUrl, { method: 'DELETE' })).status).toBe(401);
  });

  it('exposes the AuthInfo to tools', async () => {
    const { client, close } = await connectClient(statefulUrl, { headers: bearer('alice') });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ clientId: 'fake-client', scopes: ['mcp:tools'], extra: { sub: 'alice' } });
      expect(result.adminOnly.isError).toBe(true);
    } finally {
      await close();
    }
  });

  it('lets scope mcp:admin call admin_only', async () => {
    const { client, close } = await connectClient(statefulUrl, { headers: bearer('admin') });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('binds a session to the subject that initialized it', async () => {
    const { sessionId } = await initializeSession(statefulUrl, bearer('alice'));
    expect(sessionId).toBeDefined();

    const own = await rawCallTool(statefulUrl, sessionId!, 'add', { a: 1, b: 1 }, bearer('alice'));
    expect(own.response.status).toBe(200);

    const stolen = await rawCallTool(statefulUrl, sessionId!, 'add', { a: 1, b: 1 }, bearer('bob'));
    expect(stolen.response.status).toBe(403);
    expect(stolen.response.json<{ error: { message: string } }>().error.message).toMatch(/different principal/);

    expect((await rawRequest(statefulUrl, { method: 'DELETE', headers: { 'mcp-session-id': sessionId!, ...bearer('bob') } })).status).toBe(403);
  });

  it('forgets a session after DELETE', async () => {
    const { sessionId } = await initializeSession(statefulUrl, bearer('alice'));
    const del = await rawRequest(statefulUrl, { method: 'DELETE', headers: { 'mcp-session-id': sessionId!, ...bearer('alice') } });
    expect(del.status).toBe(200);
    const after = await rawCallTool(statefulUrl, sessionId!, 'add', { a: 1, b: 1 }, bearer('alice'));
    expect(after.response.status).toBe(404);
  });
});

describe('createApp error handling', () => {
  it('answers invalid JSON with a JSON-RPC parse error, not an HTML stack trace', async () => {
    const res = await rawRequest(statefulUrl, { method: 'POST', headers: { ...bearer('alice'), accept: 'application/json, text/event-stream', 'content-type': 'application/json' }, body: '{not json' });
    expect(res.status).toBe(400);
    expect(res.json()).toEqual({ jsonrpc: '2.0', error: { code: -32700, message: 'Parse error: invalid JSON body' }, id: null });
    expect(res.text).not.toContain('node_modules');
  });

  it('answers 415 for a non-JSON content type, even on the first request', async () => {
    const res = await rawRequest(statefulUrl, { method: 'POST', headers: { ...bearer('alice'), accept: 'application/json, text/event-stream', 'content-type': 'text/plain' }, body: 'hello' });
    expect(res.status).toBe(415);
  });

  it('hides internal errors behind a generic JSON-RPC 500', async () => {
    const res = await rawRequest(`${server.baseUrl}/boom`);
    expect(res.status).toBe(500);
    expect(res.json()).toEqual({ jsonrpc: '2.0', error: { code: -32603, message: 'Internal Server Error' }, id: null });
    expect(res.text).not.toContain('secret internal detail');
  });

  it('checks the Host header before parsing the body', async () => {
    const res = await rawRequest(statefulUrl, { method: 'POST', headers: { host: 'evil.example', 'content-type': 'application/json' }, body: '{not json' });
    expect(res.status).toBe(403); // not 400: the rebinding request is refused first
  });
});

describe('mountMcp session idle timeout', () => {
  it('forgets a session nobody has used for sessionIdleMs', async () => {
    const url = `${server.baseUrl}/short-lived`;
    const { sessionId } = await initializeSession(url);
    expect((await rawCallTool(url, sessionId!, 'add', { a: 1, b: 1 })).response.status).toBe(200);
    await new Promise((r) => setTimeout(r, 300));
    expect((await rawCallTool(url, sessionId!, 'add', { a: 1, b: 1 })).response.status).toBe(404);
  });

  it('keeps a session alive while its notification stream (GET) is open', async () => {
    const url = `${server.baseUrl}/short-lived`;
    const { sessionId } = await initializeSession(url);
    // open the standalone SSE stream and keep it open across several sweeper ticks
    const req = httpRequest(url, { method: 'GET', headers: { accept: 'text/event-stream', 'mcp-session-id': sessionId! } });
    const streamStatus = new Promise<number>((resolve) => req.on('response', (res) => resolve(res.statusCode ?? 0)));
    req.end();
    expect(await streamStatus).toBe(200);
    await new Promise((r) => setTimeout(r, 400));
    expect((await rawCallTool(url, sessionId!, 'add', { a: 1, b: 1 })).response.status).toBe(200); // still there
    req.destroy();
    await new Promise((r) => setTimeout(r, 400));
    expect((await rawCallTool(url, sessionId!, 'add', { a: 1, b: 1 })).response.status).toBe(404); // idle again → swept
  });
});

describe('allowedHostnames', () => {
  it('lower-cases every entry (the SDK compares against URL.hostname)', () => {
    const previous = process.env.MCP_ALLOWED_HOSTS;
    process.env.MCP_ALLOWED_HOSTS = 'MCP.LAN, Other.Local';
    const hosts = allowedHostnames(['MyBox.LAN']);
    expect(hosts).toEqual(expect.arrayContaining(['localhost', '127.0.0.1', '[::1]', 'mcp.lan', 'other.local', 'mybox.lan']));
    expect(hosts.some((h) => h !== h.toLowerCase())).toBe(false);
    if (previous === undefined) delete process.env.MCP_ALLOWED_HOSTS;
    else process.env.MCP_ALLOWED_HOSTS = previous;
  });

  it('accepts a mixed-case Host header for an allowed host', async () => {
    const res = await rawRequest(`${server.baseUrl}/healthz`, { headers: { host: `LOCALHOST:${new URL(server.baseUrl).port}` } });
    expect(res.status).toBe(200);
  });
});

describe('unknown routes', () => {
  it('answer a JSON-RPC 404, not an HTML page', async () => {
    const res = await rawRequest(`${server.baseUrl}/nope`);
    expect(res.status).toBe(404);
    expect(res.headers['content-type']).toContain('application/json');
    expect(res.json()).toEqual({ jsonrpc: '2.0', error: { code: -32000, message: 'Not Found: GET /nope' }, id: null });
  });
});

describe('mountMcp (stateless)', () => {
  it('serves each POST with a fresh server and no session id', async () => {
    const { sessionId, response } = await initializeSession(statelessUrl, bearer('alice'));
    expect(response.status).toBe(200);
    expect(sessionId).toBeUndefined();

    const call = await mcpPost(statelessUrl, { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'add', arguments: { a: 2, b: 2 } } }, bearer('alice'));
    expect(call.status).toBe(200);
    expect(call.messages().find((m) => m.id === 2)?.result).toMatchObject({ content: [{ type: 'text', text: '4' }] });
  });

  it('answers 405 for GET and DELETE', async () => {
    expect((await rawRequest(statelessUrl, { headers: { accept: 'text/event-stream', ...bearer('alice') } })).status).toBe(405);
    expect((await rawRequest(statelessUrl, { method: 'DELETE', headers: bearer('alice') })).status).toBe(405);
  });

  it('works with the SDK client', async () => {
    const { client, close } = await connectClient(statelessUrl, { headers: bearer('admin') });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });
});

describe('subjectOf', () => {
  it('prefers extra.sub over clientId', () => {
    expect(subjectOf({ token: 't', clientId: 'c', scopes: [], extra: { sub: 'u' } })).toBe('u');
    expect(subjectOf({ token: 't', clientId: 'c', scopes: [] })).toBe('c');
    expect(subjectOf(undefined)).toBeUndefined();
  });
});
