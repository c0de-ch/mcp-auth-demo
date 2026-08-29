/**
 * CliOAuthProvider without an authorization server: the loopback callback listener, its state
 * checks, teardown (no dangling timer / port), and the cached-token path of connectWithOAuth().
 * The full browser-less flow against Keycloak lives in the example tests.
 */
import '../env.ts'; // always first (see README: import-order rule)
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { RequestHandler } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { CliOAuthProvider, connectWithOAuth } from './oauth-cli.ts';
import { createApp, mountMcp } from '../http.ts';
import { createDemoServer } from '../tools.ts';
import { freePort, rawRequest, startTestServer, type TestServer } from '../testing.ts';
import { runDemo } from './run.ts';

/** Accepts any bearer token and makes it the subject (stands in for a real verifier). */
const anyBearer: RequestHandler = (req, res, next) => {
  const token = req.header('authorization')?.replace(/^bearer /i, '');
  if (!token) {
    res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
    return;
  }
  const auth: AuthInfo = { token, clientId: 'fake-client', scopes: ['mcp:tools'], expiresAt: Math.floor(Date.now() / 1000) + 3600, extra: { sub: token } };
  (req as typeof req & { auth?: AuthInfo }).auth = auth;
  next();
};

let storeDir: string;
let server: TestServer;
let serverUrl: string;
let callbackPort: number;
let provider: CliOAuthProvider;

beforeAll(async () => {
  storeDir = mkdtempSync(join(tmpdir(), 'mcp-auth-test-'));
  const app = createApp({ log: false });
  mountMcp(app, { createServer: () => createDemoServer({ name: 'oauth-cli-test' }), auth: anyBearer });
  server = await startTestServer(app);
  serverUrl = `${server.baseUrl}/mcp`;
});

afterAll(async () => {
  await server.close();
  rmSync(storeDir, { recursive: true, force: true });
});

afterEach(() => provider?.cancelCallback());

const newProvider = async () => {
  callbackPort = await freePort();
  provider = new CliOAuthProvider({ serverUrl, storeDir, callbackPort, staticClient: { client_id: 'mcp-cli' } });
  provider.clearAll();
  return provider;
};

const callback = (query: string) => rawRequest(`http://127.0.0.1:${callbackPort}/callback?${query}`);
const portIsFree = () => rawRequest(`http://127.0.0.1:${callbackPort}/callback`).then(() => false, () => true);

describe('waitForCallback', () => {
  it('resolves with the code when the state matches, then closes the listener', async () => {
    const p = await newProvider();
    const pending = p.waitForCallback({ timeoutMs: 5_000 });
    const state = p.state();
    expect(p.callbackListening).toBe(true);
    const res = await callback(`code=abc&state=${state}`);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Authorized');
    await expect(pending).resolves.toBe('abc');
    expect(p.callbackListening).toBe(false);
    expect(await portIsFree()).toBe(true);
  });

  it('ignores callbacks before a state was issued and with a wrong state (keeps listening)', async () => {
    const p = await newProvider();
    const pending = p.waitForCallback({ timeoutMs: 5_000 });
    expect((await callback('code=injected')).status).toBe(400); // no state issued yet
    const state = p.state();
    expect((await callback('code=injected&state=wrong')).status).toBe(400);
    expect(p.callbackListening).toBe(true); // still waiting for the real redirect
    await callback(`code=real&state=${state}`);
    await expect(pending).resolves.toBe('real');
  });

  it('rejects on an error callback without reflecting the query into the page', async () => {
    const p = await newProvider();
    const pending = p.waitForCallback({ timeoutMs: 5_000 });
    const state = p.state();
    const res = await callback(`error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E&state=${state}`);
    expect(res.status).toBe(400);
    expect(res.text).not.toContain('<script>');
    expect(res.text).not.toContain('access_denied');
    await expect(pending).rejects.toThrow(/authorization failed: access_denied/);
  });

  it('cancelCallback() rejects the pending promise and frees the port', async () => {
    const p = await newProvider();
    const pending = p.waitForCallback(); // default 5 min timeout
    p.cancelCallback();
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(p.callbackListening).toBe(false);
    expect(await portIsFree()).toBe(true);
  });

  it('times out', async () => {
    const p = await newProvider();
    await expect(p.waitForCallback({ timeoutMs: 50 })).rejects.toThrow(/timed out/);
    expect(await portIsFree()).toBe(true);
  });
});

describe('redirectToAuthorization', () => {
  it('starts the listener before returning and prints the URL (no browser with MCP_NO_BROWSER=1)', async () => {
    const p = await newProvider();
    process.env.MCP_NO_BROWSER = '1';
    await p.redirectToAuthorization(new URL('http://as.example/authorize?state=x'));
    expect(p.callbackListening).toBe(true);
    // waitForCallback() reuses that listener instead of binding a second time
    const pending = p.waitForCallback({ timeoutMs: 5_000 });
    const state = p.state();
    await callback(`code=c1&state=${state}`);
    await expect(pending).resolves.toBe('c1');
  });
});

describe('configuration from the environment', () => {
  const restore = (name: string, value: string | undefined) => {
    if (value === undefined) delete process.env[name];
    else process.env[name] = value;
  };

  it('treats an empty OAUTH_CLIENT_SECRET as "no secret" (public client)', () => {
    const previous = { id: process.env.OAUTH_CLIENT_ID, secret: process.env.OAUTH_CLIENT_SECRET };
    process.env.OAUTH_CLIENT_ID = 'mcp-cli';
    process.env.OAUTH_CLIENT_SECRET = '';
    try {
      const p = new CliOAuthProvider({ serverUrl, storeDir, callbackPort: 1 });
      expect(p.clientInformation()).toEqual({ client_id: 'mcp-cli', client_secret: undefined });
      expect('client_secret' in (p.clientInformation() as object) && p.clientInformation()!.client_secret).toBeFalsy();
      const explicit = new CliOAuthProvider({ serverUrl, storeDir, callbackPort: 1, staticClient: { client_id: 'x', client_secret: '' } });
      expect(explicit.clientInformation()!.client_secret).toBeUndefined();
    } finally {
      restore('OAUTH_CLIENT_ID', previous.id);
      restore('OAUTH_CLIENT_SECRET', previous.secret);
    }
  });

  it('uses MCP_AUTH_STORE_DIR for the token store', () => {
    const previous = process.env.MCP_AUTH_STORE_DIR;
    process.env.MCP_AUTH_STORE_DIR = join(storeDir, 'from-env');
    try {
      const p = new CliOAuthProvider({ serverUrl, callbackPort: 1, staticClient: { client_id: 'mcp-cli' } });
      expect(p.storeFile.startsWith(join(storeDir, 'from-env'))).toBe(true);
    } finally {
      restore('MCP_AUTH_STORE_DIR', previous);
    }
  });

  it('runs MCP_BROWSER_CMD with the authorization URL as its argument', async () => {
    const previous = { cmd: process.env.MCP_BROWSER_CMD, noBrowser: process.env.MCP_NO_BROWSER };
    const marker = join(storeDir, 'browser-cmd.txt');
    process.env.MCP_BROWSER_CMD = `sh -c 'printf %s "$1" > ${marker}' --`;
    delete process.env.MCP_NO_BROWSER;
    try {
      const p = await newProvider();
      await p.redirectToAuthorization(new URL('http://as.example/authorize?state=x&code_challenge=y'));
      for (let i = 0; i < 40 && !existsSync(marker); i++) await new Promise((r) => setTimeout(r, 50));
      expect(readFileSync(marker, 'utf8')).toBe('http://as.example/authorize?state=x&code_challenge=y');
    } finally {
      restore('MCP_BROWSER_CMD', previous.cmd);
      restore('MCP_NO_BROWSER', previous.noBrowser);
    }
  });
});

describe('connectWithOAuth with stored tokens', () => {
  it('connects without touching the callback port and leaves nothing running', async () => {
    const p = await newProvider();
    p.saveTokens({ access_token: 'alice', token_type: 'bearer' });
    expect(statSync(p.storeFile).mode & 0o777).toBe(0o600);

    const { client, transport } = await connectWithOAuth({ serverUrl, provider: p, timeoutMs: 60_000 });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.whoami.json).toMatchObject({ extra: { sub: 'alice' } });
    } finally {
      await transport.terminateSession();
      await client.close();
    }
    expect(p.callbackListening).toBe(false);
    expect(await portIsFree()).toBe(true); // the listener was never started; no 5-minute timer is armed
  });
});
