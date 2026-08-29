/**
 * 08-mtls — the §6.8 negative matrix, fully hermetic: the PKI is generated into a temp dir in
 * beforeAll (scripts/gen-certs.sh with OUT_DIR) and three https servers run on port 0:
 *   server   hard-fail, default CN allow-list (alice,bob)
 *   strict   hard-fail, allow-list [bob]         → alice authenticates but is not authorized (403)
 *   soft     MTLS_SOFT_FAIL variant              → handshake accepts anyone, certAuth answers 401
 */
import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer as createHttpsServer, type Server as HttpsServer, type ServerOptions } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SecureVersion } from 'node:tls';
import type { Express } from 'express';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { fetch as undiciFetch } from 'undici';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { jsonRpcErrorHandler, notFoundHandler } from '../../src/shared/http.ts';
import { createClient, runDemo } from '../../src/shared/client/run.ts';
import { initializeRequest, MCP_HEADERS, spawnExample } from '../../src/shared/testing.ts';
import { buildApp } from './server.ts';
import { mtlsDispatcher, mtlsFetch, readPem, serverTlsOptions } from './tls.ts';

// ---------------------------------------------------------------- helpers (https twin of startTestServer)

interface TlsTestServer {
  mcpUrl: string;
  server: HttpsServer;
  /** HTTP requests that made it past the TLS handshake into Express — the "never reached" spy. */
  requests(): number;
  close(): Promise<void>;
}

function startTlsTestServer(app: Express, tls: ServerOptions): Promise<TlsTestServer> {
  app.use(notFoundHandler); // same tail as the shared listen()/startTestServer
  app.use(jsonRpcErrorHandler);
  let hits = 0;
  return new Promise((resolve, reject) => {
    const server = createHttpsServer(tls, app);
    server.on('request', () => (hits += 1));
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') return reject(new Error('unexpected server address'));
      resolve({
        mcpUrl: `https://127.0.0.1:${address.port}/mcp`,
        server,
        requests: () => hits,
        close: () => new Promise<void>((done) => { server.closeAllConnections(); server.close(() => done()); }),
      });
    });
    server.on('error', reject);
  });
}

let certs: string;
let server: TlsTestServer;
let strict: TlsTestServer;
let soft: TlsTestServer;

/** POST initialize through an mTLS-configured undici Agent (closed afterwards, win or lose). */
async function rawInit(url: string, client: string, extra: { ca?: Buffer; maxVersion?: SecureVersion } = {}) {
  const dispatcher = mtlsDispatcher(url, { client, dir: certs, ...extra });
  try {
    const res = await undiciFetch(url, { method: 'POST', headers: MCP_HEADERS, body: JSON.stringify(initializeRequest()), dispatcher });
    const text = await res.text();
    let errorMessage: string | undefined;
    try {
      errorMessage = (JSON.parse(text) as { error?: { message?: string } }).error?.message; // JSON error bodies only (200 answers are SSE)
    } catch {
      errorMessage = undefined;
    }
    return { status: res.status, errorMessage };
  } finally {
    await dispatcher.close();
  }
}

/** SDK client connected through the example's own mtlsFetch (the exact code path client.ts uses). */
async function connectMtls(url: string, client: string, headers?: Record<string, string>) {
  const sdkClient = createClient('08-mtls-test');
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    fetch: mtlsFetch(url, { client, dir: certs }),
    requestInit: headers ? { headers } : undefined,
  });
  await sdkClient.connect(transport);
  return {
    client: sdkClient,
    close: async () => {
      await transport.terminateSession().catch(() => undefined);
      await sdkClient.close();
    },
  };
}

/** Awaits a rejection and flattens the error + its `cause` chain into one string for matching. */
async function failure(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    const parts: string[] = [];
    for (let e: unknown = error; e instanceof Error; e = e.cause) {
      parts.push(`${(e as NodeJS.ErrnoException).code ?? ''}:${e.message}`);
    }
    return parts.join(' <- ');
  }
  throw new Error('expected the request to fail, but it succeeded');
}

beforeAll(async () => {
  certs = mkdtempSync(join(tmpdir(), 'mcp-08-certs-'));
  const gen = await spawnExample('scripts/gen-certs.sh', { OUT_DIR: certs }, { readyUrl: false });
  if ((await gen.exited) !== 0) throw new Error(`gen-certs.sh failed:\n${gen.stderr()}`);
  server = await startTlsTestServer(buildApp(), serverTlsOptions(certs));
  strict = await startTlsTestServer(buildApp({ allowedCn: ['bob'] }), serverTlsOptions(certs));
  soft = await startTlsTestServer(buildApp(), serverTlsOptions(certs, { softFail: true }));
});

afterAll(async () => {
  for (const s of [server, strict, soft]) await s?.close();
  if (certs) rmSync(certs, { recursive: true, force: true });
});

describe('08-mtls', () => {
  it('alice: CN → clientId/sub, OU mcp-user → [mcp:tools], notAfter → expiresAt; admin denied', async () => {
    const { client, close } = await connectMtls(server.mcpUrl, 'alice');
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect(result.tools.sort()).toEqual(['add', 'admin_only', 'whoami']);
      const whoami = result.whoami.json as { clientId: string; scopes: string[]; expiresAt: number; extra: Record<string, unknown> };
      expect(whoami.clientId).toBe('alice');
      expect(whoami.scopes).toEqual(['mcp:tools']);
      expect(whoami.expiresAt).toBeGreaterThan(Date.now() / 1000); // synthesised from the certificate's notAfter
      expect(whoami.extra).toMatchObject({ sub: 'alice', issuer: 'mcp-auth-demo CA', kind: 'mtls' });
      expect(whoami.extra.fingerprint256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
      expect(result.add.text).toBe('5');
      expect(result.adminOnly.isError).toBe(true);
      expect(result.adminOnly.text).toContain('mcp:admin');
    } finally {
      await close();
    }
  });

  it('bob: OU mcp-admin → [mcp:tools, mcp:admin]; admin_only succeeds', async () => {
    const { client, close } = await connectMtls(server.mcpUrl, 'bob');
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect((result.whoami.json as { clientId: string }).clientId).toBe('bob');
      expect((result.whoami.json as { scopes: string[] }).scopes).toEqual(['mcp:tools', 'mcp:admin']);
      expect(result.adminOnly.isError).toBe(false);
    } finally {
      await close();
    }
  });

  it('ignores Authorization headers entirely — the certificate is the only credential', async () => {
    const { client, close } = await connectMtls(server.mcpUrl, 'alice', { authorization: 'Bearer some-stolen-or-garbage-token' });
    try {
      const result = await runDemo(client, { print: () => undefined });
      expect((result.whoami.json as { clientId: string }).clientId).toBe('alice'); // not 401, not the token
    } finally {
      await close();
    }
  });

  it('no client certificate → TLS handshake error; the request never reaches Express', async () => {
    const before = server.requests();
    const error = await failure(rawInit(server.mcpUrl, 'none'));
    expect(error).toMatch(/certificate.required|ERR_SSL|ECONNRESET|UND_ERR_SOCKET/i);
    expect(server.requests()).toBe(before); // the spy: no HTTP request was ever parsed
  });

  it('certificate signed by an untrusted CA (rogue-client) → handshake error, never reaches Express', async () => {
    const before = server.requests();
    const error = await failure(rawInit(server.mcpUrl, 'rogue-client'));
    expect(error).toMatch(/alert|ERR_SSL|ECONNRESET|EPIPE|UND_ERR_SOCKET/i);
    expect(server.requests()).toBe(before);
  });

  it('expired certificate (expired-alice) → handshake error, never reaches Express', async () => {
    const before = server.requests();
    const error = await failure(rawInit(server.mcpUrl, 'expired-alice'));
    expect(error).toMatch(/expired|alert|ERR_SSL|ECONNRESET|EPIPE|UND_ERR_SOCKET/i);
    expect(server.requests()).toBe(before);
  });

  it('valid CA but CN not in MTLS_ALLOWED_CN → 403 with a static JSON error', async () => {
    const denied = await rawInit(strict.mcpUrl, 'alice'); // strict allows only bob
    expect(denied.status).toBe(403);
    expect(denied.errorMessage).toBe('Forbidden: certificate CN is not in MTLS_ALLOWED_CN');
    const ok = await rawInit(strict.mcpUrl, 'bob'); // …while bob passes the same server
    expect(ok.status).toBe(200);
  });

  it('plain http:// to the TLS port → connection error', async () => {
    const httpUrl = server.mcpUrl.replace('https://', 'http://');
    const error = await failure(fetch(httpUrl, { method: 'POST', headers: MCP_HEADERS, body: JSON.stringify(initializeRequest()) }));
    expect(error).toMatch(/fetch failed|ECONNRESET|socket hang up|EPIPE/i);
  });

  it('client trusting the wrong CA → client-side server-certificate verification error', async () => {
    const error = await failure(rawInit(server.mcpUrl, 'alice', { ca: readPem(certs, 'rogue-ca.crt') }));
    expect(error).toMatch(/UNABLE_TO_VERIFY_LEAF_SIGNATURE|SELF_SIGNED_CERT_IN_CHAIN|UNABLE_TO_GET_ISSUER_CERT|unable to (verify|get)|self.signed/i);
  });

  it('TLS 1.2-only client → rejected (server requires TLS 1.3)', async () => {
    const error = await failure(rawInit(server.mcpUrl, 'alice', { maxVersion: 'TLSv1.2' }));
    expect(error).toMatch(/protocol.version|ERR_SSL|ECONNRESET/i);
  });

  it('MTLS_SOFT_FAIL variant: no certificate reaches the app and gets 401 JSON; a good one still works', async () => {
    const denied = await rawInit(soft.mcpUrl, 'none');
    expect(denied.status).toBe(401);
    expect(denied.errorMessage).toBe('Unauthorized: a valid client certificate is required');
    const ok = await rawInit(soft.mcpUrl, 'alice');
    expect(ok.status).toBe(200);
  });
});
