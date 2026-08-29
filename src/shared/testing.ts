/**
 * testing.ts — helpers for the Vitest integration tests of every example.
 *
 *   startTestServer(app)            ephemeral port on 127.0.0.1
 *   mcpPost / initializeSession /   raw HTTP (node:http, so tests can forge the Host header —
 *   rawCallTool                     Node's fetch silently ignores a custom Host)
 *   connectClient / callTool        the real SDK client, for end-to-end assertions
 *   wwwAuthenticate / expectOAuth401  assert the 401 challenge a resource server must send
 *   testKeyPair / mintLocalJwt      in-process RS256/ES256 keys for hermetic negative matrices
 *   spawnExample / waitForHttp      run a real example process (Python twin, smoke)
 *   isKeycloakUp / keycloak*Token   tokens straight from Keycloak for Keycloak-backed examples
 *
 * Tests that need Keycloak wrap themselves in `describe.skipIf(!(await isKeycloakUp()))` so the
 * suite stays green on a machine without Docker; `REQUIRE_KEYCLOAK=1` (npm run test:kc) turns
 * such a skip into a failure.
 */
import { REPO_ROOT, keycloak, publicUrl } from './env.ts';
import { spawn, type ChildProcess } from 'node:child_process';
import { request as httpRequest, type IncomingHttpHeaders, type Server } from 'node:http';
import { createServer as createTcpServer } from 'node:net';
import type { Express } from 'express';
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey, type JSONWebKeySet, type JWK, type JWTPayload } from 'jose';
import { jsonRpcErrorHandler, notFoundHandler } from './http.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import type { OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { LATEST_PROTOCOL_VERSION, type CallToolResult } from '@modelcontextprotocol/sdk/types.js';

/** Streamable HTTP is strict: POST needs BOTH accept values and a JSON content type (406/415 otherwise). */
export const MCP_HEADERS: Record<string, string> = {
  accept: 'application/json, text/event-stream',
  'content-type': 'application/json',
};

export interface TestServer {
  baseUrl: string;
  server: Server;
  close(): Promise<void>;
}

/** Listens on an ephemeral 127.0.0.1 port; baseUrl is `http://127.0.0.1:<port>`. */
export function startTestServer(app: Express): Promise<TestServer> {
  app.use(notFoundHandler); // same as listen(): JSON 404s and no HTML stack traces
  app.use(jsonRpcErrorHandler);
  return new Promise((resolve, reject) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') return reject(new Error('unexpected server address'));
      resolve({
        baseUrl: `http://127.0.0.1:${address.port}`,
        server,
        close: () =>
          new Promise<void>((done) => {
            server.closeAllConnections?.();
            server.close(() => done());
          }),
      });
    });
    server.on('error', reject);
  });
}

/** An unused TCP port on 127.0.0.1 (for tests that must know the port before binding it). */
export function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createTcpServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

export interface JsonRpcMessage {
  jsonrpc: '2.0';
  id?: number | string | null;
  method?: string;
  params?: unknown;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export interface RawResponse {
  status: number;
  headers: IncomingHttpHeaders;
  text: string;
  /** Parses a JSON body. */
  json<T = unknown>(): T;
  /** JSON-RPC messages from either a JSON body or an SSE body (`data:` lines). */
  messages(): JsonRpcMessage[];
}

export interface RawRequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

/** Plain node:http request. Unlike fetch it sends whatever Host header you give it. */
export function rawRequest(url: string, { method = 'GET', headers = {}, body }: RawRequestOptions = {}): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(url, { method, headers }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          text,
          json: <T>() => JSON.parse(text) as T,
          messages: () => parseJsonRpcBody(text, res.headers['content-type']),
        });
      });
      res.on('error', reject);
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Extracts JSON-RPC messages from a JSON or text/event-stream body. */
export function parseJsonRpcBody(text: string, contentType = ''): JsonRpcMessage[] {
  if (!text.trim()) return [];
  if (!contentType.includes('text/event-stream')) {
    const parsed = JSON.parse(text) as JsonRpcMessage | JsonRpcMessage[];
    return Array.isArray(parsed) ? parsed : [parsed];
  }
  return text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => JSON.parse(line.slice(5).trim()) as JsonRpcMessage);
}

/** POST a JSON-RPC message with the headers Streamable HTTP requires (extra headers win). */
export function mcpPost(url: string, jsonRpc: unknown, headers: Record<string, string> = {}): Promise<RawResponse> {
  return rawRequest(url, { method: 'POST', headers: { ...MCP_HEADERS, ...headers }, body: JSON.stringify(jsonRpc) });
}

export const initializeRequest = (id: number | string = 1): JsonRpcMessage => ({
  jsonrpc: '2.0',
  id,
  method: 'initialize',
  params: { protocolVersion: LATEST_PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'test-client', version: '0.0.0' } },
});

/** Sends `initialize` and returns the session id from the `mcp-session-id` response header. */
export async function initializeSession(url: string, headers: Record<string, string> = {}) {
  const response = await mcpPost(url, initializeRequest(), headers);
  const sessionId = response.headers['mcp-session-id'];
  return { sessionId: typeof sessionId === 'string' ? sessionId : undefined, response };
}

/** Raw `tools/call` on an existing session; `result` is undefined when the call did not succeed. */
export async function rawCallTool(url: string, sessionId: string, name: string, args: Record<string, unknown> = {}, headers: Record<string, string> = {}) {
  const response = await mcpPost(
    url,
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name, arguments: args } },
    { 'mcp-session-id': sessionId, ...headers },
  );
  const reply = response.status === 200 ? response.messages().find((m) => m.id === 2) : undefined;
  return { response, result: reply?.result as CallToolResult | undefined, error: reply?.error };
}

export interface ConnectClientOptions {
  /** Static headers (e.g. `Authorization: Bearer …`); they override provider headers. */
  headers?: Record<string, string>;
  authProvider?: OAuthClientProvider;
  name?: string;
}

/** A connected SDK client. `close()` terminates the server session and closes the transport. */
export async function connectClient(url: string, { headers, authProvider, name = 'test-client' }: ConnectClientOptions = {}) {
  const client = new Client({ name, version: '0.0.0' });
  const transport = new StreamableHTTPClientTransport(new URL(url), {
    authProvider,
    requestInit: headers ? { headers } : undefined,
  });
  await client.connect(transport);
  return {
    client,
    transport,
    close: async () => {
      await transport.terminateSession().catch(() => undefined);
      await client.close();
    },
  };
}

export { callTool, toolOutcome, type ToolOutcome } from './client/run.ts';

// ---------------------------------------------------------------- bearer challenges

export interface WwwAuthenticate {
  scheme?: string;
  error?: string;
  error_description?: string;
  scope?: string;
  resource_metadata?: string;
  [param: string]: string | undefined;
}

/** Parses `WWW-Authenticate: Bearer error="…", scope="…", resource_metadata="…"` (raw or fetch response). */
export function wwwAuthenticate(res: RawResponse | Response): WwwAuthenticate {
  const header = 'headers' in res && typeof (res.headers as Headers).get === 'function' ? (res.headers as Headers).get('www-authenticate') : (res.headers as IncomingHttpHeaders)['www-authenticate'];
  if (!header) return {};
  const value = Array.isArray(header) ? header[0] : header;
  const [scheme, rest = ''] = value.split(/\s+(.*)/s);
  const params: WwwAuthenticate = { scheme };
  for (const match of rest.matchAll(/([a-zA-Z_]+)="([^"]*)"/g)) params[match[1]] = match[2];
  return params;
}

export interface ExpectOAuth401Options {
  /** Expected `resource_metadata` value; `false` asserts it is ABSENT (examples 01/02). */
  resourceMetadata?: string | false;
  scope?: string;
  /** Default `invalid_token`. */
  error?: string;
}

/** Asserts a 401 with a well-formed Bearer challenge — the response every OAuth client discovery starts from. */
export function expectOAuth401(res: RawResponse, { resourceMetadata, scope, error = 'invalid_token' }: ExpectOAuth401Options = {}): void {
  if (res.status !== 401) throw new Error(`expected 401, got ${res.status}: ${res.text.slice(0, 200)}`);
  const challenge = wwwAuthenticate(res);
  if (challenge.scheme?.toLowerCase() !== 'bearer') throw new Error(`expected a Bearer challenge, got WWW-Authenticate: ${res.headers['www-authenticate']}`);
  if (challenge.error !== error) throw new Error(`expected error="${error}", got "${challenge.error}"`);
  if (typeof resourceMetadata === 'string' && challenge.resource_metadata !== resourceMetadata) {
    throw new Error(`expected resource_metadata="${resourceMetadata}", got "${challenge.resource_metadata}"`);
  }
  if (resourceMetadata === false && challenge.resource_metadata !== undefined) throw new Error(`expected no resource_metadata, got "${challenge.resource_metadata}"`);
  if (scope !== undefined && challenge.scope !== scope) throw new Error(`expected scope="${scope}", got "${challenge.scope}"`);
}

// ---------------------------------------------------------------- local JWTs (hermetic tests)

/** Decodes the payload of a JWT WITHOUT verifying it — for inspecting claims in tests only. */
export function decodeJwtPayload(token: string): JWTPayload {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('not a JWT');
  return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as JWTPayload;
}

export interface TestKeyPair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: JWK;
  jwks: JSONWebKeySet;
  kid: string;
  alg: 'RS256' | 'ES256';
}

/** A fresh signing key pair with a `kid`, as a JWK Set a verifier can use directly. */
export async function testKeyPair(alg: 'RS256' | 'ES256' = 'RS256', kid = `test-${alg.toLowerCase()}`): Promise<TestKeyPair> {
  const { privateKey, publicKey } = await generateKeyPair(alg);
  const publicJwk: JWK = { ...(await exportJWK(publicKey)), kid, alg, use: 'sig' };
  return { privateKey, publicKey, publicJwk, jwks: { keys: [publicJwk] }, kid, alg };
}

export interface MintOptions {
  key: CryptoKey;
  kid?: string;
  alg?: 'RS256' | 'ES256';
  issuer: string;
  audience: string | string[];
  sub?: string;
  /** Space-separated `scope` claim (default `mcp:tools`). */
  scope?: string;
  /** `realm_access.roles` (Keycloak shape). */
  roles?: string[];
  /** jose duration ('5m', '-1m', …) or absolute epoch seconds. Default '5m'. */
  expiresIn?: string | number;
  azp?: string;
  /** Username claim (`preferred_username`), default `sub`. */
  username?: string;
  extraClaims?: Record<string, unknown>;
}

/** Mints a Keycloak-shaped access token with a local key (see testKeyPair()). */
export async function mintLocalJwt({ key, kid = 'test-rs256', alg = 'RS256', issuer, audience, sub = 'user-1', scope = 'mcp:tools', roles = ['mcp-user'], expiresIn = '5m', azp = 'mcp-cli', username, extraClaims = {} }: MintOptions): Promise<string> {
  return new SignJWT({ scope, azp, preferred_username: username ?? sub, realm_access: { roles }, typ: 'Bearer', ...extraClaims })
    .setProtectedHeader({ alg, kid })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(sub)
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(key);
}

// ---------------------------------------------------------------- example processes

/** Polls `url` until it answers with one of `okStatus` (default 200) or the timeout elapses. */
export async function waitForHttp(url: string, { timeoutMs = 20_000, okStatus = [200], intervalMs = 250, fetchFn = fetch }: { timeoutMs?: number; okStatus?: number[]; intervalMs?: number; fetchFn?: typeof fetch } = {}): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError = 'no response';
  while (Date.now() < deadline) {
    try {
      const res = await fetchFn(url, { signal: AbortSignal.timeout(intervalMs * 4) });
      if (okStatus.includes(res.status)) return;
      lastError = `HTTP ${res.status}`;
    } catch (error) {
      lastError = (error as Error).message;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  throw new Error(`timed out after ${timeoutMs} ms waiting for ${url} (${lastError})`);
}

export interface SpawnedExample {
  child: ChildProcess;
  stdout: () => string;
  stderr: () => string;
  /** SIGTERM, then SIGKILL after 3 s; resolves once the process has exited. */
  stop(): Promise<void>;
  /** Resolves with the exit code once the process ends on its own. */
  exited: Promise<number | null>;
}

export interface SpawnExampleOptions {
  /** URL that must answer 200 before the promise resolves (default `<publicUrl(port)>/healthz`; `false` = do not wait). */
  readyUrl?: string | false;
  timeoutMs?: number;
  /** Extra CLI arguments after the script. */
  args?: string[];
  /** Used for the default readyUrl. */
  port?: number;
}

/**
 * Spawns `node --import tsx <script>` (or `uv run --project <dir> python <script>` for `.py`, or
 * `bash <script>` for `.sh`) with cwd = repo root, capturing stdout/stderr, and resolves when
 * `readyUrl` answers 200. Used by the Python twin's tests and by scripts/smoke.ts; hermetic tests
 * should import buildApp() instead. No `npx`/`tsx` wrapper process: signals must reach the server
 * itself, otherwise stop() leaves an orphan listening on the port.
 */
export async function spawnExample(script: string, envOverrides: Record<string, string> = {}, { readyUrl, timeoutMs = 30_000, args = [], port }: SpawnExampleOptions = {}): Promise<SpawnedExample> {
  const projectDir = script.slice(0, script.lastIndexOf('/')) || '.';
  const [cmd, cmdArgs] = script.endsWith('.py')
    ? ['uv', ['run', '--project', projectDir, 'python', script, ...args]] // uv exec()s python: no wrapper
    : script.endsWith('.sh')
      ? ['bash', [script, ...args]]
      : [process.execPath, ['--import', 'tsx', script, ...args]];
  // Own process group so stop() can kill everything the script started (bash → openssl, …).
  const child = spawn(cmd, cmdArgs, { cwd: REPO_ROOT, env: { ...process.env, ...envOverrides }, stdio: ['ignore', 'pipe', 'pipe'], detached: true });
  let out = '';
  let err = '';
  child.stdout?.on('data', (c: Buffer) => (out += c.toString()));
  child.stderr?.on('data', (c: Buffer) => (err += c.toString()));
  const exited = new Promise<number | null>((resolve) => child.once('exit', (code) => resolve(code)));
  const spawned: SpawnedExample = {
    child,
    stdout: () => out,
    stderr: () => err,
    exited,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) return;
      const signal = (sig: NodeJS.Signals) => {
        try {
          process.kill(-child.pid!, sig); // the whole process group
        } catch {
          child.kill(sig);
        }
      };
      signal('SIGTERM');
      const killer = setTimeout(() => signal('SIGKILL'), 3000);
      await exited;
      clearTimeout(killer);
    },
  };
  const url = readyUrl === false ? undefined : (readyUrl ?? (port !== undefined ? publicUrl(port, '/healthz') : undefined));
  if (url) {
    try {
      await Promise.race([
        waitForHttp(url, { timeoutMs }),
        exited.then((code) => {
          throw new Error(`${script} exited with code ${code} before ${url} was ready:\n${err.slice(-2000)}`);
        }),
      ]);
    } catch (error) {
      await spawned.stop();
      throw error;
    }
  }
  return spawned;
}

// ---------------------------------------------------------------- Keycloak helpers

let keycloakProbe: Promise<boolean> | undefined;

// process.stderr directly: vitest hides console.* output of files whose tests are all skipped.
const notReachable = (url: string, why: string) =>
  process.stderr.write(`\nskipped: Keycloak not reachable at ${url} (${why}) — start it with: npm run kc:up\n`);

/**
 * True when the realm's discovery document answers within 2 s. Logs once when it does not.
 * With REQUIRE_KEYCLOAK=1 (npm run test:kc) an unreachable Keycloak throws instead, so a skipped
 * suite can never pass CI silently.
 */
export function isKeycloakUp(): Promise<boolean> {
  keycloakProbe ??= (async () => {
    const { discoveryUrl } = keycloak();
    let why: string;
    try {
      const res = await fetch(discoveryUrl, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return true;
      why = `HTTP ${res.status}`;
    } catch (error) {
      why = (error as Error).message;
    }
    if (process.env.REQUIRE_KEYCLOAK === '1') throw new Error(`REQUIRE_KEYCLOAK=1 but Keycloak is not reachable at ${discoveryUrl} (${why})`);
    notReachable(discoveryUrl, why);
    return false;
  })();
  return keycloakProbe;
}

async function tokenRequest(form: Record<string, string>, basicAuth?: { clientId: string; clientSecret: string }): Promise<OAuthTokens> {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
  if (basicAuth) headers.authorization = `Basic ${Buffer.from(`${basicAuth.clientId}:${basicAuth.clientSecret}`).toString('base64')}`;
  const res = await fetch(keycloak().tokenEndpoint, { method: 'POST', headers, body: new URLSearchParams(form) });
  const body = (await res.json()) as OAuthTokens & { error?: string; error_description?: string };
  if (!res.ok) throw new Error(`Keycloak token request failed (${res.status}): ${body.error} ${body.error_description ?? ''}`);
  return body;
}

export interface PasswordTokenOptions {
  username: string;
  password: string;
  scope?: string;
  /** Default `mcp-test` — the only client in the realm with the password grant enabled. */
  clientId?: string;
}

/**
 * Resource Owner Password grant — DEMO/TEST ONLY (the grant was removed from OAuth 2.1). The realm
 * enables it on the dedicated `mcp-test` client purely so headless tests can obtain user tokens
 * without a browser; `mcp-cli` deliberately has it switched off.
 */
export function keycloakPasswordToken({ username, password, scope = 'mcp:tools', clientId = 'mcp-test' }: PasswordTokenOptions): Promise<OAuthTokens> {
  return tokenRequest({ grant_type: 'password', client_id: clientId, username, password, scope });
}

export interface ClientCredentialsOptions {
  clientId: string;
  clientSecret: string;
  scope?: string;
}

/** Client Credentials grant (service account) with HTTP Basic client authentication. */
export function keycloakClientCredentials({ clientId, clientSecret, scope = 'mcp:tools' }: ClientCredentialsOptions): Promise<OAuthTokens> {
  return tokenRequest({ grant_type: 'client_credentials', scope }, { clientId, clientSecret });
}
