/**
 * oauth-cli.ts — an OAuthClientProvider for command-line MCP clients.
 *
 * The SDK drives the whole OAuth 2.1 dance (discovery → DCR → PKCE → redirect → code exchange →
 * refresh); this class only supplies what a CLI has to decide for itself:
 *   - where tokens / client registration / PKCE verifier / state are persisted (a JSON file)
 *   - the redirect URI and a loopback HTTP listener that receives the authorization code
 *   - how to show the authorization URL to the human (print it, try to open a browser)
 *
 * Used by every browser-based example (03, 04, 06, 10) — the example's client.ts stays tiny.
 */
import { REPO_ROOT, port as envPort } from '../env.ts';
import { createHash, randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { UnauthorizedError, type OAuthClientProvider } from '@modelcontextprotocol/sdk/client/auth.js';
import type { OAuthClientInformationMixed, OAuthClientMetadata, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);
const DEFAULT_CALLBACK_TIMEOUT_MS = 5 * 60_000;

export interface StaticClient {
  client_id: string;
  client_secret?: string;
}

export interface CliOAuthProviderOptions {
  /** The MCP endpoint URL; part of the store-file key so each server gets its own tokens. */
  serverUrl: string;
  /** Fallback scope when neither WWW-Authenticate nor PRM say otherwise. NEVER include `openid`. */
  scope?: string;
  clientName?: string;
  /** Pre-registered client → skips Dynamic Client Registration. Default: env OAUTH_CLIENT_ID. */
  staticClient?: StaticClient;
  /** Host in the redirect URI (env OAUTH_REDIRECT_HOST, default 127.0.0.1). Must match what the AS has registered. */
  redirectHost?: string;
  /** Port of the loopback listener (env OAUTH_CALLBACK_PORT, default 4199). */
  callbackPort?: number;
  /** Directory of the token store (env MCP_AUTH_STORE_DIR, default <repo>/.mcp-auth, git-ignored). */
  storeDir?: string;
}

/** What survives between runs (and between the redirect and the callback). */
interface StoredState {
  client?: OAuthClientInformationMixed;
  tokens?: OAuthTokens;
  codeVerifier?: string;
  state?: string;
}

export class CliOAuthProvider implements OAuthClientProvider {
  readonly serverUrl: string;
  readonly scope: string;
  readonly clientName: string;
  readonly redirectHost: string;
  readonly callbackPort: number;
  readonly storeFile: string;
  private readonly staticClient?: StaticClient;
  private data: StoredState;
  private listener?: CallbackListener;

  constructor(options: CliOAuthProviderOptions) {
    this.serverUrl = options.serverUrl;
    this.scope = options.scope ?? 'mcp:tools';
    if (this.scope.split(' ').includes('openid')) {
      throw new Error("scope must not contain 'openid': Keycloak's DCR policy rejects it and MCP does not need an id_token");
    }
    this.clientName = options.clientName ?? 'mcp-auth-demo cli';
    // An EMPTY client_secret must become undefined: the SDK treats `client_secret !== undefined` as
    // "confidential client" and would send client_secret_basic with an empty password.
    const staticClient = options.staticClient ?? (process.env.OAUTH_CLIENT_ID ? { client_id: process.env.OAUTH_CLIENT_ID, client_secret: process.env.OAUTH_CLIENT_SECRET } : undefined);
    this.staticClient = staticClient && { client_id: staticClient.client_id, client_secret: staticClient.client_secret || undefined };
    this.redirectHost = options.redirectHost ?? process.env.OAUTH_REDIRECT_HOST?.trim() ?? '127.0.0.1';
    this.callbackPort = options.callbackPort ?? envPort('OAUTH_CALLBACK_PORT', 4199);
    const storeDir = options.storeDir ?? process.env.MCP_AUTH_STORE_DIR?.trim() ?? join(REPO_ROOT, '.mcp-auth');
    // The client id is part of the key: switching between Dynamic Client Registration and a
    // pre-registered client (OAUTH_CLIENT_ID=mcp-cli) must not replay the other one's tokens, which
    // would silently connect as the wrong client — and, if the stored tokens are still valid, as the
    // wrong USER, since a run that expects a fresh login would never open the browser.
    const identity = `${this.serverUrl}\u0000${this.clientName}\u0000${this.staticClient?.client_id ?? 'dcr'}`;
    const key = createHash('sha256').update(identity).digest('hex').slice(0, 16);
    this.storeFile = join(storeDir, `${key}.json`);
    this.data = this.load();
  }

  // ------------------------------------------------------------ OAuthClientProvider

  /** Defined → interactive authorization-code flow. */
  get redirectUrl(): string {
    return `http://${this.redirectHost}:${this.callbackPort}/callback`;
  }

  /** RFC 7591 metadata sent on Dynamic Client Registration. Public client (PKCE instead of a secret). */
  get clientMetadata(): OAuthClientMetadata {
    return {
      client_name: this.clientName,
      redirect_uris: [this.redirectUrl],
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      scope: this.scope,
    };
  }

  /** Fresh CSRF state per authorization request; persisted so the callback can check it. */
  state(): string {
    this.data.state = randomBytes(16).toString('hex');
    this.save();
    return this.data.state;
  }

  clientInformation(): OAuthClientInformationMixed | undefined {
    return this.staticClient ?? this.data.client;
  }

  saveClientInformation(info: OAuthClientInformationMixed): void {
    this.data.client = info;
    this.save();
  }

  tokens(): OAuthTokens | undefined {
    return this.data.tokens;
  }

  saveTokens(tokens: OAuthTokens): void {
    this.data.tokens = tokens;
    this.save();
  }

  saveCodeVerifier(codeVerifier: string): void {
    this.data.codeVerifier = codeVerifier;
    this.save();
  }

  codeVerifier(): string {
    if (!this.data.codeVerifier) throw new Error('No PKCE code verifier saved — start the authorization flow first');
    return this.data.codeVerifier;
  }

  /** Called by the SDK on invalid_client / invalid_grant so the next attempt starts clean. */
  invalidateCredentials(scope: 'all' | 'client' | 'tokens' | 'verifier' | 'discovery'): void {
    if (scope === 'all') this.data = {};
    if (scope === 'client') delete this.data.client;
    if (scope === 'tokens') delete this.data.tokens;
    if (scope === 'verifier') delete this.data.codeVerifier;
    this.save();
  }

  /**
   * Called by the SDK (awaited) right before auth() returns 'REDIRECT'. Starts the loopback
   * listener FIRST — a browser with an existing SSO session redirects back within milliseconds —
   * then shows the URL and tries a browser unless MCP_NO_BROWSER=1. Nothing is bound when stored
   * tokens work, so a second run neither touches the callback port nor keeps the process alive.
   */
  async redirectToAuthorization(authorizationUrl: URL): Promise<void> {
    await this.startCallbackListener();
    console.log('\n==> Authorization required. Open this URL in a browser:\n');
    console.log(`    ${authorizationUrl.href}\n`);
    if (process.env.MCP_NO_BROWSER !== '1') openBrowser(authorizationUrl.href);
  }

  // ------------------------------------------------------------ CLI extras

  /** Starts the loopback listener unless one is already waiting; resolves once the port is bound. */
  startCallbackListener(): Promise<void> {
    if (!this.listener || this.listener.settled) {
      this.listener = new CallbackListener({
        port: this.callbackPort,
        // Bound to 127.0.0.1 when the redirect host is loopback, otherwise to 0.0.0.0 (LAN callback).
        bindHost: LOOPBACK_HOSTS.has(this.redirectHost) ? '127.0.0.1' : '0.0.0.0',
        redirectUrl: this.redirectUrl,
        expectedState: () => this.data.state,
      });
    }
    return this.listener.bound;
  }

  /**
   * Resolves with the authorization code from GET /callback?code=…&state=… (the listener is
   * started if redirectToAuthorization() has not done so already). Rejects on timeout, on an
   * `error` callback from the AS, or when cancelCallback() is called. Either way the listener is
   * closed and the timer cleared, so the process can exit.
   */
  waitForCallback({ timeoutMs = DEFAULT_CALLBACK_TIMEOUT_MS }: { timeoutMs?: number } = {}): Promise<string> {
    if (!this.listener) void this.startCallbackListener(); // bind errors surface through `code`
    const listener = this.listener!;
    listener.armTimeout(timeoutMs);
    const consumed = () => {
      if (this.listener === listener) this.listener = undefined; // the next round starts fresh
    };
    listener.code.then(consumed, consumed);
    return listener.code;
  }

  /** Stops the loopback listener if it is running; a pending waitForCallback() rejects. No-op otherwise. */
  cancelCallback(): void {
    this.listener?.cancel();
    this.listener = undefined;
  }

  /** True while the loopback listener is bound (for tests and diagnostics). */
  get callbackListening(): boolean {
    return this.listener !== undefined && !this.listener.settled;
  }

  /** The state value of the current authorization request (for tests). */
  expectedState(): string | undefined {
    return this.data.state;
  }

  /** Forget tokens only; the client registration is kept. */
  clearTokens(): void {
    delete this.data.tokens;
    delete this.data.codeVerifier;
    delete this.data.state;
    this.save();
  }

  /** Forget everything, including a dynamically registered client. */
  clearAll(): void {
    this.data = {};
    if (existsSync(this.storeFile)) unlinkSync(this.storeFile);
  }

  // ------------------------------------------------------------ persistence

  private load(): StoredState {
    if (!existsSync(this.storeFile)) return {};
    try {
      return JSON.parse(readFileSync(this.storeFile, 'utf8')) as StoredState;
    } catch {
      return {};
    }
  }

  private save(): void {
    mkdirSync(dirname(this.storeFile), { recursive: true, mode: 0o700 });
    writeFileSync(this.storeFile, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    chmodSync(this.storeFile, 0o600); // mode above only applies when the file is created
  }
}

interface CallbackListenerOptions {
  port: number;
  bindHost: string;
  redirectUrl: string;
  /** The `state` the provider issued for the current authorization request (undefined before). */
  expectedState: () => string | undefined;
}

/**
 * One-shot HTTP listener for the authorization-code redirect. Settles `code` exactly once —
 * with the code, or with an Error (AS error, timeout, cancel, bind failure) — and closes itself.
 * Requests whose `state` is missing or does not match are answered 400 and otherwise IGNORED
 * (the real redirect may still be on its way): a stale tab or a forged request cannot end the
 * flow, and no code is accepted before the provider has issued a state.
 */
class CallbackListener {
  /** Resolves with the authorization code. */
  readonly code: Promise<string>;
  /** Resolves once the port is bound (rejects on e.g. EADDRINUSE). */
  readonly bound: Promise<void>;
  settled = false;
  private timer?: NodeJS.Timeout;
  private readonly server: Server;
  private resolveCode!: (code: string) => void;
  private rejectCode!: (error: Error) => void;

  constructor(private readonly options: CallbackListenerOptions) {
    this.code = new Promise<string>((resolve, reject) => {
      this.resolveCode = resolve;
      this.rejectCode = reject;
    });
    this.code.catch(() => undefined); // may settle before anyone awaits it — not an unhandled rejection
    this.server = createServer((req, res) => this.handle(req, res));
    this.bound = new Promise<void>((resolve, reject) => {
      this.server.once('error', (error) => {
        this.settle(error);
        reject(error);
      });
      this.server.listen(options.port, options.bindHost, () => {
        console.error(`[oauth] waiting for callback on http://${options.bindHost}:${options.port}/callback (redirect URI ${options.redirectUrl})`);
        resolve();
      });
    });
    this.bound.catch(() => undefined);
  }

  /** (Re)arms the timeout. unref(): a forgotten timer must never keep the process alive. */
  armTimeout(timeoutMs: number): void {
    if (this.settled) return;
    clearTimeout(this.timer);
    this.timer = setTimeout(() => this.settle(new Error(`timed out after ${timeoutMs} ms waiting for the OAuth callback`)), timeoutMs);
    this.timer.unref();
  }

  cancel(): void {
    this.settle(new Error('OAuth callback cancelled'));
  }

  private settle(error?: Error, code?: string): void {
    if (this.settled) return;
    this.settled = true;
    clearTimeout(this.timer);
    this.server.close();
    this.server.closeAllConnections?.();
    error ? this.rejectCode(error) : this.resolveCode(code!);
  }

  private handle(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url ?? '/', 'http://localhost'); // loopback-ok: parse base only, never dialled
    if (url.pathname !== '/callback') {
      res.writeHead(404).end('not found');
      return;
    }
    const expected = this.options.expectedState();
    if (!expected || url.searchParams.get('state') !== expected) {
      console.error('[oauth] ignoring a callback with a missing or unexpected state parameter');
      res.writeHead(400, { 'content-type': 'text/html' }).end(page('State mismatch', 'This callback does not belong to the current login. Use the newest URL printed in the terminal.'));
      return; // keep listening
    }
    const code = url.searchParams.get('code');
    const error = url.searchParams.get('error');
    if (error || !code) {
      // Query values are attacker-controlled: print them to the terminal, never into the page.
      console.error(`[oauth] authorization failed: ${error ?? 'no code in callback'} ${url.searchParams.get('error_description') ?? ''}`.trim());
      res.writeHead(400, { 'content-type': 'text/html' }).end(page('Authorization failed', 'See the terminal for details.'));
      this.settle(new Error(`authorization failed: ${error ?? 'no code in callback'}`));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' }).end(page('Authorized', 'You can close this tab and return to the terminal.'));
    this.settle(undefined, code);
  }
}

/** Static text only — nothing from the request is ever interpolated here. */
function page(title: string, body: string): string {
  return `<!doctype html><meta charset="utf-8"><title>${title}</title><body style="font-family:system-ui;margin:3rem"><h1>${title}</h1><p>${body}</p></body>`;
}

/**
 * Best-effort browser launch; failures are ignored (the URL was printed anyway).
 * MCP_BROWSER_CMD replaces the platform opener — smoke tests and CI point it at
 * `python3 scripts/browser-login.py --user alice --password password`, which logs in headlessly.
 * The URL is passed as the last argument (single-quoted for the shell) and the driver's output
 * goes to this process's stderr so a failing login is visible in the terminal.
 */
export function openBrowser(url: string): void {
  const driver = process.env.MCP_BROWSER_CMD?.trim();
  const [cmd, args, stdio]: [string, string[], 'ignore' | ['ignore', 2, 2]] = driver
    ? ['sh', ['-c', `${driver} '${url.replaceAll("'", '%27')}'`], ['ignore', 2, 2]] // fd 2 = our stderr
    : process.platform === 'darwin'
      ? ['open', [url], 'ignore']
      : process.platform === 'win32'
        ? ['cmd', ['/c', 'start', '', url.replaceAll('&', '^&')], 'ignore'] // cmd.exe splits on unescaped &
        : ['xdg-open', [url], 'ignore'];
  try {
    const child = spawn(cmd, args, { stdio, detached: true });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    /* ignore */
  }
}

/** Convenience: forget tokens for this server. */
export function clearTokens(provider: CliOAuthProvider): void {
  provider.clearTokens();
}

/**
 * The `--logout` flag pattern for example clients:
 *   if (handleLogoutFlag(provider)) process.exit(0);
 * Returns true when `--logout` was present (tokens and registration are wiped).
 */
export function handleLogoutFlag(provider: CliOAuthProvider, argv: string[] = process.argv): boolean {
  if (!argv.includes('--logout')) return false;
  provider.clearAll();
  console.log(`Logged out: removed ${provider.storeFile}`);
  return true;
}

export interface ConnectWithOAuthOptions {
  serverUrl: string;
  provider: CliOAuthProvider;
  clientName?: string;
  clientVersion?: string;
  /** How long to wait for the browser round-trip (default 5 min). */
  timeoutMs?: number;
}

/**
 * Connects an SDK Client through the provider. First attempt: if stored tokens work (or refresh
 * works) we are done and nothing else happened. Otherwise the SDK called redirectToAuthorization()
 * (listener up, browser opened) and threw UnauthorizedError; we wait for the loopback callback,
 * exchange the code via transport.finishAuth(), and connect again with a NEW transport (the failed
 * one is closed). Any failure tears the listener down so the process can exit.
 */
export async function connectWithOAuth({ serverUrl, provider, clientName = 'mcp-auth-demo cli', clientVersion = '0.1.0', timeoutMs }: ConnectWithOAuthOptions) {
  const client = new Client({ name: clientName, version: clientVersion });
  const url = new URL(serverUrl);

  let transport = new StreamableHTTPClientTransport(url, { authProvider: provider });
  try {
    await client.connect(transport);
    return { client, transport };
  } catch (error) {
    if (!(error instanceof UnauthorizedError)) {
      provider.cancelCallback();
      throw error;
    }
  }

  try {
    const code = await provider.waitForCallback({ timeoutMs }); // human logs in; the AS redirects to our listener
    await transport.finishAuth(code); // POST token endpoint: code + PKCE verifier → saveTokens()
    transport = new StreamableHTTPClientTransport(url, { authProvider: provider });
    await client.connect(transport); // now carries Authorization: Bearer <access_token>
    return { client, transport };
  } catch (error) {
    provider.cancelCallback();
    throw error;
  }
}
