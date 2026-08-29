/**
 * http.ts — Express 5 bootstrap shared by every example server.
 *
 *   createApp()  → express app: Host-header check, JSON body parser, request log, GET /healthz,
 *                  JSON-RPC error handler (no HTML stack traces)
 *   mountMcp()   → Streamable HTTP endpoint (stateful sessions by default) + optional auth middleware
 *   listen()     → bind 0.0.0.0 and print the canonical public URL
 *
 * Deliberately NOT using the SDK's createMcpExpressApp(): its defaults (127.0.0.1 + localhost-only
 * Host validation) reject every request from another LAN machine, which is how this demo is used.
 */
import { publicHost, publicHostSource, publicUrl } from './env.ts';
import { randomUUID } from 'node:crypto';
import type { Server } from 'node:http';
import type { Server as HttpsServer } from 'node:https';
import express, { type ErrorRequestHandler, type Express, type Request, type RequestHandler, type Response } from 'express';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { hostHeaderValidation } from '@modelcontextprotocol/sdk/server/middleware/hostHeaderValidation.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';

// requireBearerAuth() stores the verified token as `req.auth`; the type augmentation lives in the
// SDK's bearerAuth.d.ts, so we declare the same shape here for modules that never import it.
type AuthedRequest = Request & { auth?: AuthInfo };

/** Stable identity of a caller: the token subject when present, otherwise the client id. */
export function subjectOf(authInfo: AuthInfo | undefined): string | undefined {
  if (!authInfo) return undefined;
  const sub = authInfo.extra?.sub;
  return typeof sub === 'string' && sub ? sub : authInfo.clientId;
}

/**
 * Hostnames (no port) accepted in the Host header — DNS-rebinding protection. Lower-cased: the
 * SDK middleware compares against `URL.hostname`, which is always lower case.
 */
export function allowedHostnames(extra: string[] = []): string[] {
  const fromEnv = (process.env.MCP_ALLOWED_HOSTS ?? '').split(',').map((h) => h.trim()).filter(Boolean);
  return [...new Set([publicHost(), 'localhost', '127.0.0.1', '[::1]', ...fromEnv, ...extra].map((h) => h.toLowerCase()))];
}

const jsonRpcError = (res: Response, status: number, code: number, message: string) => {
  res.status(status).json({ jsonrpc: '2.0', error: { code, message }, id: null });
};

/** Catch-all for unknown routes: a JSON-RPC 404 instead of Express's HTML "Cannot GET /x" page. */
export const notFoundHandler: RequestHandler = (req, res) => {
  jsonRpcError(res, 404, -32000, `Not Found: ${req.method} ${req.path}`);
};

/**
 * Final error handler: JSON-RPC bodies instead of Express's default HTML page with a stack trace.
 * body-parser errors carry `status`/`type` (invalid JSON → 400, too large → 413, …); anything
 * else is a bug and becomes a 500 that is logged to stderr, never echoed to the client.
 */
export const jsonRpcErrorHandler: ErrorRequestHandler = (error: unknown, req, res, next) => {
  if (res.headersSent) return next(error);
  const { status, type } = (error ?? {}) as { status?: unknown; type?: unknown };
  if (typeof status === 'number' && status >= 400 && status < 500) {
    const parseFailed = type === 'entity.parse.failed';
    jsonRpcError(res, status, parseFailed ? -32700 : -32600, parseFailed ? 'Parse error: invalid JSON body' : `Bad Request: ${typeof type === 'string' ? type : 'invalid request'}`);
    return;
  }
  console.error(`[http] ${req.method} ${req.originalUrl} → 500:`, error);
  jsonRpcError(res, 500, -32603, 'Internal Server Error');
};

export interface CreateAppOptions {
  /** Additional Host header values to accept (hostnames only, no port). */
  allowedHosts?: string[];
  /** Request logging to stderr; defaults to on unless MCP_LOG=0. */
  log?: boolean;
}

/** Express app with the plumbing every example needs. Auth is NOT included — that is per example. */
export function createApp({ allowedHosts = [], log = process.env.MCP_LOG !== '0' }: CreateAppOptions = {}): Express {
  const app = express();
  app.disable('x-powered-by');

  if (log) {
    app.use((req, res, next) => {
      const started = process.hrtime.bigint();
      res.on('finish', () => {
        const ms = Number(process.hrtime.bigint() - started) / 1e6;
        console.error(`${req.method} ${req.originalUrl} ${res.statusCode} ${ms.toFixed(1)}ms`);
      });
      next();
    });
  }

  // Rejects requests whose Host header is not one of ours with 403 (JSON-RPC error body, like the
  // SDK). A malicious web page that rebinds its DNS name to this machine's IP cannot reach us.
  // First, so that a rebinding request is refused before its body is even parsed.
  app.use(hostHeaderValidation(allowedHostnames(allowedHosts)));

  // The SDK transport needs the parsed body: express.json() consumes the stream, so every
  // handleRequest() call below passes req.body explicitly.
  app.use(express.json({ limit: '1mb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });

  // Catches body-parser errors (registered before the routes → errors from the routes themselves
  // are handled by the copy mountMcp() appends after them).
  app.use(jsonRpcErrorHandler);
  return app;
}

export interface MountMcpOptions {
  /** URL path of the MCP endpoint. Keep the default unless you know why. */
  path?: string;
  /** Factory producing a fresh McpServer per session (stateful) or per request (stateless). */
  createServer: () => McpServer;
  /** Auth middleware (e.g. requireBearerAuth) applied to POST, GET and DELETE alike. */
  auth?: RequestHandler | RequestHandler[];
  /** Stateless mode: new transport + server per POST, GET/DELETE answer 405. */
  stateless?: boolean;
  /** Idle sessions (no request for this long) are closed and forgotten. Default 30 min; 0 disables. */
  sessionIdleMs?: number;
}

interface Session {
  transport: StreamableHTTPServerTransport;
  server: McpServer;
  /** Principal that initialized the session; later requests must present the same one. */
  subject: string | undefined;
  lastSeen: number;
  /** Open standalone GET (SSE) streams — a session with one is in use even without requests. */
  streams: number;
}

/**
 * Mounts the Streamable HTTP transport. Stateful mode (default): the first POST must be an
 * `initialize` request; the transport mints an `mcp-session-id` that the client echoes on every
 * later POST/GET/DELETE. One transport + one McpServer live per session and are dropped when the
 * client sends DELETE, the transport closes, or the session sits idle for `sessionIdleMs`.
 *
 * The SDK does not tie a session to a token. We do: the session remembers the subject that
 * initialized it and any request for that session by a different subject is refused with 403.
 */
export function mountMcp(app: Express, { path = '/mcp', createServer, auth, stateless = false, sessionIdleMs = 30 * 60_000 }: MountMcpOptions): void {
  const guards = auth === undefined ? [] : Array.isArray(auth) ? auth : [auth];

  if (stateless) {
    app.post(path, ...guards, async (req: AuthedRequest, res) => {
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      const server = createServer();
      res.on('close', () => {
        void transport.close();
        void server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    });
    const methodNotAllowed: RequestHandler = (_req, res) => {
      res.set('Allow', 'POST');
      jsonRpcError(res, 405, -32000, 'Method not allowed: stateless server');
    };
    app.get(path, ...guards, methodNotAllowed);
    app.delete(path, ...guards, methodNotAllowed);
    app.use(jsonRpcErrorHandler);
    return;
  }

  const sessions = new Map<string, Session>();

  // In-memory sessions never survive a restart, but they must not pile up either: clients that
  // crash without DELETE would otherwise leak a transport + McpServer each. A session whose
  // notification stream (GET) is still open is alive no matter how long ago its last request was.
  // unref() keeps the sweeper from holding the process open.
  if (sessionIdleMs > 0) {
    setInterval(() => {
      const cutoff = Date.now() - sessionIdleMs;
      for (const session of sessions.values()) {
        if (session.streams === 0 && session.lastSeen < cutoff) void session.transport.close(); // onclose below removes it
      }
    }, Math.min(sessionIdleMs, 60_000)).unref();
  }

  /** Looks up the session named by the request; writes an error response and returns undefined on failure. */
  const sessionFor = (req: AuthedRequest, res: Response): Session | undefined => {
    const id = req.header('mcp-session-id');
    if (!id) {
      jsonRpcError(res, 400, -32000, 'Bad Request: mcp-session-id header required');
      return undefined;
    }
    const session = sessions.get(id);
    if (!session) {
      jsonRpcError(res, 404, -32001, 'Session not found');
      return undefined;
    }
    if (session.subject !== subjectOf(req.auth)) {
      jsonRpcError(res, 403, -32000, 'Forbidden: session belongs to a different principal');
      return undefined;
    }
    session.lastSeen = Date.now();
    return session;
  };

  app.post(path, ...guards, async (req: AuthedRequest, res) => {
    // express.json() silently skips other content types (req.body stays undefined); answer like
    // the SDK transport would instead of confusing the caller with "must be initialize".
    if (!req.is('application/json')) {
      jsonRpcError(res, 415, -32000, 'Unsupported Media Type: Content-Type must be application/json');
      return;
    }
    if (req.header('mcp-session-id') !== undefined) {
      const session = sessionFor(req, res);
      if (session) await session.transport.handleRequest(req, res, req.body);
      return;
    }
    if (!isInitializeRequest(req.body)) {
      jsonRpcError(res, 400, -32000, 'Bad Request: first request of a session must be initialize');
      return;
    }
    const server = createServer();
    const subject = subjectOf(req.auth);
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      // Fires inside handleRequest(), before the initialize response is written.
      onsessioninitialized: (id) => {
        sessions.set(id, { transport, server, subject, lastSeen: Date.now(), streams: 0 });
      },
      // DELETE from the client: forget the session before the transport closes.
      onsessionclosed: (id) => {
        sessions.delete(id);
      },
    });
    // server.connect() chains onto an existing onclose, so this survives the connect below.
    transport.onclose = () => {
      if (transport.sessionId) sessions.delete(transport.sessionId);
    };
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  app.get(path, ...guards, async (req: AuthedRequest, res) => {
    // server → client notification stream (SSE); counted so the idle sweeper leaves it alone
    const session = sessionFor(req, res);
    if (!session) return;
    session.streams += 1;
    res.on('close', () => {
      session.streams -= 1;
      session.lastSeen = Date.now();
    });
    await session.transport.handleRequest(req, res);
  });
  app.delete(path, ...guards, async (req: AuthedRequest, res) => {
    // explicit session termination
    const session = sessionFor(req, res);
    if (session) await session.transport.handleRequest(req, res);
  });

  // After the routes, so that a rejected async handler (or a throwing auth middleware) still
  // yields a JSON-RPC error instead of Express's HTML stack trace.
  app.use(jsonRpcErrorHandler);
}

export interface ListenOptions {
  port: number;
  name: string;
  /** Path shown in the banner; defaults to /mcp. */
  path?: string;
  /** Interface to bind; defaults to 0.0.0.0 (all). Example 09's internal server binds 127.0.0.1. */
  host?: string;
  /** A pre-built server wrapping `app` (e.g. https.createServer(tls, app) in example 08). */
  server?: Server | HttpsServer;
}

/**
 * Binds 0.0.0.0 (all interfaces) so other LAN machines can connect, then prints the banner.
 * Appends the JSON 404 fallback and the error handler, so call it after every route is mounted.
 */
export function listen(app: Express, { port, name, path = '/mcp', host = '0.0.0.0', server }: ListenOptions): Promise<Server | HttpsServer> {
  app.use(notFoundHandler);
  app.use(jsonRpcErrorHandler); // last in the chain: covers routes an example added after mountMcp()
  return new Promise((resolve, reject) => {
    const scheme = server && 'setSecureContext' in server ? 'https' : 'http';
    const listening = () => {
      const url = publicUrl(port, path, scheme);
      console.log(`[${name}] listening on ${host}:${port}`);
      console.log(`[${name}] MCP endpoint: ${url}   (PUBLIC_HOST ${publicHost()} — ${publicHostSource()})`);
      console.log(`[${name}] LAN: use exactly that URL from other machines; set PUBLIC_HOST in .env if it is wrong.`);
      resolve(httpServer);
    };
    const httpServer = server ? server.listen(port, host, listening) : app.listen(port, host, listening);
    httpServer.on('error', reject);
  });
}
