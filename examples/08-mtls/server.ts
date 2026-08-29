/**
 * 08 — mutual TLS: the client CERTIFICATE is the credential. No bearer tokens, no Keycloak, no
 * browser — the TLS handshake authenticates the caller before a single HTTP byte is exchanged.
 *
 * certAuth() maps the verified peer certificate onto the same AuthInfo every other example
 * produces (CN → clientId/sub, OU → scopes, notAfter → expiresAt), so the shared tools see
 * `extra.authInfo` exactly as they do with JWTs. Authorization headers are ignored entirely.
 *
 * MTLS_ALLOWED_CN   comma list of accepted CNs (default alice,bob) — authenticated ≠ authorized
 * MTLS_SOFT_FAIL=1  rejectUnauthorized:false — handshake succeeds, certAuth answers 401 JSON
 */
import { env, isMain, port } from '../../src/shared/env.ts';
import type { TLSSocket } from 'node:tls';
import type { Request, RequestHandler, Response } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createApp, mountMcp } from '../../src/shared/http.ts';
import { createDemoServer, SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';
import { certDir, listenTls } from './tls.ts';

export const PORT = port('PORT_08', port('MCP_PORT', 4108));
const SOFT_FAIL = process.env.MTLS_SOFT_FAIL === '1';

const allowedCnFromEnv = () => env('MTLS_ALLOWED_CN', 'alice,bob').split(',').map((cn) => cn.trim()).filter(Boolean);

/** subject/issuer attributes can be multi-valued; the demo certs carry exactly one value each. */
const first = (value: string | string[] | undefined): string | undefined => (Array.isArray(value) ? value[0] : value);

const deny = (res: Response, status: number, message: string) => {
  res.status(status).json({ jsonrpc: '2.0', error: { code: -32000, message }, id: null });
};

/**
 * The auth middleware of this example — mountMcp({ auth: certAuth() }) instead of
 * requireBearerAuth. By the time it runs, Node has already verified the chain, validity window
 * and signature against `ca` (rejectUnauthorized) — this middleware only maps identity to
 * AuthInfo and applies the CN allow-list (authentication happened in the handshake;
 * authorization is still an application decision).
 */
export function certAuth(allowedCn: string[] = allowedCnFromEnv()): RequestHandler {
  return (req, res, next) => {
    const socket = req.socket as TLSSocket;
    const cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate() : undefined;
    const cn = first(cert?.subject?.CN);
    if (!socket.authorized || !cert || !cn) {
      // Unreachable in hard-fail mode (the handshake already failed); this is the MTLS_SOFT_FAIL
      // path, where the TLS layer let the request through for the app to answer politely.
      deny(res, 401, 'Unauthorized: a valid client certificate is required'); // static string
      return;
    }
    if (!allowedCn.includes(cn)) {
      deny(res, 403, 'Forbidden: certificate CN is not in MTLS_ALLOWED_CN'); // static string
      return;
    }
    const ou = ([] as string[]).concat(cert.subject.OU ?? []);
    (req as Request & { auth?: AuthInfo }).auth = {
      token: cert.fingerprint256, // no bearer token exists; the fingerprint is the stable stand-in
      clientId: cn,
      scopes: ou.includes('mcp-admin') ? [SCOPE_TOOLS, SCOPE_ADMIN] : [SCOPE_TOOLS],
      expiresAt: Date.parse(cert.valid_to) / 1000, // certificate notAfter, in seconds
      extra: { sub: cn, issuer: first(cert.issuer.CN), fingerprint256: cert.fingerprint256, kind: 'mtls' },
    };
    next();
  };
}

export interface Overrides {
  allowedCn?: string[];
}

/** The baseline server plus certAuth — the TLS options live in tls.ts, not in the Express app. */
export function buildApp(overrides: Overrides = {}) {
  const app = createApp();
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '08-mtls' }),
    auth: certAuth(overrides.allowedCn),
  });
  return app;
}

if (isMain(import.meta)) {
  try {
    await listenTls(buildApp(), { port: PORT, name: '08-mtls', softFail: SOFT_FAIL });
    if (SOFT_FAIL) console.error('[08-mtls] MTLS_SOFT_FAIL=1 — handshake accepts anyone; certAuth answers 401 instead');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      console.error(`[08-mtls] certificates missing (${(error as Error).message}) — generate them: npm run ex:08:certs`);
      process.exit(1);
    }
    throw error;
  }
}
