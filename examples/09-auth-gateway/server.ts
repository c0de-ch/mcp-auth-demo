/**
 * 09 — the INTERNAL MCP server that sits behind the gateway.
 *
 * It is an ordinary Streamable HTTP MCP server (the same shared tools as everywhere else) with one
 * difference: it does NOT verify OAuth tokens. It trusts the gateway's signed identity assertion
 * (default) — never a bearer token, never a plain forwarded-user header. That is the whole point of
 * the pattern: the gateway is the resource server, the backend only checks "did MY gateway send
 * this?". A missing or invalid assertion is a plain 401 with NO Protected Resource Metadata — the
 * backend is not a public resource and must not invite clients to start OAuth discovery against it.
 *
 *   INTERNAL_TRUST_MODE=assertion  (default)  verify X-Gateway-Assertion (HS256, aud, exp, replay)
 *                                             and bind 0.0.0.0 (LAN rule; isolate it in production)
 *   INTERNAL_TRUST_MODE=network    (opt-in)   trust plain X-Forwarded-User / X-Forwarded-Scopes and
 *                                             bind 127.0.0.1 — the DELIBERATELY INSECURE variant the
 *                                             docs and a test use to show why network trust is not
 *                                             enough (anyone who reaches the port forges the headers)
 */
import { env, isMain, port, publicUrl } from '../../src/shared/env.ts';
import type { Request, RequestHandler, Response } from 'express';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { createDemoServer } from '../../src/shared/tools.ts';
import { ASSERTION_HEADER, createAssertionVerifier } from './assertion.ts';

/** The internal listener port (never exposed to real clients in production). */
export const PORT = port('PORT_09_INTERNAL', 4119);

/** requireBearerAuth populates `req.auth`; declare the shape for the modes that set it themselves. */
type AuthedRequest = Request & { auth?: AuthInfo };

export type TrustMode = 'assertion' | 'network';

export function trustModeFromEnv(): TrustMode {
  return env('INTERNAL_TRUST_MODE', 'assertion') === 'network' ? 'network' : 'assertion';
}

/** Assertion mode binds all interfaces (LAN rule); network mode binds loopback only (the demo's claim). */
export function internalBindHost(mode: TrustMode = trustModeFromEnv()): string {
  return mode === 'network' ? '127.0.0.1' : '0.0.0.0'; // loopback-ok: the network-mode isolation claim
}

/** A 401 the backend uses for every rejected request: JSON only, and NEVER a WWW-Authenticate/PRM. */
function unauthorized(res: Response, message: string): void {
  res.status(401).json({ jsonrpc: '2.0', error: { code: -32001, message: `Unauthorized: ${message}` }, id: null });
}

/**
 * DEFAULT mode. Verifies the gateway's HS256 assertion and turns it into `req.auth`. The tools then
 * see exactly the same `extra.authInfo` shape as in every other example, plus `via: 'gateway'` so
 * `whoami` shows the request arrived through the trust boundary.
 */
export function trustGatewayAssertion(secret: string, opts?: { replayWindowMs?: number }): RequestHandler {
  const verify = createAssertionVerifier(secret, opts);
  return async (req: AuthedRequest, res, next) => {
    const token = req.header(ASSERTION_HEADER);
    if (!token) {
      unauthorized(res, 'gateway assertion required');
      return;
    }
    try {
      const claims = await verify(token);
      req.auth = {
        token: claims.jti, // the assertion id — never the caller's real token, which stops at the gateway
        clientId: claims.azp,
        scopes: claims.scopes,
        expiresAt: claims.exp,
        extra: { sub: claims.sub, roles: claims.roles, via: 'gateway' },
      };
      next();
    } catch {
      // Static message: no request-derived text ever reaches a response header/body here.
      unauthorized(res, 'invalid gateway assertion');
    }
  };
}

/**
 * OPT-IN, INSECURE mode. Trusts `X-Forwarded-User` / `X-Forwarded-Scopes` at face value — the
 * "we are on a private network, the proxy sets these" anti-pattern. There is no signature: anybody
 * who can reach this port forges any identity. The example ships it, binds it to 127.0.0.1, and a
 * test asserts the forgery works, so the warning in the docs cannot quietly rot.
 */
export function trustForwardedHeaders(): RequestHandler {
  return (req: AuthedRequest, res, next) => {
    const user = req.header('x-forwarded-user');
    if (!user) {
      unauthorized(res, 'x-forwarded-user required (network trust mode)');
      return;
    }
    const scopes = (req.header('x-forwarded-scopes') ?? '').split(/\s+/).filter(Boolean);
    req.auth = {
      token: `forwarded:${user}`,
      clientId: user,
      scopes, // trusted verbatim — no role policy, no verification: the whole vulnerability
      expiresAt: Math.floor(Date.now() / 1000) + 60,
      extra: { sub: user, roles: [], via: 'network-headers' },
    };
    next();
  };
}

export interface InternalOverrides {
  /** HS256 secret shared with the gateway; default GATEWAY_INTERNAL_SECRET. */
  secret?: string;
  /** Trust mode; default from INTERNAL_TRUST_MODE. */
  mode?: TrustMode;
  /** jti replay window in ms (assertion mode); default 60 s. */
  replayWindowMs?: number;
}

/** Builds the internal Express app; exported so tests run it on an ephemeral port in either mode. */
export function buildInternalApp({ secret = env('GATEWAY_INTERNAL_SECRET', 'gateway-internal-secret-demo'), mode = trustModeFromEnv(), replayWindowMs }: InternalOverrides = {}) {
  const app = createApp();
  const auth = mode === 'network' ? trustForwardedHeaders() : trustGatewayAssertion(secret, { replayWindowMs });
  mountMcp(app, { createServer: () => createDemoServer({ name: '09-auth-gateway-internal' }), auth });
  return app;
}

if (isMain(import.meta)) {
  const mode = trustModeFromEnv();
  if (mode === 'network') {
    console.error('[09-internal] INTERNAL_TRUST_MODE=network — trusting UNSIGNED X-Forwarded-User headers (INSECURE demo). Bound to 127.0.0.1 only.');
  } else {
    console.error('[09-internal] verifying the gateway assertion (HS256). In production this listener must be network-isolated, not just bound to 0.0.0.0.');
  }
  await listen(buildInternalApp({ mode }), { port: PORT, name: '09-internal', host: internalBindHost(mode) });
  console.error(`[09-internal] direct clients get 401 (no PRM); reach it through the gateway. Internal URL: ${publicUrl(PORT)}`);
}
