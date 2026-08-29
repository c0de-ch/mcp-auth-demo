/**
 * 09 — the AUTH GATEWAY (a.k.a. sidecar) that fronts an unauthenticated internal MCP server.
 *
 * This is the conformant OAuth 2.1 resource server: it serves the Protected Resource Metadata,
 * validates the caller's Keycloak access token exactly like example 04, and then — instead of
 * running the MCP tools itself — reverse-proxies the request to the internal server, replacing the
 * bearer token with a short-lived signed identity assertion (see assertion.ts). The trust boundary
 * is the whole lesson: tokens terminate here, the backend trusts only this gateway.
 *
 *   client ──Bearer (Keycloak)──▶ GATEWAY ──X-Gateway-Assertion (HS256)──▶ internal MCP server
 *                                    │  validates token, serves PRM, strips inbound identity headers
 *                                    └▶ streams the response back unbuffered (SSE included)
 *
 * The proxy is hand-rolled with node:http so nothing is buffered — an SSE notification stream must
 * flow through in real time. It forwards only a strict allow-list of headers (default-deny), which
 * inherently strips any inbound Authorization / X-Gateway-Assertion / X-Forwarded-* a client tried
 * to smuggle in. Upstream connection failures become a 502 JSON-RPC error.
 */
import { env, isMain, keycloak, port, publicUrl } from '../../src/shared/env.ts';
import { request as httpRequest, type IncomingHttpHeaders } from 'node:http';
import type { Express, Request, Response } from 'express';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { createApp, listen } from '../../src/shared/http.ts';
import { createJwtVerifier, keycloakEffectiveScopes, type JwksSource } from '../../src/shared/jwt.ts';
import { audiences, discoverKeycloak, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import { mountProtectedResourceMetadata } from '../../src/shared/prm.ts';
import { SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';
import { signAssertion } from './assertion.ts';

/** requireBearerAuth stores the verified token on `req.auth`; declare the shape we read from it. */
type AuthedRequest = Request & { auth?: AuthInfo };

export const PORT = port('PORT_09', 4109);
/** Where the internal server listens; the gateway talks to it over loopback (co-located sidecar). */
const INTERNAL_PORT = port('PORT_09_INTERNAL', 4119);
export const MCP_PATH = '/mcp';

/** Request headers the proxy forwards upstream. Everything else (Authorization, X-Forwarded-*, an
 * inbound X-Gateway-Assertion) is dropped by omission — a default-deny strip. */
const FORWARD_REQUEST_HEADERS = ['mcp-session-id', 'mcp-protocol-version', 'accept', 'content-type', 'last-event-id'];
/** Hop-by-hop response headers we must NOT relay (Node re-frames the body itself). */
const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'transfer-encoding', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'upgrade']);

export interface GatewayOverrides {
  /** Internal MCP server URL; default http://127.0.0.1:<PORT_09_INTERNAL>/mcp (or GATEWAY_INTERNAL_URL). */
  internalUrl?: string;
  /** HS256 secret for the identity assertion; default GATEWAY_INTERNAL_SECRET. */
  secret?: string;
  /** Discovery document (fetched from Keycloak when neither this nor `jwks` is given). */
  metadata?: KeycloakMetadata;
  /** Override the issuer (hermetic tests). */
  issuer?: string;
  /** Override the key source with a local JWK Set (hermetic tests); skips Keycloak discovery. */
  jwks?: JwksSource;
  /** Accepted `aud` values; default audiences() (`mcp-server`). */
  audience?: string[];
}

/**
 * Builds the gateway app: PRM + Keycloak token verification (the resource-server half) followed by
 * the signing reverse proxy (the trust-boundary half). Async because it discovers Keycloak unless a
 * local `jwks` override is supplied.
 */
export async function buildGatewayApp(overrides: GatewayOverrides = {}): Promise<Express> {
  const resourceUrl = publicUrl(PORT); // the gateway IS the public resource clients dial
  const internalUrl = overrides.internalUrl ?? env('GATEWAY_INTERNAL_URL', `http://127.0.0.1:${INTERNAL_PORT}${MCP_PATH}`); // loopback-ok: co-located sidecar hop
  const secret = overrides.secret ?? env('GATEWAY_INTERNAL_SECRET', 'gateway-internal-secret-demo');

  // Same verifier as example 04: issuer + JWKS from discovery, audience mcp-server, role-aware
  // effective scopes. requiredScopes lives in the VERIFIER (→ 403 "missing scope: mcp:tools"), so
  // requireBearerAuth carries no scope= and the 401 advertises only the PRM (SEP-835).
  const metadata = overrides.jwks ? undefined : (overrides.metadata ?? (await discoverKeycloak()));
  const issuer = overrides.issuer ?? metadata?.issuer ?? keycloak().issuer;
  const verifier: OAuthTokenVerifier = createJwtVerifier({
    issuer,
    audience: overrides.audience ?? audiences(),
    jwks: overrides.jwks ?? metadata!.jwks_uri,
    requiredScopes: [SCOPE_TOOLS],
    effectiveScopes: keycloakEffectiveScopes,
  });

  const app = createApp();
  const resourceMetadataUrl = mountProtectedResourceMetadata(app, {
    resourceUrl,
    authorizationServers: [issuer],
    scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN],
    resourceName: '09-auth-gateway',
  });

  // Guard EVERY method on /mcp (POST, GET SSE, DELETE), then proxy. No requiredScopes here — the
  // scope check is in the verifier, so the 401 names the PRM but no scope to request.
  const guard = requireBearerAuth({ verifier, resourceMetadataUrl });
  app.all(MCP_PATH, guard, makeProxyHandler(internalUrl, secret));
  return app;
}

/** The signing reverse proxy: mint the assertion from `req.auth`, stream to the internal server. */
function makeProxyHandler(internalUrl: string, secret: string) {
  const target = new URL(internalUrl);
  return async (req: AuthedRequest, res: Response): Promise<void> => {
    const auth = req.auth!; // requireBearerAuth guarantees it, or we never get here
    const assertion = await signAssertion(
      {
        sub: String(auth.extra?.sub ?? auth.clientId),
        azp: auth.clientId,
        scopes: auth.scopes,
        roles: Array.isArray(auth.extra?.roles) ? (auth.extra!.roles as string[]) : [],
      },
      secret,
    );

    // Allow-list forward: this is also the strip step (default-deny) for identity headers.
    const headers: Record<string, string> = {};
    for (const name of FORWARD_REQUEST_HEADERS) {
      const value = req.headers[name];
      if (typeof value === 'string') headers[name] = value;
    }
    headers['x-gateway-assertion'] = assertion; // set AFTER the copy, so an inbound one cannot win

    // MCP POSTs carry a small JSON body (already parsed by express.json); GET/DELETE carry none.
    const body = req.method === 'POST' ? JSON.stringify(req.body ?? {}) : undefined;
    if (body !== undefined) headers['content-length'] = String(Buffer.byteLength(body));

    const upstream = httpRequest(
      { protocol: target.protocol, hostname: target.hostname, port: target.port, path: target.pathname + target.search, method: req.method, headers },
      (upstreamRes) => {
        res.writeHead(upstreamRes.statusCode ?? 502, filterResponseHeaders(upstreamRes.headers));
        res.flushHeaders(); // push the head out NOW — an SSE stream's first byte may be 15 s away
        upstreamRes.pipe(res); // no buffering: SSE frames reach the client as they arrive
      },
    );
    upstream.on('error', () => {
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.status(502).json({ jsonrpc: '2.0', error: { code: -32002, message: 'Bad Gateway: internal MCP server unreachable' }, id: null });
    });
    res.on('close', () => upstream.destroy()); // client hung up → stop talking to the backend

    if (body !== undefined) upstream.end(body);
    else upstream.end();
  };
}

/** Copies upstream response headers minus hop-by-hop ones so Node frames the body correctly. */
function filterResponseHeaders(headers: IncomingHttpHeaders): Record<string, number | string | string[]> {
  const out: Record<string, number | string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value !== undefined && !HOP_BY_HOP.has(name.toLowerCase())) out[name] = value;
  }
  return out;
}

if (isMain(import.meta)) {
  const app = await buildGatewayApp();
  await listen(app, { port: PORT, name: '09-gateway' });
  console.error(`[09-gateway] validating Keycloak tokens, proxying to the internal server with a signed assertion. Public MCP URL: ${publicUrl(PORT)}`);
}
