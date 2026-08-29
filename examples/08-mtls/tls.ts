/**
 * tls.ts — the TLS plumbing of example 08 (mutual TLS).
 *
 *   serverTlsOptions()  key/cert/CA + requestCert for https.createServer()
 *   listenTls()         https.createServer(tls, app) handed to the shared listen()
 *   mtlsDispatcher()    undici Agent whose connections present a client certificate
 *   mtlsFetch()         WHATWG-fetch wrapper around that Agent for the SDK client transport
 *
 * Certificates come from `npm run ex:08:certs` (scripts/gen-certs.sh); tests generate their own
 * PKI into a temp dir and pass `dir` explicitly.
 */
import { env, REPO_ROOT } from '../../src/shared/env.ts';
import { readFileSync } from 'node:fs';
import { createServer as createHttpsServer, type Server as HttpsServer, type ServerOptions } from 'node:https';
import { isIP } from 'node:net';
import { join } from 'node:path';
import type { SecureVersion } from 'node:tls';
import type { Express } from 'express';
import { Agent, fetch as undiciFetch, type RequestInit as UndiciRequestInit } from 'undici';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import { listen } from '../../src/shared/http.ts';

/** Where the demo PKI lives; MTLS_CERT_DIR overrides (tests use a temp dir). */
export function certDir(): string {
  return env('MTLS_CERT_DIR', join(REPO_ROOT, 'examples/08-mtls/certs'));
}

export function readPem(dir: string, file: string): Buffer {
  return readFileSync(join(dir, file)); // throws a clear ENOENT → "run npm run ex:08:certs" (see server.ts)
}

/**
 * TLS options of the server. The three lines that make it MUTUAL TLS:
 *   ca                  the only CA a client certificate may chain to (never the system store)
 *   requestCert         ask every client for a certificate during the handshake
 *   rejectUnauthorized  kill the handshake when the certificate is missing/expired/untrusted —
 *                       soft-fail mode (MTLS_SOFT_FAIL=1) lets the request through instead and
 *                       certAuth answers 401 JSON (friendlier errors, but the TLS layer no longer
 *                       guarantees that only certificate holders can even speak HTTP to us).
 */
export function serverTlsOptions(dir: string = certDir(), { softFail = false }: { softFail?: boolean } = {}): ServerOptions {
  return {
    key: readPem(dir, 'server.key'),
    cert: readPem(dir, 'server.crt'),
    ca: readPem(dir, 'ca.crt'),
    requestCert: true,
    rejectUnauthorized: !softFail,
    minVersion: 'TLSv1.3',
  };
}

export interface ListenTlsOptions {
  port: number;
  name: string;
  dir?: string;
  softFail?: boolean;
}

/** https twin of the shared listen(): binds 0.0.0.0 and prints the https:// banner. */
export function listenTls(app: Express, { port, name, dir, softFail }: ListenTlsOptions): Promise<HttpsServer> {
  const server = createHttpsServer(serverTlsOptions(dir, { softFail }), app);
  return listen(app, { port, name, server }) as Promise<HttpsServer>;
}

export interface MtlsConnectOptions {
  /** Which client certificate to present: alice | bob | expired-alice | rogue-client | none. */
  client: string;
  /** Certificate directory (default certDir()). */
  dir?: string;
  /** CA bundle the CLIENT trusts for the server certificate (tests: trust the wrong CA). */
  ca?: Buffer;
  /** Highest TLS version the client offers (tests: force a TLS 1.2-only client). */
  maxVersion?: SecureVersion;
}

/**
 * undici Agent whose TLS connections present the chosen client certificate and trust only the
 * demo CA for the server certificate. `connect` options go straight into tls.connect().
 */
export function mtlsDispatcher(serverUrl: string | URL, { client, dir = certDir(), ca, maxVersion }: MtlsConnectOptions): Agent {
  const host = new URL(serverUrl).hostname;
  return new Agent({
    connect: {
      ca: ca ?? readPem(dir, 'ca.crt'),
      ...(client === 'none' ? {} : { cert: readPem(dir, `${client}.crt`), key: readPem(dir, `${client}.key`) }),
      // SNI must not carry an IP literal (RFC 6066) — undici omits it for IPs on its own; for a
      // DNS name make it explicit so the cert is verified against the name the user dialled.
      ...(isIP(host) ? {} : { servername: host }),
      ...(maxVersion ? { maxVersion } : {}),
    },
  });
}

/**
 * WHATWG-compatible fetch for the SDK's StreamableHTTPClientTransport that routes every request
 * (POSTs and the GET SSE stream alike) through the mTLS Agent. Node's global fetch and undici's
 * are the same implementation, but only undici's accepts a `dispatcher`; its `RequestInit` /
 * `Response` types are that implementation's own declarations, hence the two casts.
 */
export function mtlsFetch(serverUrl: string | URL, options: MtlsConnectOptions): FetchLike {
  const dispatcher = mtlsDispatcher(serverUrl, options);
  return (url, init) => undiciFetch(url, { ...(init as UndiciRequestInit), dispatcher }) as unknown as Promise<Response>;
}
