/**
 * assertion.ts — the signed identity assertion the gateway hands to the internal server.
 *
 * The trust boundary of example 09 in one file. The gateway validates the caller's Keycloak token
 * and mints a SHORT-LIVED HS256 JWT that says "I, the gateway, authenticated this subject". The
 * internal server verifies THAT — never the original bearer token — so the two roles are cleanly
 * separated: the gateway is the conformant OAuth resource server, the backend trusts only the
 * gateway. The shared secret (GATEWAY_INTERNAL_SECRET) is the whole trust relationship; rotate it
 * like any other credential.
 *
 * Shape (verified against jose 6): { iss:'mcp-gateway', aud:'mcp-internal', sub, azp, scopes, roles,
 * jti, iat, exp } — exp is now+30s, and every assertion carries a fresh jti so the backend can
 * reject replays. Nothing here logs the token; it is a bearer credential for the backend.
 */
import '../../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';

/** The gateway is the only issuer the backend trusts; the assertion is only for the backend. */
export const ASSERTION_ISS = 'mcp-gateway';
export const ASSERTION_AUD = 'mcp-internal';
/** Lower-case header name (Node lower-cases request headers). */
export const ASSERTION_HEADER = 'x-gateway-assertion';
/** Assertions are valid for a single hop; 30 s is ample and keeps the replay window small. */
export const ASSERTION_TTL_SECONDS = 30;

/** The identity the gateway asserts about a request (derived from the verified Keycloak token). */
export interface AssertionInput {
  sub: string;
  /** The authorized party (`azp`) of the original token — which OAuth client acted for the user. */
  azp: string;
  /** EFFECTIVE scopes the gateway computed (role policy already applied). */
  scopes: string[];
  roles: string[];
}

/** What a verified assertion yields — the backend turns this into `req.auth`. */
export interface VerifiedAssertion extends AssertionInput {
  jti: string;
  /** Expiry in seconds since epoch (the assertion's own `exp`). */
  exp: number;
}

const keyOf = (secret: string): Uint8Array => new TextEncoder().encode(secret);

/**
 * Signs the gateway's identity assertion (HS256). `ttlSeconds` is overridable only so tests can
 * mint an already-expired assertion; production always uses the 30 s default.
 */
export function signAssertion(input: AssertionInput, secret: string, ttlSeconds = ASSERTION_TTL_SECONDS): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ azp: input.azp, scopes: input.scopes, roles: input.roles })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuer(ASSERTION_ISS)
    .setAudience(ASSERTION_AUD)
    .setSubject(input.sub)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(keyOf(secret));
}

export interface AssertionVerifierOptions {
  /** How long a jti is remembered so a captured assertion cannot be replayed. Default 60 s. */
  replayWindowMs?: number;
  /** Clock skew tolerance in seconds (gateway and backend are usually the same host). Default 5. */
  clockToleranceSec?: number;
}

/**
 * Builds the backend's assertion verifier: enforces HS256 (no algorithm confusion), the fixed
 * issuer and audience, expiry, and a jti replay cache. The returned function throws on any of
 * those failures — the backend maps that to a plain 401 (it is NOT a public resource, so no PRM).
 */
export function createAssertionVerifier(secret: string, { replayWindowMs = 60_000, clockToleranceSec = 5 }: AssertionVerifierOptions = {}) {
  const key = keyOf(secret);
  const seen = new Map<string, number>(); // jti -> when it may be forgotten (epoch ms)

  return async function verifyAssertion(token: string): Promise<VerifiedAssertion> {
    const { payload } = await jwtVerify(token, key, {
      issuer: ASSERTION_ISS,
      audience: ASSERTION_AUD,
      algorithms: ['HS256'], // reject anything else, including alg:none
      clockTolerance: clockToleranceSec,
    });
    const jti = typeof payload.jti === 'string' ? payload.jti : undefined;
    if (!jti) throw new Error('gateway assertion has no jti');

    const now = Date.now();
    for (const [seenJti, forgetAt] of seen) if (forgetAt <= now) seen.delete(seenJti);
    if (seen.has(jti)) throw new Error('gateway assertion replayed');
    seen.set(jti, now + replayWindowMs);

    const list = (claim: unknown): string[] => (Array.isArray(claim) ? claim.filter((v): v is string => typeof v === 'string') : []);
    return {
      sub: String(payload.sub ?? ''),
      azp: String(payload.azp ?? ''),
      scopes: list(payload.scopes),
      roles: list(payload.roles),
      jti,
      exp: typeof payload.exp === 'number' ? payload.exp : Math.floor(now / 1000),
    };
  };
}
