/**
 * jwt.ts — JWT access-token verification shared by every JWT-based example (02, 04, 06, 09, 10).
 *
 * Wraps `jose` in the SDK's OAuthTokenVerifier interface so it plugs straight into
 * requireBearerAuth(). The two rules that make the SDK middleware behave:
 *   1. Only InvalidTokenError (→ 401 + WWW-Authenticate) and InsufficientScopeError (→ 403) are
 *      understood; anything else becomes a 500 without WWW-Authenticate, which silently breaks
 *      client-side OAuth discovery. So every failure here is wrapped in one of those two.
 *   2. requireBearerAuth checks expiry but NOT issuer or audience — we do, via jwtVerify().
 *   3. A JWKS that cannot be fetched is OUR problem, not the client's: that becomes ServerError
 *      (500, no WWW-Authenticate) so SDK clients do not start refresh/re-authorization loops.
 */
import './env.ts';
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  errors as joseErrors,
  importJWK,
  jwtVerify,
  type CryptoKey,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
  type KeyObject,
} from 'jose';
import { InsufficientScopeError, InvalidTokenError, ServerError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { SCOPE_ADMIN } from './tools.ts';

/** Where signing keys come from: a JWKS URL, a JWK Set, a single JWK, or an already-imported key. */
export type JwksSource = string | URL | JSONWebKeySet | JWK | CryptoKey | KeyObject;

export interface JwtVerifierOptions {
  /** Expected `iss` claim (exact string match). */
  issuer: string;
  /** Expected `aud` claim; one of these must be present in the token. */
  audience: string | string[];
  jwks: JwksSource;
  /** Scopes the token must carry (after effectiveScopes) or the request gets 403 insufficient_scope. */
  requiredScopes?: string[];
  /** Policy hook computing the EFFECTIVE scopes from the payload (default: the `scope` claim). */
  effectiveScopes?: (payload: JWTPayload) => string[];
  /** Allowed clock skew in seconds (default 5). */
  clockToleranceSec?: number;
}

/** The token's own scope list: RFC 8693 `scope` (space separated) or the `scp` array some IdPs use. */
export function tokenScopes(payload: JWTPayload): string[] {
  if (typeof payload.scope === 'string') return payload.scope.split(' ').filter(Boolean);
  if (Array.isArray(payload.scp)) return payload.scp.filter((s): s is string => typeof s === 'string');
  return [];
}

/**
 * Keycloak policy used by every Keycloak example:
 *   scope = what the CLIENT was granted (consent), role = what the USER may do.
 *   effective = both: `mcp:admin` survives only if the user holds the `mcp-admin` realm role.
 */
export function keycloakEffectiveScopes(payload: JWTPayload): string[] {
  const roles = realmRoles(payload);
  return tokenScopes(payload).filter((s) => s !== SCOPE_ADMIN || roles.includes('mcp-admin'));
}

function realmRoles(payload: JWTPayload): string[] {
  const realmAccess = payload.realm_access as { roles?: unknown } | undefined;
  return Array.isArray(realmAccess?.roles) ? realmAccess.roles.filter((r): r is string => typeof r === 'string') : [];
}

/** Maps a verified payload to the SDK's AuthInfo. `expiresAt` is seconds since epoch (JWT `exp`). */
export function authInfoFromPayload(
  payload: JWTPayload,
  token: string,
  effectiveScopes: (payload: JWTPayload) => string[] = tokenScopes,
): AuthInfo {
  const firstAud = Array.isArray(payload.aud) ? payload.aud[0] : payload.aud;
  const resource = firstAud && /^https?:\/\//.test(firstAud) && URL.canParse(firstAud) ? new URL(firstAud) : undefined;
  return {
    token,
    clientId: String(payload.azp ?? payload.client_id ?? payload.sub ?? 'unknown'),
    scopes: effectiveScopes(payload),
    expiresAt: payload.exp,
    resource,
    extra: {
      sub: payload.sub,
      username: payload.preferred_username ?? payload.username, // OIDC claim, or RFC 7662 introspection field
      email: payload.email,
      roles: realmRoles(payload),
      claims: payload,
    },
  };
}

type KeyResolver = Parameters<typeof jwtVerify>[1];

const isJwkSet = (v: object): v is JSONWebKeySet => 'keys' in v && Array.isArray((v as JSONWebKeySet).keys);
const isJwk = (v: object): v is JWK => 'kty' in v;

async function resolveKeys(jwks: JwksSource): Promise<KeyResolver> {
  if (typeof jwks === 'string' || jwks instanceof URL) return createRemoteJWKSet(new URL(jwks)); // cached + auto-refresh on unknown kid
  if (isJwkSet(jwks)) return createLocalJWKSet(jwks);
  if (isJwk(jwks)) return importJWK(jwks);
  return jwks; // CryptoKey / KeyObject
}

/**
 * Fixed-vocabulary reason for a jose failure. NEVER includes `error.message`: jose quotes strings
 * from the *unverified* token header in some messages, and requireBearerAuth() copies our message
 * unescaped into the WWW-Authenticate header — a crafted token could inject quotes or CR/LF there
 * (the latter makes res.set() throw and turns the 401 into a 500). Every branch below is static
 * or a jose-chosen enum value (`claim`, `reason`, `code`). Unknown errors are logged to stderr.
 */
export function describeJoseError(error: unknown): string {
  if (error instanceof joseErrors.JWTExpired) return 'token expired';
  if (error instanceof joseErrors.JWTClaimValidationFailed) {
    if (error.claim === 'iss') return 'wrong issuer';
    if (error.claim === 'aud') return 'wrong audience';
    return `claim ${error.claim} ${error.reason}`;
  }
  if (error instanceof joseErrors.JWSSignatureVerificationFailed) return 'bad signature';
  if (error instanceof joseErrors.JWKSNoMatchingKey) return 'no matching signing key';
  if (error instanceof joseErrors.JOSEError) return error.code;
  console.error('[jwt] token verification failed with an unexpected error:', error);
  return 'verification failed';
}

/**
 * True when the failure is about fetching the signing keys (network error, timeout, non-200,
 * unparsable JWKS) rather than about the token. jose throws JWKSTimeout, a generic JOSEError
 * ("Expected 200 OK …" / "Failed to parse …") or Node's `TypeError: fetch failed` for those.
 */
export function isKeyRetrievalError(error: unknown): boolean {
  if (error instanceof joseErrors.JWKSTimeout) return true;
  if (error instanceof joseErrors.JOSEError) return error.code === 'ERR_JOSE_GENERIC';
  return error instanceof TypeError; // fetch failed / DNS / ECONNREFUSED
}

/** Defense in depth for anything that ends up in an HTTP header: no quotes, no CR/LF, no controls. */
export function headerSafe(text: string): string {
  return text.replace(/["\\\r\n\x00-\x1f\x7f]/g, ' ');
}

/** Builds an OAuthTokenVerifier for requireBearerAuth({ verifier }). */
export function createJwtVerifier(options: JwtVerifierOptions): OAuthTokenVerifier {
  const { issuer, audience, requiredScopes = [], effectiveScopes = tokenScopes, clockToleranceSec = 5 } = options;
  const keys = resolveKeys(options.jwks); // resolved once, shared by all requests
  keys.catch(() => undefined); // a bad key source surfaces per request below, not as an unhandled rejection

  return {
    async verifyAccessToken(token: string): Promise<AuthInfo> {
      let payload: JWTPayload;
      try {
        ({ payload } = await jwtVerify(token, await keys, { issuer, audience, clockTolerance: clockToleranceSec }));
      } catch (error) {
        if (isKeyRetrievalError(error)) {
          console.error('[jwt] cannot fetch the signing keys:', error instanceof Error ? error.message : error);
          throw new ServerError('token verification unavailable'); // 500: not the client's fault
        }
        throw new InvalidTokenError(`JWT rejected: ${headerSafe(describeJoseError(error))}`);
      }
      if (typeof payload.exp !== 'number') throw new InvalidTokenError('JWT rejected: missing exp claim');

      const authInfo = authInfoFromPayload(payload, token, effectiveScopes);
      const missing = requiredScopes.filter((s) => !authInfo.scopes.includes(s));
      // requiredScopes is server configuration, but it still ends up in a header: keep it header-safe.
      if (missing.length > 0) throw new InsufficientScopeError(headerSafe(`missing scope: ${missing.join(' ')}`));
      return authInfo;
    },
  };
}
