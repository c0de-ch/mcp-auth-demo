/**
 * keycloak.ts — everything the Keycloak-backed examples (04–07, 09–11) share:
 *
 *   KC                       realm vocabulary (client ids, scopes, roles, audience)
 *   discoverKeycloak()       the realm's OpenID discovery document, cached
 *   createKeycloakVerifier() createJwtVerifier() pre-wired with issuer, JWKS, audience and the
 *                            keycloakEffectiveScopes() policy
 *   introspect()             RFC 7662 token introspection (example 07)
 *   exchangeToken()          RFC 8693 token exchange (example 10)
 *   revokeToken()            RFC 7009 revocation (example 07's --revoke)
 *   adminLogoutUser()        admin REST: kill every session of a user (07's revoke script, tests)
 *
 * None of this is MCP-specific; it is the plain OAuth plumbing every resource server needs.
 * Secrets are read by the caller and passed in; nothing here logs a token or a secret.
 */
import { env, keycloak } from './env.ts';
import { OAuthMetadataSchema, type OAuthMetadata, type OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import { createJwtVerifier, keycloakEffectiveScopes, type JwksSource } from './jwt.ts';

/** Names used throughout the realm (`keycloak/realm-mcp.template.json`). */
export const KC = {
  clients: {
    cli: 'mcp-cli', // public PKCE client for humans
    test: 'mcp-test', // password grant — tests only
    service: 'mcp-service', // client_credentials (05)
    serviceJwt: 'mcp-service-jwt', // private_key_jwt (05 stretch)
    server: 'mcp-server', // the resource server's own identity: introspection (07), exchange (10)
    downstream: 'downstream-api', // audience of the exchanged token (10)
  },
  scopes: { tools: 'mcp:tools', admin: 'mcp:admin', downstream: 'downstream-api' },
  /** Logical audience every MCP access token carries (`aud`), added by the mcp:tools/mcp:admin scopes. */
  audience: 'mcp-server',
  roles: { user: 'mcp-user', admin: 'mcp-admin' },
} as const;

/** Accepted `aud` values: MCP_AUDIENCE (comma list) or the realm default. */
export function audiences(): string[] {
  const fromEnv = (process.env.MCP_AUDIENCE ?? '').split(',').map((a) => a.trim()).filter(Boolean);
  return fromEnv.length > 0 ? fromEnv : [KC.audience];
}

/** Keycloak-specific fields that the SDK's loose schema keeps but does not type. */
export interface KeycloakMetadata extends OAuthMetadata {
  jwks_uri: string;
  introspection_endpoint?: string;
  revocation_endpoint?: string;
  registration_endpoint?: string;
  end_session_endpoint?: string;
}

const discoveryCache = new Map<string, Promise<KeycloakMetadata>>();

/**
 * GET <issuer>/.well-known/openid-configuration, validated with the SDK's (loose) OAuthMetadataSchema
 * so unknown fields survive. Asserts S256 PKCE support and a `jwks_uri`. Cached per issuer.
 */
export function discoverKeycloak(issuer = keycloak().issuer, fetchFn: typeof fetch = fetch): Promise<KeycloakMetadata> {
  let cached = discoveryCache.get(issuer);
  if (!cached) {
    cached = (async () => {
      const url = `${issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`;
      const res = await fetchFn(url, { signal: AbortSignal.timeout(5000) });
      if (!res.ok) throw new Error(`Keycloak discovery failed: ${res.status} ${url}`);
      const metadata = OAuthMetadataSchema.parse(await res.json()) as KeycloakMetadata;
      if (metadata.issuer !== issuer) throw new Error(`Keycloak issuer mismatch: expected ${issuer}, document says ${metadata.issuer}`);
      if (!metadata.jwks_uri) throw new Error('Keycloak discovery document has no jwks_uri');
      if (!metadata.code_challenge_methods_supported?.includes('S256')) throw new Error('Keycloak does not advertise PKCE S256');
      return metadata;
    })();
    discoveryCache.set(issuer, cached);
    cached.catch(() => discoveryCache.delete(issuer)); // a transient failure must not be cached forever
  }
  return cached;
}

export interface KeycloakVerifierOptions {
  /** Discovery document; fetched when omitted. */
  metadata?: KeycloakMetadata;
  /** Scopes the token must carry (after the role policy) or the request gets 403. */
  requiredScopes?: string[];
  /** Accepted `aud` values (default audiences()). */
  audience?: string[];
  /** Override the key source (tests use local JWKs). */
  jwks?: JwksSource;
}

/**
 * The verifier every Keycloak example plugs into requireBearerAuth(): issuer and JWKS from
 * discovery, audience `mcp-server`, and the effective-scopes policy (`mcp:admin` needs the
 * `mcp-admin` realm role).
 */
export async function createKeycloakVerifier({ metadata, requiredScopes, audience, jwks }: KeycloakVerifierOptions = {}): Promise<OAuthTokenVerifier> {
  const md = metadata ?? (await discoverKeycloak());
  return createJwtVerifier({
    issuer: md.issuer,
    audience: audience ?? audiences(),
    jwks: jwks ?? md.jwks_uri,
    requiredScopes,
    effectiveScopes: keycloakEffectiveScopes,
  });
}

/** `Authorization: Basic …` value for client_secret_basic. */
export function basicAuth(clientId: string, secret: string): string {
  return `Basic ${Buffer.from(`${clientId}:${secret}`).toString('base64')}`;
}

/** An OAuth error response (RFC 6749 §5.2) with the HTTP status it came with. */
export class KeycloakError extends Error {
  constructor(
    readonly status: number,
    readonly error: string,
    readonly error_description?: string,
  ) {
    super(`Keycloak ${status} ${error}${error_description ? `: ${error_description}` : ''}`);
    this.name = 'KeycloakError';
  }
}

interface ClientAuth {
  clientId: string;
  clientSecret?: string;
  metadata?: KeycloakMetadata;
  fetchFn?: typeof fetch;
}

/** Form POST with client_secret_basic (or the public client_id in the body when there is no secret). */
async function oauthPost(url: string, form: Record<string, string>, { clientId, clientSecret, fetchFn = fetch }: ClientAuth): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' };
  const body = new URLSearchParams(form);
  if (clientSecret) headers.authorization = basicAuth(clientId, clientSecret);
  else body.set('client_id', clientId);
  return fetchFn(url, { method: 'POST', headers, body, signal: AbortSignal.timeout(10_000) });
}

async function readJson<T>(res: Response): Promise<T> {
  const body = (await res.json().catch(() => ({}))) as T & { error?: string; error_description?: string };
  if (!res.ok) throw new KeycloakError(res.status, body.error ?? 'unknown_error', body.error_description);
  return body;
}

/** RFC 7662 introspection response (Keycloak adds the usual JWT claims when `active`). */
export interface IntrospectionResponse {
  active: boolean;
  sub?: string;
  username?: string;
  client_id?: string;
  scope?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  iss?: string;
  azp?: string;
  token_type?: string;
  realm_access?: { roles?: string[] };
  [claim: string]: unknown;
}

/**
 * RFC 7662: ask Keycloak whether `token` is active. Keycloak only answers `active: true` when the
 * introspecting client (`mcp-server`) is in the token's `aud` — which the mcp:tools scope's audience
 * mapper guarantees. Network/HTTP failures throw (the caller maps them to ServerError).
 */
export async function introspect(token: string, auth: ClientAuth & { tokenTypeHint?: 'access_token' | 'refresh_token' }): Promise<IntrospectionResponse> {
  const md = auth.metadata ?? (await discoverKeycloak());
  const url = md.introspection_endpoint ?? keycloak().introspectionEndpoint;
  const form: Record<string, string> = { token };
  if (auth.tokenTypeHint) form.token_type_hint = auth.tokenTypeHint;
  return readJson<IntrospectionResponse>(await oauthPost(url, form, auth));
}

export interface ExchangeOptions extends ClientAuth {
  /** The caller's access token (must carry the requesting client in `aud`). */
  subjectToken: string;
  /** Client id of the target API (`downstream-api`). */
  audience: string;
  /** Keycloak needs the audience's scope here as well (`downstream-api`), otherwise `invalid_request`. */
  scope?: string;
  clientSecret: string;
}

/**
 * RFC 8693 standard token exchange (Keycloak 26, client attribute `standard.token.exchange.enabled`):
 * the resource server (`mcp-server`) trades the user's token for one with `aud=<audience>` and
 * `azp=mcp-server` — acting on behalf of the user towards a downstream API. Throws KeycloakError.
 */
export async function exchangeToken({ subjectToken, audience, scope, ...auth }: ExchangeOptions): Promise<OAuthTokens> {
  const md = auth.metadata ?? (await discoverKeycloak());
  const form: Record<string, string> = {
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: subjectToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    requested_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    audience,
  };
  if (scope) form.scope = scope;
  return readJson<OAuthTokens>(await oauthPost(md.token_endpoint, form, auth));
}

/**
 * RFC 7009: revoke an access or refresh token. Public clients (`mcp-cli`) send only `client_id`.
 * Keycloak answers 200 for unknown tokens too (as the RFC requires). Throws KeycloakError otherwise.
 */
export async function revokeToken(token: string, auth: ClientAuth & { tokenTypeHint?: 'access_token' | 'refresh_token' }): Promise<void> {
  const md = auth.metadata ?? (await discoverKeycloak());
  const url = md.revocation_endpoint ?? `${md.issuer}/protocol/openid-connect/revoke`;
  const form: Record<string, string> = { token };
  if (auth.tokenTypeHint) form.token_type_hint = auth.tokenTypeHint;
  const res = await oauthPost(url, form, auth);
  if (!res.ok) await readJson(res); // throws with the OAuth error body
}

/** Admin-CLI token for the master realm (KC_ADMIN_USER / KC_ADMIN_PASSWORD — DEMO credentials). */
async function adminToken(fetchFn: typeof fetch): Promise<string> {
  const { baseUrl } = keycloak();
  const res = await fetchFn(`${baseUrl}/realms/master/protocol/openid-connect/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'password',
      client_id: 'admin-cli',
      username: env('KC_ADMIN_USER', 'admin'),
      password: env('KC_ADMIN_PASSWORD', 'admin'),
    }),
    signal: AbortSignal.timeout(10_000),
  });
  return (await readJson<OAuthTokens>(res)).access_token;
}

/**
 * Admin REST API: log the user out of every session, which makes Keycloak answer `active: false`
 * for their tokens from now on (JWT verifiers keep accepting them until `exp` — that contrast is
 * what example 07 demonstrates). Needs the realm admin credentials from `.env`.
 */
export async function adminLogoutUser(username: string, fetchFn: typeof fetch = fetch): Promise<void> {
  const { baseUrl, realm } = keycloak();
  const headers = { authorization: `Bearer ${await adminToken(fetchFn)}` };
  const users = await readJson<Array<{ id: string; username: string }>>(
    await fetchFn(`${baseUrl}/admin/realms/${realm}/users?username=${encodeURIComponent(username)}&exact=true`, { headers, signal: AbortSignal.timeout(10_000) }),
  );
  const user = users.find((u) => u.username === username);
  if (!user) throw new Error(`Keycloak user not found: ${username}`);
  const res = await fetchFn(`${baseUrl}/admin/realms/${realm}/users/${user.id}/logout`, { method: 'POST', headers, signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new KeycloakError(res.status, 'admin_logout_failed');
}
