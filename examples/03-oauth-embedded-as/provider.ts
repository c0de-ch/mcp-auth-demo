/**
 * 03 — provider.ts: the authorization-server brain behind the SDK's mcpAuthRouter.
 *
 * The SDK contributes the OAuth endpoints (/authorize validation, /token with PKCE S256,
 * /register, /revoke, metadata documents); this class contributes everything stateful:
 * clients, pending authorizations (login + consent), single-use codes, opaque access tokens
 * and rotating refresh tokens — all in memory, gone on restart (that is the point of the demo).
 *
 * Security behaviour implemented here (each has a test in server.test.ts):
 *   - authorization codes are single-use; REUSE revokes every token issued from that code
 *     (OAuth 2.1 §4.1.2) — detected even though the SDK asks for the PKCE challenge first
 *   - refresh tokens rotate on every use; presenting a rotated token revokes the whole family
 *   - codes are bound to client_id, redirect_uri, PKCE challenge, scopes, resource and subject
 *   - passwords are scrypt-hashed at rest and compared in constant time
 *   - scopes: the AS only knows SCOPES_SUPPORTED; consent can only grant what the USER may
 *     grant (alice: mcp:tools; bob: + mcp:admin) — scope ≠ user right is decided here
 *   - verifyAccessToken throws InsufficientScopeError when mcp:tools is missing, so the /mcp
 *     401 challenge never pins a `scope=` and clients request the PRM's scopes (SEP-835)
 *   - every OAuthError message is a static string (they end up in WWW-Authenticate / redirects)
 */
import { publicHost } from '../../src/shared/env.ts';
import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import type { Response } from 'express';
import type { AuthorizationParams, OAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { OAuthClientInformationFull, OAuthTokenRevocationRequest, OAuthTokens } from '@modelcontextprotocol/sdk/shared/auth.js';
import { InsufficientScopeError, InvalidGrantError, InvalidScopeError, InvalidTargetError, InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { SCOPE_ADMIN, SCOPE_TOOLS } from '../../src/shared/tools.ts';

export const SCOPES_SUPPORTED: string[] = [SCOPE_TOOLS, SCOPE_ADMIN];

export const SCOPE_DESCRIPTIONS: Record<string, string> = {
  [SCOPE_TOOLS]: 'Use the MCP demo tools on your behalf',
  [SCOPE_ADMIN]: 'Use the administrative demo tools',
};

// ---------------------------------------------------------------- demo users

/**
 * DEMO user table. Passwords are scrypt-hashed at rest (both are the string "password" — this is
 * a public demo); a real AS would load such a table from a credential store. `grantableScopes` is
 * what the consent page may grant this user: only bob can hand out mcp:admin.
 */
interface DemoUser {
  sub: string;
  salt: string;
  /** hex(scrypt(password, salt, 64)) */
  passwordScrypt: string;
  grantableScopes: string[];
}

const USERS: Record<string, DemoUser> = {
  alice: {
    sub: 'alice',
    salt: 'dad46ba36b72ac3f1513daad22b67a0b',
    passwordScrypt:
      'cfd216b118984a071c170bff3240f4b0d48bd20aab9dfae7961f46de7411ddd8cf4daa3be6bd3e41d9fa2bc52042e2f333d58bffa35fbb991f6afbadb10e00e7',
    grantableScopes: [SCOPE_TOOLS],
  },
  bob: {
    sub: 'bob',
    salt: '2aa4fee8811cb9547b689b81b2126970',
    passwordScrypt:
      '00058d12beb7a298350f308065119dec38c41ef921c42dfa077df44c03800ae82479fa48dc332b7831c1e0246ba9447576074b42e7a357821b53100509c283b7',
    grantableScopes: [SCOPE_TOOLS, SCOPE_ADMIN],
  },
};

/** Compared against for unknown usernames so the lookup takes the same time either way. */
const DUMMY_USER: DemoUser = {
  sub: 'dummy',
  salt: 'eff00d20c7d426f6f504e443e65290a6',
  passwordScrypt:
    '6359460dd927e5921462c75bc9bdd0f8bc18a651dcbe5f02cd571b30cc25b9a1f5e11e9ed0cec32d8a81f4d0fac88479b7fbcf0c590837f602b3718d12c22ba5',
  grantableScopes: [],
};

/** Constant-time password check; unknown users burn the same scrypt work as known ones. */
function verifyCredentials(username: string, password: string): DemoUser | undefined {
  const user = Object.hasOwn(USERS, username) ? USERS[username] : DUMMY_USER;
  const computed = scryptSync(password, user.salt, 64);
  const stored = Buffer.from(user.passwordScrypt, 'hex');
  const match = timingSafeEqual(computed, stored);
  return match && user !== DUMMY_USER ? user : undefined;
}

/** Constant-time comparison of two secrets of possibly different lengths (csrf values). */
function safeEqual(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb) && a === b;
}

// ---------------------------------------------------------------- pre-registered client

/**
 * The one pre-registered client (OAUTH_CLIENT_ID=mcp-cli skips Dynamic Client Registration).
 * The callback listener may run on 4199 (the repo default) or 4193, on the same machine
 * (loopback) or on another LAN machine (PUBLIC_HOST). Loopback entries get RFC 8252 port
 * relaxation from the SDK; the PUBLIC_HOST entries are matched exactly.
 */
const CALLBACK_PORTS = [4199, 4193];
const MCP_CLI_REDIRECT_URIS = CALLBACK_PORTS.flatMap((p) => [
  `http://127.0.0.1:${p}/callback`,
  `http://localhost:${p}/callback`, // loopback-ok: registered redirect URI, never dialled by the server
  `http://${publicHost()}:${p}/callback`,
]);

function preRegisteredClients(): Map<string, OAuthClientInformationFull> {
  return new Map([
    [
      'mcp-cli',
      {
        client_id: 'mcp-cli',
        client_name: 'mcp-cli (pre-registered demo client)',
        redirect_uris: MCP_CLI_REDIRECT_URIS,
        token_endpoint_auth_method: 'none', // public client: PKCE instead of a secret
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        scope: SCOPES_SUPPORTED.join(' '),
      },
    ],
  ]);
}

// ---------------------------------------------------------------- state records

/** An /authorize request waiting for the human: login first, then consent, then the code. */
export interface PendingAuthorization {
  id: string;
  /** Per-transaction anti-CSRF secret; rendered into the forms, required back on every POST. */
  csrf: string;
  client: OAuthClientInformationFull;
  params: AuthorizationParams;
  /** Set by a successful POST /login. */
  sub?: string;
  grantableScopes?: string[];
  expiresAt: number; // ms
}

interface CodeRecord {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scopes: string[];
  resource?: string;
  sub: string;
  expiresAt: number; // ms
}

interface AccessTokenRecord {
  clientId: string;
  scopes: string[];
  sub: string;
  family: string;
  resource?: string;
  expiresAt: number; // seconds since epoch (AuthInfo convention)
}

interface RefreshTokenRecord extends AccessTokenRecord {
  /** True once this token was exchanged; presenting it again reveals theft → revoke the family. */
  rotated: boolean;
}

export interface ConsentScope {
  scope: string;
  description: string;
  /** False when the logged-in user may not grant this scope (alice + mcp:admin). */
  granted: boolean;
}

export interface ConsentView {
  csrf: string;
  sub: string;
  clientId: string;
  clientName: string;
  redirectUri: string;
  resource?: string;
  scopes: ConsentScope[];
}

export interface DemoAuthorizationServerOptions {
  /** Canonical MCP resource URL — the only RFC 8707 `resource` this AS will accept. */
  resource: string;
  txnTtlMs?: number;
  codeTtlMs?: number;
  accessTokenTtlSec?: number;
  refreshTokenTtlSec?: number;
}

const nowSec = () => Math.floor(Date.now() / 1000);
const randomId = (bytes = 32) => randomBytes(bytes).toString('hex');
/** How long a spent code is remembered so its reuse can be detected and punished. */
const USED_CODE_MEMORY_MS = 10 * 60_000;

// ---------------------------------------------------------------- the provider

export class DemoAuthorizationServer implements OAuthServerProvider {
  readonly resource: string;
  private readonly txnTtlMs: number;
  private readonly codeTtlMs: number;
  private readonly accessTokenTtlSec: number;
  private readonly refreshTokenTtlSec: number;

  private readonly clients = preRegisteredClients();
  private readonly txns = new Map<string, PendingAuthorization>();
  private readonly codes = new Map<string, CodeRecord>();
  /** Spent codes → token family, for OAuth 2.1 §4.1.2 reuse detection. */
  private readonly usedCodes = new Map<string, { family: string; expiresAt: number }>();
  private readonly accessTokens = new Map<string, AccessTokenRecord>();
  private readonly refreshTokens = new Map<string, RefreshTokenRecord>();

  constructor(options: DemoAuthorizationServerOptions) {
    this.resource = options.resource;
    this.txnTtlMs = options.txnTtlMs ?? 5 * 60_000;
    this.codeTtlMs = options.codeTtlMs ?? 5 * 60_000;
    this.accessTokenTtlSec = options.accessTokenTtlSec ?? 15 * 60;
    this.refreshTokenTtlSec = options.refreshTokenTtlSec ?? 24 * 60 * 60;
  }

  /** The SDK's /register handler generates client_id/secret and hands the full record here. */
  readonly clientsStore: OAuthRegisteredClientsStore = {
    getClient: (clientId) => this.clients.get(clientId),
    registerClient: (client) => {
      const info = client as OAuthClientInformationFull; // the handler filled client_id
      this.clients.set(info.client_id, info);
      return info;
    },
  };

  // ------------------------------------------------------ OAuthServerProvider

  /**
   * Called by the SDK once client_id + redirect_uri are validated. Parks the request under an
   * unguessable transaction id and sends the browser to our own login page. Scope and resource
   * problems are thrown here so the SDK reports them per spec: a 302 back to the redirect_uri
   * with `error=` (the redirect URI itself is already known to be registered).
   */
  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: Response): Promise<void> {
    this.prune();
    if ((params.scopes ?? []).some((s) => !SCOPES_SUPPORTED.includes(s))) {
      throw new InvalidScopeError('requested scope is not supported by this authorization server');
    }
    if (params.resource && params.resource.href !== this.resource) {
      throw new InvalidTargetError('resource is not served by this authorization server');
    }
    const id = randomId();
    this.txns.set(id, {
      id,
      csrf: randomId(16),
      client,
      // An empty scope request falls back to the baseline tool scope (documented AS default).
      params: { ...params, scopes: params.scopes?.length ? params.scopes : [SCOPE_TOOLS] },
      expiresAt: Date.now() + this.txnTtlMs,
    });
    res.redirect(`/login?txn=${id}`);
  }

  /** The SDK verifies PKCE S256 locally against this stored challenge — reuse is detected here. */
  async challengeForAuthorizationCode(_client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    this.prune();
    const used = this.usedCodes.get(authorizationCode);
    if (used) {
      // OAuth 2.1 §4.1.2: a code presented twice means it leaked — burn everything it produced.
      this.revokeFamily(used.family);
      throw new InvalidGrantError('authorization code was already used; all tokens issued from it are now revoked');
    }
    const record = this.codes.get(authorizationCode);
    if (!record) throw new InvalidGrantError('unknown or expired authorization code');
    return record.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string, // PKCE already verified by the SDK token handler
    redirectUri?: string,
    resource?: URL,
  ): Promise<OAuthTokens> {
    const record = this.codes.get(authorizationCode);
    if (!record || record.expiresAt < Date.now()) {
      this.codes.delete(authorizationCode);
      throw new InvalidGrantError('unknown or expired authorization code');
    }
    // The code is bound to the client, the redirect_uri and the resource of the /authorize request.
    if (record.clientId !== client.client_id) throw new InvalidGrantError('authorization code was issued to another client');
    if (redirectUri !== undefined && redirectUri !== record.redirectUri) {
      throw new InvalidGrantError('redirect_uri does not match the authorization request');
    }
    if (resource !== undefined && resource.href !== (record.resource ?? this.resource)) {
      throw new InvalidTargetError('resource does not match the authorization request');
    }
    // Single use: spend the code, but remember it so reuse can revoke the family (see above).
    this.codes.delete(authorizationCode);
    const family = randomId(16);
    this.usedCodes.set(authorizationCode, { family, expiresAt: Date.now() + USED_CODE_MEMORY_MS });
    return this.issueTokens({ clientId: record.clientId, scopes: record.scopes, sub: record.sub, family, resource: record.resource });
  }

  async exchangeRefreshToken(
    client: OAuthClientInformationFull,
    refreshToken: string,
    scopes?: string[],
    resource?: URL,
  ): Promise<OAuthTokens> {
    this.prune();
    const record = this.refreshTokens.get(refreshToken);
    if (!record || record.expiresAt <= nowSec()) {
      this.refreshTokens.delete(refreshToken);
      throw new InvalidGrantError('unknown or expired refresh token');
    }
    if (record.rotated) {
      // The token was already rotated away: someone replayed an old refresh token. Burn the family.
      this.revokeFamily(record.family);
      throw new InvalidGrantError('refresh token was already rotated; all tokens in its family are now revoked');
    }
    if (record.clientId !== client.client_id) throw new InvalidGrantError('refresh token was issued to another client');
    if (resource !== undefined && resource.href !== (record.resource ?? this.resource)) {
      throw new InvalidTargetError('resource does not match the refresh token');
    }
    let granted = record.scopes;
    if (scopes?.length) {
      // RFC 6749 §6: the refreshed scope may only narrow, never widen.
      if (scopes.some((s) => !record.scopes.includes(s))) {
        throw new InvalidScopeError('requested scope exceeds the scope originally granted');
      }
      granted = scopes;
    }
    record.rotated = true; // kept until its natural expiry so a replay is recognisable
    return this.issueTokens({ clientId: record.clientId, scopes: granted, sub: record.sub, family: record.family, resource: record.resource });
  }

  /** Used by requireBearerAuth on /mcp. Opaque token → in-memory lookup, no JWT anywhere. */
  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const record = this.accessTokens.get(token);
    if (!record || record.expiresAt <= nowSec()) {
      if (record) this.accessTokens.delete(token);
      throw new InvalidTokenError('unknown or expired access token');
    }
    if (!record.scopes.includes(SCOPE_TOOLS)) {
      // 403 insufficient_scope (no scope= pinned in the challenge — the PRM advertises the scopes).
      throw new InsufficientScopeError('token does not carry the mcp:tools scope');
    }
    return {
      token,
      clientId: record.clientId,
      scopes: record.scopes,
      expiresAt: record.expiresAt,
      resource: new URL(record.resource ?? this.resource),
      extra: { sub: record.sub },
    };
  }

  /** RFC 7009. Access token → that token only; refresh token → its whole family. */
  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const access = this.accessTokens.get(request.token);
    if (access) {
      if (access.clientId === client.client_id) this.accessTokens.delete(request.token);
      return; // wrong client: do nothing, reveal nothing (the endpoint answers 200 regardless)
    }
    const refresh = this.refreshTokens.get(request.token);
    if (refresh && refresh.clientId === client.client_id) this.revokeFamily(refresh.family);
  }

  // ------------------------------------------------------ pages.ts interface

  /** The pending transaction behind ?txn=…, if it is still alive. */
  pending(txnId: string): PendingAuthorization | undefined {
    const txn = this.txns.get(txnId);
    if (!txn) return undefined;
    if (txn.expiresAt < Date.now()) {
      this.txns.delete(txnId);
      return undefined;
    }
    return txn;
  }

  /** POST /login: bind the authenticated user to the transaction. */
  authenticate(txnId: string, csrf: string, username: string, password: string): 'ok' | 'expired' | 'csrf' | 'credentials' {
    const txn = this.pending(txnId);
    if (!txn) return 'expired';
    if (!safeEqual(csrf, txn.csrf)) return 'csrf';
    const user = verifyCredentials(username, password);
    if (!user) return 'credentials';
    txn.sub = user.sub;
    txn.grantableScopes = user.grantableScopes;
    return 'ok';
  }

  /** GET /consent: everything the consent page shows. Client metadata is rendered — escape it! */
  consentView(txnId: string): ConsentView | 'expired' | 'unauthenticated' {
    const txn = this.pending(txnId);
    if (!txn) return 'expired';
    if (!txn.sub || !txn.grantableScopes) return 'unauthenticated';
    return {
      csrf: txn.csrf,
      sub: txn.sub,
      clientId: txn.client.client_id,
      clientName: txn.client.client_name ?? txn.client.client_id,
      redirectUri: txn.params.redirectUri,
      resource: txn.params.resource?.href,
      scopes: (txn.params.scopes ?? []).map((scope) => ({
        scope,
        description: SCOPE_DESCRIPTIONS[scope] ?? scope,
        granted: txn.grantableScopes!.includes(scope),
      })),
    };
  }

  /**
   * POST /consent: the resource owner's decision. Accept → single-use code bound to
   * { client, redirect_uri, PKCE challenge, granted scopes, resource, sub }; deny → error
   * redirect. Either way the transaction is spent.
   */
  decide(txnId: string, csrf: string, accept: boolean): { redirectTo: string } | 'expired' | 'csrf' | 'unauthenticated' {
    const txn = this.pending(txnId);
    if (!txn) return 'expired';
    if (!safeEqual(csrf, txn.csrf)) return 'csrf';
    if (!txn.sub || !txn.grantableScopes) return 'unauthenticated';
    this.txns.delete(txnId);

    const redirect = new URL(txn.params.redirectUri);
    const withState = () => {
      if (txn.params.state) redirect.searchParams.set('state', txn.params.state);
      return { redirectTo: redirect.href };
    };
    const granted = (txn.params.scopes ?? []).filter((s) => txn.grantableScopes!.includes(s));
    if (!accept || granted.length === 0) {
      redirect.searchParams.set('error', 'access_denied');
      redirect.searchParams.set('error_description', accept ? 'none of the requested scopes are available to this account' : 'the resource owner denied the request');
      return withState();
    }
    const code = randomId();
    this.codes.set(code, {
      clientId: txn.client.client_id,
      redirectUri: txn.params.redirectUri,
      codeChallenge: txn.params.codeChallenge,
      scopes: granted,
      resource: txn.params.resource?.href,
      sub: txn.sub,
      expiresAt: Date.now() + this.codeTtlMs,
    });
    redirect.searchParams.set('code', code);
    return withState();
  }

  // ------------------------------------------------------ internals

  private issueTokens(grant: { clientId: string; scopes: string[]; sub: string; family: string; resource?: string }): OAuthTokens {
    const accessToken = randomId();
    const refreshToken = randomId();
    this.accessTokens.set(accessToken, { ...grant, expiresAt: nowSec() + this.accessTokenTtlSec });
    this.refreshTokens.set(refreshToken, { ...grant, expiresAt: nowSec() + this.refreshTokenTtlSec, rotated: false });
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: this.accessTokenTtlSec,
      refresh_token: refreshToken,
      // Echo the granted scope — it may be narrower than requested (RFC 6749 §5.1 requires this).
      scope: grant.scopes.join(' '),
    };
  }

  /** Deletes every access and refresh token descending from one authorization code. */
  private revokeFamily(family: string): void {
    for (const [token, record] of this.accessTokens) if (record.family === family) this.accessTokens.delete(token);
    for (const [token, record] of this.refreshTokens) if (record.family === family) this.refreshTokens.delete(token);
  }

  /** Lazy cleanup so the in-memory maps stay bounded. */
  private prune(): void {
    const ms = Date.now();
    const sec = nowSec();
    for (const [id, txn] of this.txns) if (txn.expiresAt < ms) this.txns.delete(id);
    for (const [code, record] of this.codes) if (record.expiresAt < ms) this.codes.delete(code);
    for (const [code, record] of this.usedCodes) if (record.expiresAt < ms) this.usedCodes.delete(code);
    for (const [token, record] of this.accessTokens) if (record.expiresAt <= sec) this.accessTokens.delete(token);
    for (const [token, record] of this.refreshTokens) if (record.expiresAt <= sec) this.refreshTokens.delete(token);
  }
}
