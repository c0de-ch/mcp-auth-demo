/**
 * 06 — OAuth facade: the MCP server pretends to BE the authorization server and proxies every
 * OAuth operation to Keycloak (SDK ProxyOAuthServerProvider). Clients only ever talk to this
 * origin: metadata, /register (DCR passthrough), /authorize (302 to Keycloak) and /token
 * (server-side form POST to Keycloak) all live on port 4106. The one thing that does NOT pass
 * through the facade is the browser callback — Keycloak redirects straight to the CLI's
 * loopback listener, so the redirect URI must be registered at Keycloak too.
 *
 * TRANSITIONAL pattern: useful to hide the IdP or to give DCR to clients that cannot register
 * upstream themselves; the honest limitations are in docs/06-oauth-proxy-keycloak.md.
 */
import { isMain, port, publicHost, publicUrl } from '../../src/shared/env.ts';
import type { Express } from 'express';
import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import type { OAuthRegisteredClientsStore } from '@modelcontextprotocol/sdk/server/auth/clients.js';
import type { OAuthTokenVerifier } from '@modelcontextprotocol/sdk/server/auth/provider.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { FetchLike } from '@modelcontextprotocol/sdk/shared/transport.js';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { SCOPE_ADMIN, SCOPE_TOOLS, createDemoServer } from '../../src/shared/tools.ts';
import { KC, createKeycloakVerifier, discoverKeycloak, type KeycloakMetadata } from '../../src/shared/keycloak.ts';
import type { JwksSource } from '../../src/shared/jwt.ts';

export const PORT = port('PORT_06', port('MCP_PORT', 4106));

/**
 * The facade's copy of the realm's pre-registered public client. getClient() must return
 * redirect_uris — the SDK validates them locally in /authorize before anything reaches
 * Keycloak — and they must MIRROR what the realm registered for `mcp-cli`, because Keycloak
 * validates the redirect_uri AGAIN (exactly, no loopback-port relaxation) when the browser
 * arrives. OAUTH_CALLBACK_PORT must therefore equal the port the realm template was rendered
 * with (default 4199); a URI only the facade accepts dies on Keycloak's error page.
 */
export function seededCliClient(): OAuthClientInformationFull {
  const callbackPort = port('OAUTH_CALLBACK_PORT', 4199);
  const hosts = ['localhost', '127.0.0.1', publicHost()]; // as in realm-mcp.template.json — loopback-ok
  return {
    client_id: KC.clients.cli,
    client_name: 'MCP CLI client (public, PKCE)',
    redirect_uris: hosts.map((host) => `http://${host}:${callbackPort}/callback`),
    token_endpoint_auth_method: 'none', // public client: PKCE instead of a secret — verified by Keycloak only
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    scope: `${SCOPE_TOOLS} ${SCOPE_ADMIN}`,
  };
}

export interface KeycloakFacadeOptions {
  /** Keycloak's discovery document — the upstream endpoints every OAuth call is proxied to. */
  metadata: KeycloakMetadata;
  /** Verifies Keycloak-issued JWTs at /mcp (the facade doubles as the resource server). */
  verifier: OAuthTokenVerifier;
  /** Upstream HTTP for /register, /token, /revoke (tests inject a stub/spy; /authorize never fetches — it redirects the browser). */
  fetch?: FetchLike;
  /** Pre-seeded client records (default: the realm's public `mcp-cli`). */
  clients?: OAuthClientInformationFull[];
}

/**
 * ProxyOAuthServerProvider wired to Keycloak, plus the one thing the stock class is missing:
 * it forwards /register to Keycloak but never persists the response, so the very next
 * /authorize or /token for the freshly issued client_id would fail with invalid_client.
 * The clientsStore override remembers everything Keycloak returns (in memory — a restart
 * forgets dynamically registered clients, the seeded `mcp-cli` always survives).
 */
export class KeycloakFacade extends ProxyOAuthServerProvider {
  /** client_id → registration: the seeded clients plus everything /register returned. */
  readonly clients: Map<string, OAuthClientInformationFull>;

  constructor({ metadata, verifier, fetch: fetchFn, clients = [seededCliClient()] }: KeycloakFacadeOptions) {
    const known = new Map(clients.map((client) => [client.client_id, client]));
    super({
      endpoints: {
        authorizationUrl: metadata.authorization_endpoint,
        tokenUrl: metadata.token_endpoint,
        revocationUrl: metadata.revocation_endpoint,
        registrationUrl: metadata.registration_endpoint,
      },
      verifyAccessToken: (token) => verifier.verifyAccessToken(token),
      getClient: async (clientId) => known.get(clientId),
      fetch: fetchFn,
    });
    this.clients = known;
  }

  override get clientsStore(): OAuthRegisteredClientsStore {
    const upstream = super.clientsStore; // getClient + (when registrationUrl is set) the DCR passthrough
    const registerUpstream = upstream.registerClient;
    return {
      getClient: upstream.getClient,
      ...(registerUpstream && {
        registerClient: async (client: Omit<OAuthClientInformationFull, 'client_id' | 'client_id_issued_at'>) => {
          // The SDK parses Keycloak's answer with a STRIP schema, so extras such as the
          // registration_access_token are already gone here (and never reach the MCP client).
          const registered = await registerUpstream(client);
          this.clients.set(registered.client_id, registered);
          console.error(`[06-oauth-proxy-keycloak] DCR passthrough: Keycloak issued client_id ${registered.client_id}`);
          return registered;
        },
      }),
    };
  }
}

export interface Overrides {
  /** Keycloak discovery document (tests pass a stub; fetched from KEYCLOAK_URL otherwise). */
  metadata?: KeycloakMetadata;
  /** Key source for access-token verification (tests pass a local JWKS). */
  jwks?: JwksSource;
  /** Accepted `aud` values (default MCP_AUDIENCE | mcp-server). */
  audience?: string[];
  /** The facade's canonical MCP URL (default publicUrl(PORT)); tests pass their ephemeral one. */
  resourceUrl?: string;
  /** fetch used for every upstream call (tests pass a spy to prove what is — and is not — forwarded). */
  fetch?: FetchLike;
  /** Extra seeded clients besides mcp-cli (tests seed mcp-test to exercise the refresh passthrough). */
  clients?: OAuthClientInformationFull[];
}

export async function buildApp(overrides: Overrides = {}): Promise<Express> {
  const metadata = overrides.metadata ?? (await discoverKeycloak());
  const resourceUrl = overrides.resourceUrl ?? publicUrl(PORT);
  const verifier = await createKeycloakVerifier({
    metadata,
    requiredScopes: [SCOPE_TOOLS], // enforced by the VERIFIER (403), not by requireBearerAuth (401 scope=…)
    audience: overrides.audience,
    jwks: overrides.jwks,
  });
  const provider = new KeycloakFacade({
    metadata,
    verifier,
    fetch: overrides.fetch,
    clients: [seededCliClient(), ...(overrides.clients ?? [])],
  });
  const rateLimit = process.env.MCP_RATE_LIMIT === '0' ? (false as const) : undefined;

  const app = createApp();
  // As far as clients can tell, this origin IS the authorization server: AS metadata, PRM,
  // /authorize, /token, /register and /revoke all live here (mcpAuthRouter mounts at the root).
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL('/', resourceUrl), // the facade's issuer = its own origin, not Keycloak's
      resourceServerUrl: new URL(resourceUrl), // PRM: authorization_servers = [facade]
      scopesSupported: [SCOPE_TOOLS, SCOPE_ADMIN], // SEP-835: the 401 names no scope, so clients request these
      resourceName: '06-oauth-proxy-keycloak',
      // Forward the DCR body untouched — Keycloak, not the facade, assigns the client_id.
      clientRegistrationOptions: { rateLimit, clientIdGeneration: false },
      authorizationOptions: { rateLimit },
      tokenOptions: { rateLimit },
      revocationOptions: { rateLimit },
    }),
  );
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '06-oauth-proxy-keycloak' }),
    // No requiredScopes here: that would pin scope="mcp:tools" in the 401 and bob could never
    // obtain mcp:admin through the browser flow (see "Scope selection" in src/shared/README.md).
    auth: requireBearerAuth({ verifier: provider, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(resourceUrl)) }),
  });
  return app;
}

if (isMain(import.meta)) {
  const metadata = await discoverKeycloak();
  console.error(`[06-oauth-proxy-keycloak] facade issuer ${new URL('/', publicUrl(PORT)).href} → upstream Keycloak ${metadata.issuer}`);
  console.error(`[06-oauth-proxy-keycloak] clients talk ONLY to this origin; Keycloak redirects the browser straight to the CLI callback`);
  await listen(await buildApp({ metadata }), { port: PORT, name: '06-oauth-proxy-keycloak' });
}
