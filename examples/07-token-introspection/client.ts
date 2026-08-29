/**
 * 07 — client: example 04's OAuth client pointed at the introspection server, plus revocation
 * made visible. The token is a Keycloak JWT, but this client never cares what is inside it.
 *
 *   npm run ex:07:client [-- http://<host>:4107/mcp] [--revoke] [--logout]
 *
 * Before connecting, a stored token is probed raw (no OAuth provider): if the resource server
 * answers 401 — e.g. after `npm run ex:07:revoke -- alice` — the client prints the challenge and
 * exits 1 instead of silently re-authenticating, which is the whole point of this example. The SDK
 * would otherwise refresh / restart the browser flow and hide the revocation from you.
 * `--revoke` revokes its own access token at Keycloak (RFC 7009) after the demo, then polls the
 * server with that token until the cached verdict expires and the 401 appears.
 */
import { publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { revokeToken } from '../../src/shared/keycloak.ts';
import { PORT } from './server.ts';

/** What the bearer middleware says about `token`, without an MCP session: GET /mcp carries no
 * session id, so anything but 401 (400 "session id required" when accepted) means "token OK". */
async function probe(url: string, token: string): Promise<{ status: number; challenge?: string }> {
  const res = await fetch(url, { method: 'GET', headers: { accept: 'text/event-stream', authorization: `Bearer ${token}` } });
  await res.body?.cancel();
  return { status: res.status, challenge: res.headers.get('www-authenticate') ?? undefined };
}

const serverUrl = serverUrlArg(publicUrl(PORT));
const provider = new CliOAuthProvider({ serverUrl });
if (handleLogoutFlag(provider)) process.exit(0);
console.error(`connecting to ${serverUrl} (OAuth via Keycloak; introspection happens server-side)`);

const stored = provider.tokens();
if (stored) {
  const { status, challenge } = await probe(serverUrl, stored.access_token);
  if (status === 401) {
    console.error(`stored token rejected by the resource server: 401 ${challenge ?? ''}`.trim());
    console.error('revoked or expired — an introspecting server sees this immediately; a JWKS server (04) would accept a revoked token until exp.');
    console.error('tokens forgotten; run the client again to log in afresh.');
    provider.clearTokens();
    process.exit(1);
  }
}

const { client, transport } = await connectWithOAuth({ serverUrl, provider });
const result = await runDemo(client, {});

let extra: Record<string, unknown> | undefined;
if (process.argv.includes('--revoke')) {
  const token = provider.tokens()!.access_token;
  const clientId = provider.clientInformation()?.client_id;
  if (!clientId) throw new Error('no client id in the token store — pass OAUTH_CLIENT_ID again to revoke');
  await revokeToken(token, { clientId, tokenTypeHint: 'access_token' }); // RFC 7009; public client → client_id only
  console.log(`revoked the access token at Keycloak (RFC 7009, client ${clientId}); polling the server with the same token…`);
  const started = Date.now();
  let verdict = await probe(serverUrl, token);
  while (verdict.status !== 401 && Date.now() - started < 30_000) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    verdict = await probe(serverUrl, token);
  }
  if (verdict.status !== 401) throw new Error('revoked token still accepted after 30s — INTROSPECTION_TTL_SECONDS very large?');
  const afterSeconds = Number(((Date.now() - started) / 1000).toFixed(1));
  console.log(`401 after ${afterSeconds}s (cache TTL): ${verdict.challenge ?? ''}`.trim());
  provider.clearTokens(); // the access token is dead; forget it so the next run logs in again
  extra = { revoked: { afterSeconds, challenge: verdict.challenge } };
}

await transport.terminateSession().catch(() => undefined); // after --revoke the DELETE carries a dead token → ignore
await client.close();
process.exit(printResult('07', result, extra));
