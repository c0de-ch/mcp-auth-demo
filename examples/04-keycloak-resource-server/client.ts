/**
 * 04 — client: the SDK drives the whole spec flow (401 → PRM → AS metadata → DCR → PKCE →
 * browser → code → tokens → retry); CliOAuthProvider only persists state and runs the loopback
 * callback listener. Default is Dynamic Client Registration; OAUTH_CLIENT_ID=mcp-cli uses the
 * pre-registered public client (callback port 4199 — the one registered in the realm).
 * Usage: npm run ex:04:client [-- http://<host>:4104/mcp] [--logout]
 */
import { publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
const staticId = process.env.OAUTH_CLIENT_ID?.trim();

// One token store per (server, client): a token minted for the dynamically registered client must
// never be replayed as mcp-cli (and switching OAUTH_CLIENT_ID must not reuse foreign tokens).
const provider = new CliOAuthProvider({ serverUrl, clientName: staticId ? `mcp-auth-demo cli [${staticId}]` : undefined });
if (handleLogoutFlag(provider)) process.exit(0);

console.error(`connecting to ${serverUrl} (${staticId ? `pre-registered client ${staticId}` : 'Dynamic Client Registration'})`);
const { client, transport } = await connectWithOAuth({ serverUrl, provider, clientName: '04-keycloak-client' });

const expected = process.env.EXPECT_ADMIN?.trim();
const result = await runDemo(client, { expectAdmin: expected ? expected === 'ok' : undefined });

await transport.terminateSession().catch(() => undefined); // server may have restarted; exit cleanly anyway
await client.close();
process.exit(printResult('04', result));
