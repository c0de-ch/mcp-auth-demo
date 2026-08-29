/**
 * 11 — the UNCHANGED TypeScript OAuth client (example 04's shape) pointed at the Python server:
 * the interop proof. Discovery (401 → PRM → Keycloak metadata → DCR/PKCE → tokens) is all done
 * by the TS SDK; the server on the other side is `mcp` (Python) 2.1.1.
 * Usage: npm run ex:11:client [-- http://<host>:4111/mcp | --logout]     (or MCP_SERVER_URL=…)
 * Env: OAUTH_CLIENT_ID=mcp-cli for the pre-registered client (default: Dynamic Client Registration).
 */
import { port, publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';

const serverUrl = serverUrlArg(publicUrl(port('PORT_11', 4111)));
const provider = new CliOAuthProvider({ serverUrl, clientName: '11-python-mcp-keycloak cli' });
if (handleLogoutFlag(provider)) process.exit(0);

console.error(`connecting to ${serverUrl} (OAuth via Keycloak; the server side is Python)`);
const { client, transport } = await connectWithOAuth({ serverUrl, provider, clientName: '11-python-mcp-keycloak-client' });

const result = await runDemo(client);

await transport.terminateSession();
await client.close();
process.exit(printResult('11', result));
