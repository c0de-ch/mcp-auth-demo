/**
 * 09 — client: identical to example 04's OAuth client, just pointed at the GATEWAY (4109).
 *
 * The client cannot tell a gateway from a plain resource server: it discovers the PRM, logs in at
 * Keycloak and sends a Bearer token — exactly as in 04. What is different is invisible to it: the
 * gateway validates that token and forwards a signed assertion to the hidden internal server. The
 * proof shows up in `whoami`, whose `extra.via` is `gateway`.
 *
 * Usage: npm run ex:09:client            (or: npm run ex:09:client -- http://<host>:4109/mcp)
 *        MCP_BROWSER_CMD=… OAUTH_CLIENT_ID=mcp-cli npm run ex:09:client   (headless login)
 *        npm run ex:09:client -- --logout
 */
import { publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './gateway.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
const provider = new CliOAuthProvider({ serverUrl });
if (handleLogoutFlag(provider)) process.exit(0);

console.error(`connecting to the gateway at ${serverUrl} (Keycloak OAuth; the internal server stays hidden)`);
const { client, transport } = await connectWithOAuth({ serverUrl, provider });

const result = await runDemo(client);

await transport.terminateSession();
await client.close();
process.exit(printResult('09', result));
