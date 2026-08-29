/**
 * 06 — client: the SAME OAuth client code as example 04, pointed at the facade. The client
 * discovers, registers against, authorizes at and exchanges codes with http://…:4106 — it cannot
 * tell that the "authorization server" merely fronts Keycloak.
 * Usage: npm run ex:06:client [-- http://<host>:4106/mcp] [--logout]
 */
import { publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
// One token store per client identity: switching OAUTH_CLIENT_ID must not silently reuse the
// still-valid tokens a dynamically registered client obtained earlier.
const clientName = process.env.OAUTH_CLIENT_ID ? `mcp-auth-demo cli ${process.env.OAUTH_CLIENT_ID}` : undefined;
const provider = new CliOAuthProvider({ serverUrl, clientName });
if (handleLogoutFlag(provider)) process.exit(0);

const clientId = provider.clientInformation()?.client_id;
console.error(`connecting to ${serverUrl} (${clientId ? `client ${clientId}` : 'dynamic client registration via the facade'})`);
const { client, transport } = await connectWithOAuth({ serverUrl, provider, clientName: '06-oauth-proxy-client' });

const result = await runDemo(client);

await transport.terminateSession();
await client.close();
process.exit(printResult('06', result));
