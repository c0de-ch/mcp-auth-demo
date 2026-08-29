/**
 * 10 — client: exactly 04's OAuth client (discovery → DCR/PKCE → browser → Bearer) plus ONE
 * extra call, `downstream_profile`, printed under `extra.downstream` in the RESULT line —
 * the downstream API's view of the exchanged token (sub = you, azp = mcp-server).
 * Usage: npm run ex:10:client [-- http://<host>:4110/mcp | --logout]
 */
import { publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { callTool, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
const provider = new CliOAuthProvider({ serverUrl });
if (handleLogoutFlag(provider)) process.exit(0);

console.error(`connecting to ${serverUrl}`);
const { client, transport } = await connectWithOAuth({ serverUrl, provider, clientName: '10-token-exchange-client' });

const result = await runDemo(client);
const profile = await callTool(client, 'downstream_profile');
console.log(`downstream   -> ${profile.isError ? `ERROR ${profile.text}` : profile.text}`);
const body = (profile.json ?? {}) as { exchanged?: unknown; downstream?: unknown; error?: unknown };

await transport.terminateSession();
await client.close();
process.exit(printResult('10', result, {
  exchanged: body.exchanged,
  downstream: profile.isError ? { error: body.error ?? profile.text } : body.downstream,
}));
