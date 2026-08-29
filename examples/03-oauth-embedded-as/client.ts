/**
 * 03 — client: the full OAuth 2.1 dance against the embedded AS, driven by the SDK.
 *
 * First run: 401 → PRM → AS metadata → Dynamic Client Registration → browser login + consent →
 * code on the loopback listener → PKCE token exchange → connected. Later runs reuse the stored
 * tokens (refreshing on 401) and open no browser. OAUTH_CLIENT_ID=mcp-cli skips DCR; --logout
 * wipes the store (do that after a server restart — its memory is gone, your store is not).
 * Usage: npm run ex:03:client [-- http://<host>:4103/mcp | --logout]
 */
import { port, publicUrl } from '../../src/shared/env.ts';
import { CliOAuthProvider, connectWithOAuth, handleLogoutFlag } from '../../src/shared/client/oauth-cli.ts';
import { printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';

const serverUrl = serverUrlArg(publicUrl(port('PORT_03', 4103)));
const provider = new CliOAuthProvider({ serverUrl, scope: 'mcp:tools' }); // fallback scope only — the PRM's list wins (SEP-835)
if (handleLogoutFlag(provider)) process.exit(0);

const known = provider.clientInformation();
console.error(`connecting to ${serverUrl} (${known ? `client ${known.client_id}` : 'dynamic client registration'})`);

const { client, transport } = await connectWithOAuth({ serverUrl, provider, clientName: '03-oauth-embedded-as-client' });
const result = await runDemo(client, { expectAdmin: process.env.EXPECT_ADMIN ? process.env.EXPECT_ADMIN === 'ok' : undefined });

await transport.terminateSession();
await client.close();
process.exit(printResult('03', result, { clientId: provider.clientInformation()?.client_id }));
