/**
 * 08 — mTLS client: presents a client certificate in the TLS handshake; sends NO tokens.
 * Usage: MTLS_CLIENT=alice|bob|expired-alice|rogue-client|none npm run ex:08:client [-- https://<host>:4108/mcp]
 * The SDK transport's fetch is undici's, wired to an Agent carrying ca + cert + key (tls.ts).
 */
import { env, publicUrl } from '../../src/shared/env.ts';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createClient, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { mtlsFetch } from './tls.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT, '/mcp', 'https'));
const who = env('MTLS_CLIENT', 'alice');
console.error(`connecting to ${serverUrl} presenting client certificate "${who}"`);

const client = createClient('08-mtls-client');
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
  fetch: mtlsFetch(serverUrl, { client: who }),
});
await client.connect(transport); // MTLS_CLIENT=none/expired-alice/rogue-client dies right here, in the handshake

const result = await runDemo(client, { expectAdmin: who === 'bob' });

await transport.terminateSession();
await client.close();
process.exit(printResult('08', result, { client: who }));
