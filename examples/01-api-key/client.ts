/**
 * 01 — API-key client: the key rides along as a static `Authorization: Bearer <key>` header on
 * every request (SDK recipe: requestInit headers, no authProvider). Nothing is discovered and no
 * browser opens — the key IS the whole credential story.
 * Usage: MCP_API_KEY=demo-api-key-bob npm run ex:01:client [-- http://<host>:4101/mcp]
 */
import { env, publicUrl } from '../../src/shared/env.ts';
import { createHash } from 'node:crypto';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createClient, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
const apiKey = env('MCP_API_KEY'); // no default on purpose: the client must be given its credential
// Never log the key itself; a truncated hash is enough to tell keys apart (design §4.6).
console.error(`connecting to ${serverUrl} (API key sha256:${createHash('sha256').update(apiKey).digest('hex').slice(0, 8)})`);

const client = createClient('01-api-key-client');
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
  requestInit: { headers: { Authorization: `Bearer ${apiKey}` } },
});

try {
  await client.connect(transport);
} catch (error) {
  // Without an authProvider the SDK does not start OAuth discovery on a 401 — it throws a plain
  // StreamableHTTPError (not UnauthorizedError). Turn that into a readable message and exit 1.
  if (error instanceof StreamableHTTPError && error.code === 401) {
    console.error("API key rejected (401): check MCP_API_KEY against the server's MCP_API_KEYS table");
    process.exit(1);
  }
  throw error;
}

const result = await runDemo(client);

await transport.terminateSession();
await client.close();
process.exit(printResult('01', result));
