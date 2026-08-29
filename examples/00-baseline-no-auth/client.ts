/**
 * 00 — baseline client: connect without credentials and run the shared demo.
 * Usage: npm run ex:00:client [-- http://<host>:4100/mcp]     (or MCP_SERVER_URL=…)
 */
import { publicUrl } from '../../src/shared/env.ts';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createClient, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const serverUrl = serverUrlArg(publicUrl(PORT));
console.error(`connecting to ${serverUrl} (no credentials)`);

const client = createClient('00-baseline-client');
const transport = new StreamableHTTPClientTransport(new URL(serverUrl));
await client.connect(transport);

const result = await runDemo(client, { expectAdmin: false });

await transport.terminateSession();
await client.close();
process.exit(printResult('00', result));
