/**
 * 02 — client: get a JWT from the local issuer, then call the MCP server with a static bearer.
 * Usage: npm run ex:02:client [-- http://<host>:4102/mcp]      (or MCP_SERVER_URL=…)
 *   DEMO_USER=alice|bob   which demo user to log in as (default alice)
 *   MCP_TOKEN=<jwt>       skip the issuer and present this token verbatim
 *   --expired            ask the issuer for an already-expired token (shows the 401)
 *
 * Like example 01 the client just sets `Authorization: Bearer <token>`; without an authProvider the
 * SDK surfaces a rejected token as StreamableHTTPError(code 401), which we turn into exit code 1.
 */
import { env, publicUrl } from '../../src/shared/env.ts';
import { StreamableHTTPClientTransport, StreamableHTTPError } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { createClient, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';
import { issuerUrl } from './issuer.ts';

/** Returns the bearer token: MCP_TOKEN if set, otherwise one minted by the local issuer. */
async function obtainToken(): Promise<string> {
  const preset = process.env.MCP_TOKEN?.trim();
  if (preset) return preset;
  const user = env('DEMO_USER', 'alice');
  const form = new URLSearchParams({ username: user, password: env('DEMO_PASSWORD', 'password') });
  if (process.argv.includes('--expired')) form.set('ttl', '-60'); // already expired -> server 401
  const res = await fetch(`${issuerUrl()}/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  if (!res.ok) throw new Error(`issuer /token returned HTTP ${res.status} for user ${user}`);
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error('issuer /token response had no access_token');
  return body.access_token;
}

const serverUrl = serverUrlArg(publicUrl(PORT));
const token = await obtainToken();
console.error(`connecting to ${serverUrl} as ${env('DEMO_USER', 'alice')} with a bearer JWT from ${issuerUrl()}`);

const client = createClient('02-jwt-local-client');
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), {
  requestInit: { headers: { Authorization: `Bearer ${token}` } },
});

try {
  await client.connect(transport);
} catch (error) {
  if (error instanceof StreamableHTTPError && error.code === 401) {
    console.error('server rejected the JWT (401): expired, wrong issuer/audience, bad signature or unknown key');
    process.exit(1);
  }
  throw error;
}

const result = await runDemo(client, { expectAdmin: env('DEMO_USER', 'alice') === 'bob' });

await transport.terminateSession();
await client.close();
process.exit(printResult('02', result));
