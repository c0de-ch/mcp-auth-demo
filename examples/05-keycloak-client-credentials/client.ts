/**
 * 05 — machine-to-machine client: no browser, no redirect, no user. The SDK's non-interactive
 * providers (redirectUrl = undefined) make auth() fetch a token straight from Keycloak's token
 * endpoint with grant_type=client_credentials; discovery still runs 401 → PRM → AS metadata.
 * Usage: npm run ex:05:client [-- http://<host>:4105/mcp] [--auth private-key-jwt]
 *   default                  client_secret_basic — client mcp-service + MCP_SERVICE_CLIENT_SECRET
 *   --auth private-key-jwt   RFC 7523 signed client assertion — client mcp-service-jwt +
 *                            keycloak/.generated/mcp-service-jwt.key (npm run kc:keys)
 */
import { REPO_ROOT, env, publicUrl } from '../../src/shared/env.ts';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { ClientCredentialsProvider, PrivateKeyJwtProvider } from '@modelcontextprotocol/sdk/client/auth-extensions.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { KC } from '../../src/shared/keycloak.ts';
import { callTool, createClient, printResult, runDemo, serverUrlArg } from '../../src/shared/client/run.ts';
import { PORT } from './server.ts';

const argv = process.argv.slice(2);
const flagAt = argv.indexOf('--auth');
const method = flagAt >= 0 ? argv.splice(flagAt, 2)[1] : (argv.find((a) => a.startsWith('--auth='))?.slice('--auth='.length) ?? 'client-secret-basic');
if (method !== 'client-secret-basic' && method !== 'private-key-jwt') {
  console.error(`unknown --auth method "${method}" (use client-secret-basic or private-key-jwt)`);
  process.exit(1);
}
const serverUrl = serverUrlArg(publicUrl(PORT), argv);

const provider =
  method === 'private-key-jwt'
    ? new PrivateKeyJwtProvider({
        clientId: KC.clients.serviceJwt,
        privateKey: readFileSync(resolve(REPO_ROOT, 'keycloak/.generated/mcp-service-jwt.key'), 'utf8'),
        algorithm: 'RS256',
        jwtLifetimeSeconds: 60,
        scope: KC.scopes.tools,
      })
    : new ClientCredentialsProvider({ clientId: KC.clients.service, clientSecret: env('MCP_SERVICE_CLIENT_SECRET'), scope: KC.scopes.tools });

console.error(`connecting to ${serverUrl} as ${provider.clientInformation().client_id} (client_credentials, ${method})`);
// Eager grant: token-endpoint failures (wrong secret, bad assertion) surface here, before connect().
await auth(provider, { serverUrl });

const client = createClient('05-keycloak-client-credentials-client');
const transport = new StreamableHTTPClientTransport(new URL(serverUrl), { authProvider: provider });
await client.connect(transport);

const result = await runDemo(client, { expectAdmin: false }); // service account: role mcp-user only
const serviceOnly = await callTool(client, 'service_only');
console.log(`service_only -> ${serviceOnly.isError ? `ERROR ${serviceOnly.text}` : serviceOnly.text}`);

await transport.terminateSession();
await client.close();
process.exit(printResult('05', result, { auth: method, serviceOnly: serviceOnly.isError ? 'denied' : 'ok' }));
