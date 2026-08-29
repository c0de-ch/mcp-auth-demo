/**
 * tools.ts — the three demo tools every example server exposes.
 *
 *   whoami      → echoes the caller's AuthInfo (or { anonymous: true })
 *   add         → { a, b } → a + b   (sanity check that the session works)
 *   admin_only  → succeeds only when the caller holds the `mcp:admin` scope
 *
 * CONTRACT — "effective scopes":
 *   Tools look at ONE thing: `extra.authInfo.scopes`. They never inspect roles, claims,
 *   client ids or headers. It is the VERIFIER's job (jwt.ts, an API-key store, an
 *   introspection call, …) to compute the effective scope list — e.g. keycloakEffectiveScopes()
 *   keeps `mcp:admin` only when the user also has the `mcp-admin` realm role. Keeping the policy
 *   in the verifier means every example can swap its auth mechanism without touching the tools.
 */
import './env.ts';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';

export const SCOPE_TOOLS = 'mcp:tools';
export const SCOPE_ADMIN = 'mcp:admin';

/** True when `authInfo` carries `scope`. Missing authInfo (unauthenticated server) → false. */
export function requireScope(authInfo: AuthInfo | undefined, scope: string): boolean {
  return authInfo?.scopes.includes(scope) ?? false;
}

/** Plain-JSON view of an AuthInfo for whoami (the raw token is deliberately omitted). */
export function formatAuthInfo(authInfo: AuthInfo | undefined): Record<string, unknown> {
  if (!authInfo) return { anonymous: true };
  return {
    clientId: authInfo.clientId,
    scopes: authInfo.scopes,
    expiresAt: authInfo.expiresAt,
    expiresAtIso: authInfo.expiresAt ? new Date(authInfo.expiresAt * 1000).toISOString() : undefined,
    resource: authInfo.resource?.href,
    extra: authInfo.extra,
  };
}

const text = (value: unknown): CallToolResult => ({
  content: [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }],
});

const toolError = (message: string): CallToolResult => ({ isError: true, content: [{ type: 'text', text: message }] });

export interface DemoServerOptions {
  name: string;
  version?: string;
}

/** A McpServer with the three shared demo tools registered. One instance per session. */
export function createDemoServer({ name, version = '0.1.0' }: DemoServerOptions): McpServer {
  const server = new McpServer({ name, version });

  server.registerTool(
    'whoami',
    { title: 'Who am I', description: 'Returns the identity the server derived from your credentials.' },
    async (extra) => text(formatAuthInfo(extra.authInfo)),
  );

  server.registerTool(
    'add',
    { title: 'Add', description: 'Adds two numbers.', inputSchema: { a: z.number(), b: z.number() } },
    async ({ a, b }) => text(String(a + b)),
  );

  server.registerTool(
    'admin_only',
    { title: 'Admin only', description: `Succeeds only for callers holding the ${SCOPE_ADMIN} scope.` },
    async (extra) =>
      requireScope(extra.authInfo, SCOPE_ADMIN)
        ? text(`admin ok: ${extra.authInfo?.clientId} has ${SCOPE_ADMIN}`)
        : toolError(`insufficient_scope: admin_only requires scope ${SCOPE_ADMIN}`),
  );

  return server;
}
