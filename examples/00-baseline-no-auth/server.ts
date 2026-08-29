/**
 * 00 — baseline: a Streamable HTTP MCP server with NO authentication.
 * Every other example is this file plus an auth middleware in mountMcp({ auth }).
 */
import { isMain, port } from '../../src/shared/env.ts';
import { createApp, listen, mountMcp } from '../../src/shared/http.ts';
import { createDemoServer } from '../../src/shared/tools.ts';

export const PORT = port('PORT_00', port('MCP_PORT', 4100));

/** Builds the Express app; exported so the test can run it on an ephemeral port. */
export function buildApp() {
  const app = createApp();
  mountMcp(app, {
    createServer: () => createDemoServer({ name: '00-baseline-no-auth' }),
    // auth: <none> — whoami reports { anonymous: true } and admin_only is always rejected.
  });
  return app;
}

if (isMain(import.meta)) {
  await listen(buildApp(), { port: PORT, name: '00-baseline-no-auth' });
}
