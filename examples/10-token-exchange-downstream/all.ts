/**
 * 10 — both processes in one terminal: the downstream API (4190) and the MCP server (4110).
 * `npm run ex:10:all` is what `scripts/smoke.ts` starts; use `ex:10:downstream` + `ex:10:server`
 * for two separate terminals. `DEMO_PASSTHROUGH=1` additionally registers the anti-pattern tool.
 */
import '../../src/shared/env.ts';
import { listen } from '../../src/shared/http.ts';
import { buildDownstreamApp, DOWNSTREAM_PORT } from './downstream.ts';
import { buildApp, PORT } from './server.ts';

// Downstream first: the MCP server dials it as soon as a client calls downstream_profile.
await listen(await buildDownstreamApp(), { port: DOWNSTREAM_PORT, name: '10-downstream-api', path: '/me' });
await listen(await buildApp(), { port: PORT, name: '10-token-exchange-downstream' });
