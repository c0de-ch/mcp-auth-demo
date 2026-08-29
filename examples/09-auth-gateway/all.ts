/**
 * 09 — run the gateway and the internal server together in one process (`npm run ex:09:all`).
 *
 * Convenience for the demo and for smoke: normally the two are separate deployments (that is the
 * whole point — a trust boundary between processes/hosts). The internal server starts first so the
 * gateway always has a backend to proxy to. Split them with `ex:09:server` + `ex:09:gateway`.
 */
import { isMain } from '../../src/shared/env.ts';
import { listen } from '../../src/shared/http.ts';
import { PORT as GATEWAY_PORT, buildGatewayApp } from './gateway.ts';
import { PORT as INTERNAL_PORT, buildInternalApp, internalBindHost, trustModeFromEnv } from './server.ts';

if (isMain(import.meta)) {
  const mode = trustModeFromEnv();
  await listen(buildInternalApp({ mode }), { port: INTERNAL_PORT, name: '09-internal', host: internalBindHost(mode) });
  await listen(await buildGatewayApp(), { port: GATEWAY_PORT, name: '09-gateway' });
  console.error(`[09-all] gateway (public) + internal server up in one process; trust mode: ${mode}. Point the client at the gateway.`);
}
