/**
 * 07 — revoke: end every Keycloak session of a user (admin REST API), then wait one cache window.
 *
 *   npm run ex:07:revoke -- alice [--no-wait]
 *
 * After this, Keycloak answers `active: false` for all of the user's access AND refresh tokens.
 * The introspection server (07) therefore rejects them on the next uncached request — while a
 * JWKS-validating server (04) keeps accepting the already-issued access tokens until `exp`.
 * The wait covers the 07 server's positive-cache window (INTROSPECTION_TTL_SECONDS, default 10 s),
 * so the very next client run is guaranteed to see the 401. Uses the DEMO admin credentials
 * (KC_ADMIN_USER / KC_ADMIN_PASSWORD from .env).
 */
import { env } from '../../src/shared/env.ts';
import { adminLogoutUser } from '../../src/shared/keycloak.ts';

const args = process.argv.slice(2);
const username = args.find((a) => !a.startsWith('--')) ?? 'alice';
const ttl = Number(env('INTROSPECTION_TTL_SECONDS', '10'));

await adminLogoutUser(username);
console.log(`Keycloak: ended every session of ${username} (admin REST).`);
console.log('Introspection now answers active:false for their tokens; JWT signatures stay valid until exp.');

let waitedSeconds = 0;
if (!args.includes('--no-wait') && ttl > 0) {
  waitedSeconds = ttl + 1;
  console.log(`waiting ${waitedSeconds}s: the 07 server may trust a cached verdict for up to INTROSPECTION_TTL_SECONDS=${ttl}s…`);
  await new Promise((resolve) => setTimeout(resolve, waitedSeconds * 1000));
}
// scripts/smoke.ts expects a RESULT line from every step that exits 0 (see README integration notes).
console.log(`RESULT ${JSON.stringify({ example: '07', revoked: username, waitedSeconds })}`);
