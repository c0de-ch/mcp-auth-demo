/**
 * 02 — mint.ts: prints a single JWT to stdout for the docs' "break it" section.
 *
 *   npm run ex:02:mint -- --sub alice [--scope "mcp:tools mcp:admin"] [--ttl 300] [--nbf 120]
 *                         [--aud http://…] [--iss http://…] [--kid other] [--alg RS256|none|HS256]
 *                         [--tamper]
 *
 * The happy path reuses the issuer's own signing routine (issuer.ts `mintToken`). The attack
 * variants (`--alg none`, `--alg HS256`, `--tamper`, unknown `--kid`, future `--nbf`, wrong
 * `--aud`/`--iss`, negative `--ttl`) are produced here with a SEPARATE routine so the issuer's key
 * handling stays clean and honest. Every one of these is rejected by server.ts — see server.test.ts.
 *
 * Only the token is written to stdout (so `TOKEN=$(npm run -s ex:02:mint -- …)` works); everything
 * else goes to stderr.
 */
import { isMain } from '../../src/shared/env.ts';
import { exportSPKI, importJWK, SignJWT, type CryptoKey } from 'jose';
import { audienceUrl, issuerUrl, loadIssuerKeys, mintToken } from './issuer.ts';

/** Minimal `--flag value` / `--flag` parser. */
function parseArgs(argv: string[]): Record<string, string | boolean> {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    if (!argv[i].startsWith('--')) continue;
    const key = argv[i].slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith('--')) out[key] = true;
    else out[key] = next, i++;
  }
  return out;
}

const b64url = (value: unknown): string => Buffer.from(JSON.stringify(value)).toString('base64url');

async function mint(args: Record<string, string | boolean>): Promise<{ token: string; note: string }> {
  const sub = typeof args.sub === 'string' ? args.sub : 'alice';
  const scope = typeof args.scope === 'string' ? args.scope : 'mcp:tools';
  const ttlSec = typeof args.ttl === 'string' ? Number.parseInt(args.ttl, 10) : 300;
  const issuer = typeof args.iss === 'string' ? args.iss : issuerUrl();
  const audience = typeof args.aud === 'string' ? args.aud : audienceUrl();
  const alg = typeof args.alg === 'string' ? args.alg : 'RS256';
  const keys = await loadIssuerKeys();
  const kid = typeof args.kid === 'string' ? args.kid : keys.kid;
  const now = Math.floor(Date.now() / 1000);

  // --- attack variants: a separate, deliberately-wrong signing routine ---
  if (alg === 'none') {
    // Unsigned "alg: none" token. jose refuses it before any signature check.
    const header = b64url({ alg: 'none', kid });
    const payload = b64url({ iss: issuer, aud: audience, sub, scope, iat: now, exp: now + Math.max(ttlSec, 1), typ: 'Bearer' });
    return { token: `${header}.${payload}.`, note: 'alg:none (unsigned)' };
  }
  if (alg === 'HS256') {
    // Algorithm-confusion: sign HS256 using the PUBLIC key bytes as the HMAC secret. jose selects
    // the RS256 verification key from the JWKS by kid and rejects the symmetric alg outright.
    const pem = await exportSPKI((await importJWK(keys.publicJwk, 'RS256')) as CryptoKey);
    const token = await new SignJWT({ scope, preferred_username: sub, typ: 'Bearer' })
      .setProtectedHeader({ alg: 'HS256', kid })
      .setIssuer(issuer).setAudience(audience).setSubject(sub)
      .setIssuedAt(now).setExpirationTime(now + Math.max(ttlSec, 1))
      .sign(new TextEncoder().encode(pem));
    return { token, note: 'HS256 signed with the public key (algorithm confusion)' };
  }

  // --- valid-shape RS256 token, possibly with a wrong claim/kid/nbf ---
  const notes: string[] = [];
  let token: string;
  const custom = typeof args.kid === 'string' || typeof args.nbf === 'string' || typeof args.iss === 'string' || typeof args.aud === 'string' || ttlSec !== 300;
  if (custom) {
    // Sign with the real private key but arbitrary header/claims (unknown kid, future nbf, …).
    const key = await importJWK(keys.privateJwk, 'RS256');
    let builder = new SignJWT({ scope, preferred_username: sub, realm_access: { roles: ['mcp-user'] }, typ: 'Bearer' })
      .setProtectedHeader({ alg: 'RS256', kid })
      .setIssuer(issuer).setAudience(audience).setSubject(sub)
      .setIssuedAt(now).setExpirationTime(now + ttlSec);
    if (typeof args.nbf === 'string') { builder = builder.setNotBefore(now + Number.parseInt(args.nbf, 10)); notes.push(`nbf=+${args.nbf}s`); }
    if (kid !== keys.kid) notes.push(`kid=${kid}`);
    if (issuer !== issuerUrl()) notes.push('wrong iss');
    if (audience !== audienceUrl()) notes.push('wrong aud');
    if (ttlSec <= 0) notes.push(`expired (ttl=${ttlSec}s)`);
    token = await builder.sign(key);
  } else {
    token = await mintToken({ sub, scope, ttlSec, keys });
  }

  if (args.tamper) {
    // Flip one claim in the payload while keeping the signature -> signature no longer matches.
    const [h, p, s] = token.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString('utf8')) as Record<string, unknown>;
    claims.scope = 'mcp:tools mcp:admin'; // privilege escalation attempt
    token = `${h}.${b64url(claims)}.${s}`;
    notes.push('tampered payload');
  }

  return { token, note: notes.length ? notes.join(', ') : 'valid' };
}

if (isMain(import.meta)) {
  const { token, note } = await mint(parseArgs(process.argv.slice(2)));
  console.error(`[02-jwt-local mint] ${note}`);
  console.log(token);
}
