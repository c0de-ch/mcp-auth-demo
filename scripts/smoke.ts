/**
 * smoke.ts — end-to-end matrix over the REAL ports (design §8.3):
 *
 *   npm run smoke                 every example that exists in examples/
 *   npm run smoke -- 00 04        only these
 *   npm run smoke -- --no-keycloak   skip the Keycloak-backed examples
 *   npm run smoke -- --keep       leave the servers running afterwards
 *
 * For each example: spawn the server process(es) with tsx on their real ports, wait for /healthz,
 * run each client step (a `client.ts` invocation with an env), parse its last `RESULT …` stdout
 * line, compare with the expectation, run the example's headline negative probe, stop everything.
 * Browser logins are delegated to scripts/browser-login.py via MCP_BROWSER_CMD, so no window opens.
 * Prints a pass/fail table, writes test-results/smoke-<timestamp>.json, exits non-zero on failure.
 *
 * The rows below are the contract every example implementer targets (design §8.3). Rows for
 * examples whose directory does not exist yet are reported as "missing" and skipped.
 *
 * NOTE for implementers: "bob → admin ok" through the browser flow requires PRM-driven scope
 * selection (required scopes on the verifier, none on requireBearerAuth) — see the "Scope
 * selection" section of src/shared/README.md. A 401 that pins scope="mcp:tools" makes the SDK
 * client request exactly that and bob never gets mcp:admin.
 */
import { REPO_ROOT, publicHost, publicUrl } from '../src/shared/env.ts';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseResultLine, type ResultLine } from '../src/shared/client/run.ts';
import { initializeSession, isKeycloakUp, spawnExample, wwwAuthenticate, type SpawnedExample } from '../src/shared/testing.ts';

// ---------------------------------------------------------------- expectation table

interface Step {
  name: string;
  /** Client script relative to the repo root (default `<dir>/client.ts`). */
  script?: string;
  env?: Record<string, string>;
  args?: string[];
  /** Expected exit code (default 0). */
  exit?: number;
  /**
   * Assertions on the RESULT line; skipped when `exit` is non-zero. A step without `expect` is
   * checked on its exit code alone and needs no RESULT line (`--logout`, helper scripts).
   */
  expect?: (r: ResultLine) => void;
}

interface Example {
  id: string;
  dir: string;
  keycloak: boolean;
  /** Server processes: script + port whose /healthz must answer (https for 08). */
  servers: Array<{ script: string; port: number; scheme?: 'http' | 'https' }>;
  /** Extra setup before the servers start (e.g. certificates). */
  setup?: () => Promise<void>;
  steps: Step[];
  /** The headline negative probe: raw initialize without credentials → expected status/header shape. */
  negative?: (mcpUrl: string) => Promise<void>;
}

const BROWSER = 'python3 scripts/browser-login.py';
const browser = (user: string) => ({ MCP_BROWSER_CMD: `${BROWSER} --user ${user} --password password` });

const whoamiField = (r: ResultLine, path: string): unknown => path.split('.').reduce<unknown>((o, k) => (o as Record<string, unknown> | undefined)?.[k], r.whoami);
const assertEq = (what: string, got: unknown, want: unknown) => {
  if (JSON.stringify(got) !== JSON.stringify(want)) throw new Error(`${what}: expected ${JSON.stringify(want)}, got ${JSON.stringify(got)}`);
};
const admin = (want: 'ok' | 'denied') => (r: ResultLine) => assertEq('adminOnly', r.adminOnly, want);
const anonymous = (r: ResultLine) => {
  assertEq('whoami', r.whoami, { anonymous: true });
  admin('denied')(r);
};
const user = (name: string, want: 'ok' | 'denied', field = 'extra.username') => (r: ResultLine) => {
  assertEq(`whoami.${field}`, whoamiField(r, field), name);
  admin(want)(r);
};

async function expect401(mcpUrl: string, { resourceMetadata }: { resourceMetadata: boolean }) {
  const { response } = await initializeSession(mcpUrl);
  if (response.status !== 401) throw new Error(`expected 401 without credentials, got ${response.status}`);
  const challenge = wwwAuthenticate(response);
  if (challenge.error !== 'invalid_token') throw new Error(`expected error="invalid_token", got ${response.headers['www-authenticate']}`);
  if (resourceMetadata && !challenge.resource_metadata) throw new Error('expected resource_metadata in WWW-Authenticate');
  if (!resourceMetadata && challenge.resource_metadata) throw new Error('did not expect resource_metadata in WWW-Authenticate');
}

const EXAMPLES: Example[] = [
  {
    id: '00',
    dir: 'examples/00-baseline-no-auth',
    keycloak: false,
    servers: [{ script: 'examples/00-baseline-no-auth/server.ts', port: 4100 }],
    steps: [{ name: 'anonymous client', expect: anonymous }],
    negative: async (mcpUrl) => {
      const { response } = await initializeSession(mcpUrl);
      if (response.status !== 200) throw new Error(`expected 200, got ${response.status}`);
      if (response.headers['www-authenticate']) throw new Error('baseline must not send WWW-Authenticate');
    },
  },
  {
    id: '01',
    dir: 'examples/01-api-key',
    keycloak: false,
    servers: [{ script: 'examples/01-api-key/server.ts', port: 4101 }],
    steps: [
      { name: 'alice key', env: { MCP_API_KEY: 'demo-api-key-alice' }, expect: user('alice', 'denied', 'extra.sub') },
      { name: 'bob key', env: { MCP_API_KEY: 'demo-api-key-bob', EXPECT_ADMIN: 'ok' }, expect: user('bob', 'ok', 'extra.sub') },
      { name: 'unknown key', env: { MCP_API_KEY: 'nope' }, exit: 1 },
    ],
    negative: (url) => expect401(url, { resourceMetadata: false }),
  },
  {
    id: '02',
    dir: 'examples/02-jwt-local',
    keycloak: false,
    servers: [
      { script: 'examples/02-jwt-local/issuer.ts', port: 4192 },
      { script: 'examples/02-jwt-local/server.ts', port: 4102 },
    ],
    steps: [
      { name: 'alice', env: { DEMO_USER: 'alice' }, expect: user('alice', 'denied') },
      { name: 'bob', env: { DEMO_USER: 'bob', EXPECT_ADMIN: 'ok' }, expect: user('bob', 'ok') },
      { name: 'expired token', args: ['--expired'], exit: 1 },
    ],
    negative: (url) => expect401(url, { resourceMetadata: false }),
  },
  {
    id: '03',
    dir: 'examples/03-oauth-embedded-as',
    keycloak: false,
    servers: [{ script: 'examples/03-oauth-embedded-as/server.ts', port: 4103 }],
    steps: [
      { name: 'DCR + browser login (alice)', env: browser('alice'), expect: user('alice', 'denied', 'extra.sub') },
      { name: 'second run (refresh, no browser)', env: { MCP_NO_BROWSER: '1' }, expect: user('alice', 'denied', 'extra.sub') },
      { name: 'logout', args: ['--logout'] },
      { name: 'pre-registered mcp-cli, bob', env: { ...browser('bob'), OAUTH_CLIENT_ID: 'mcp-cli', EXPECT_ADMIN: 'ok' }, expect: user('bob', 'ok', 'extra.sub') },
    ],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '04',
    dir: 'examples/04-keycloak-resource-server',
    keycloak: true,
    servers: [{ script: 'examples/04-keycloak-resource-server/server.ts', port: 4104 }],
    steps: [
      { name: 'DCR + browser login (alice)', env: browser('alice'), expect: user('alice', 'denied') },
      { name: 'second run (refresh, no browser)', env: { MCP_NO_BROWSER: '1' }, expect: user('alice', 'denied') },
      { name: 'pre-registered mcp-cli', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: (r) => { user('alice', 'denied')(r); assertEq('whoami.clientId', whoamiField(r, 'clientId'), 'mcp-cli'); } },
      // Without the logout, bob's run would replay alice's still-valid tokens from the mcp-cli
      // store, never open a browser, and fail EXPECT_ADMIN=ok as the wrong user.
      { name: 'logout (mcp-cli store)', env: { OAUTH_CLIENT_ID: 'mcp-cli' }, args: ['--logout'] },
      { name: 'bob (admin)', env: { ...browser('bob'), OAUTH_CLIENT_ID: 'mcp-cli', EXPECT_ADMIN: 'ok' }, expect: user('bob', 'ok') },
    ],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '05',
    dir: 'examples/05-keycloak-client-credentials',
    keycloak: true,
    servers: [{ script: 'examples/05-keycloak-client-credentials/server.ts', port: 4105 }],
    steps: [{ name: 'client_credentials', env: { EXPECT_ADMIN: 'denied' }, expect: (r) => { assertEq('whoami.clientId', whoamiField(r, 'clientId'), 'mcp-service'); admin('denied')(r); } }],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '06',
    dir: 'examples/06-oauth-proxy-keycloak',
    keycloak: true,
    servers: [{ script: 'examples/06-oauth-proxy-keycloak/server.ts', port: 4106 }],
    steps: [
      { name: 'DCR via facade + browser login (alice)', env: browser('alice'), expect: user('alice', 'denied') },
      { name: 'second run (refresh)', env: { MCP_NO_BROWSER: '1' }, expect: user('alice', 'denied') },
      { name: 'pre-registered mcp-cli', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: user('alice', 'denied') },
    ],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '07',
    dir: 'examples/07-token-introspection',
    keycloak: true,
    servers: [{ script: 'examples/07-token-introspection/server.ts', port: 4107 }],
    steps: [
      { name: 'browser login (alice)', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: user('alice', 'denied') },
      { name: 'revoke alice (admin logout)', script: 'examples/07-token-introspection/revoke.ts', args: ['alice'] },
      // Same OAUTH_CLIENT_ID as the login step: the token store is keyed by client id, and this
      // step exists to replay the REVOKED token from that store.
      { name: 'client again → 401', env: { MCP_NO_BROWSER: '1', OAUTH_CLIENT_ID: 'mcp-cli' }, exit: 1 },
    ],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '08',
    dir: 'examples/08-mtls',
    keycloak: false,
    servers: [{ script: 'examples/08-mtls/server.ts', port: 4108, scheme: 'https' }],
    setup: async () => {
      if (!existsSync(join(REPO_ROOT, 'examples/08-mtls/certs/ca.crt'))) {
        const certs = await spawnExample('scripts/gen-certs.sh', {}, { readyUrl: false });
        if ((await certs.exited) !== 0) throw new Error(`gen-certs failed:\n${certs.stderr()}`);
      }
    },
    steps: [
      { name: 'alice cert', env: { MTLS_CLIENT: 'alice' }, expect: (r) => { assertEq('whoami.clientId', whoamiField(r, 'clientId'), 'alice'); admin('denied')(r); } },
      { name: 'bob cert', env: { MTLS_CLIENT: 'bob', EXPECT_ADMIN: 'ok' }, expect: (r) => { assertEq('whoami.clientId', whoamiField(r, 'clientId'), 'bob'); admin('ok')(r); } },
      { name: 'no cert', env: { MTLS_CLIENT: 'none' }, exit: 1 },
    ],
  },
  {
    id: '09',
    dir: 'examples/09-auth-gateway',
    keycloak: true,
    servers: [{ script: 'examples/09-auth-gateway/all.ts', port: 4109 }],
    steps: [{ name: 'browser login via gateway (alice)', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: (r) => { assertEq('whoami.extra.via', whoamiField(r, 'extra.via'), 'gateway'); admin('denied')(r); } }],
    negative: async (url) => {
      await expect401(url, { resourceMetadata: true });
      const internal = await initializeSession(publicUrl(4119), { 'x-forwarded-user': 'bob' });
      if (internal.response.status !== 401) throw new Error(`internal server without assertion: expected 401, got ${internal.response.status}`);
    },
  },
  {
    id: '10',
    dir: 'examples/10-token-exchange-downstream',
    keycloak: true,
    servers: [{ script: 'examples/10-token-exchange-downstream/all.ts', port: 4110 }],
    steps: [{ name: 'browser login (alice) + downstream call', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: (r) => { user('alice', 'denied')(r); assertEq('extra.downstream.azp', (r.extra?.downstream as Record<string, unknown> | undefined)?.azp, 'mcp-server'); } }],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
  {
    id: '11',
    dir: 'examples/11-python-mcp-keycloak',
    keycloak: true,
    servers: [{ script: 'examples/11-python-mcp-keycloak/server.py', port: 4111 }],
    steps: [{ name: 'TS client, browser login (alice)', env: { ...browser('alice'), OAUTH_CLIENT_ID: 'mcp-cli' }, expect: (r) => { admin('denied')(r); if (whoamiField(r, 'subject') === undefined && whoamiField(r, 'username') === undefined && whoamiField(r, 'extra.username') === undefined) throw new Error('whoami lacks subject/username'); } }],
    negative: (url) => expect401(url, { resourceMetadata: true }),
  },
];

// ---------------------------------------------------------------- runner

interface Row {
  example: string;
  step: string;
  status: 'pass' | 'fail' | 'skip' | 'missing';
  detail: string;
  ms: number;
}

const argv = process.argv.slice(2);
const keep = argv.includes('--keep');
const noKeycloak = argv.includes('--no-keycloak');
const selected = argv.filter((a) => /^\d\d$/.test(a));

if (publicHost() === 'localhost') {
  console.error('PUBLIC_HOST=localhost is not usable on a LAN — set it to this machine\'s address in .env');
  process.exit(2);
}
console.error(`smoke: PUBLIC_HOST=${publicHost()}  examples=${selected.length ? selected.join(',') : 'all'}  keycloak=${noKeycloak ? 'skipped' : 'required for 04-07,09-11'}`);

const keycloakUp = noKeycloak ? false : await isKeycloakUp();
const rows: Row[] = [];
const timed = async (example: string, step: string, fn: () => Promise<string | void>) => {
  const started = Date.now();
  try {
    const detail = (await fn()) ?? '';
    rows.push({ example, step, status: 'pass', detail, ms: Date.now() - started });
    return true;
  } catch (error) {
    rows.push({ example, step, status: 'fail', detail: (error as Error).message.split('\n')[0].slice(0, 200), ms: Date.now() - started });
    return false;
  }
};

async function runClient(example: Example, step: Step, storeDir: string) {
  const script = step.script ?? `${example.dir}/client.ts`;
  const env: Record<string, string> = { MCP_RATE_LIMIT: '0', MCP_AUTH_STORE_DIR: storeDir, MCP_LOG: '0', ...step.env };
  delete env.EXPECT_ADMIN;
  if (step.env?.EXPECT_ADMIN) env.EXPECT_ADMIN = step.env.EXPECT_ADMIN;
  const child = await spawnExample(script, env, { readyUrl: false, args: step.args ?? [] });
  const timer = setTimeout(() => void child.stop(), 120_000);
  const code = await child.exited;
  clearTimeout(timer);
  const wantExit = step.exit ?? 0;
  if (code !== wantExit) throw new Error(`exit ${code}, expected ${wantExit}: ${child.stderr().trim().split('\n').at(-1) ?? ''}`);
  if (wantExit !== 0) return `exit ${code} as expected`;
  const result = parseResultLine(child.stdout());
  // Only steps that assert on the RESULT line require one. Steps such as `--logout`, or a helper
  // script like 07's revoke.ts, do real work without ever connecting to an MCP server, so demanding
  // a RESULT line from them would force the step to fabricate one and corrupt the output contract.
  if (step.expect) {
    if (!result) throw new Error(`no RESULT line on stdout:\n${child.stdout().slice(-500)}`);
    step.expect(result);
  }
  return result ? `adminOnly=${result.adminOnly}` : `exit ${code}`;
}

for (const example of EXAMPLES) {
  if (selected.length && !selected.includes(example.id)) continue;
  if (!existsSync(join(REPO_ROOT, example.dir))) {
    rows.push({ example: example.id, step: '-', status: 'missing', detail: `${example.dir} does not exist yet`, ms: 0 });
    continue;
  }
  if (example.keycloak && !keycloakUp) {
    rows.push({ example: example.id, step: '-', status: 'skip', detail: 'Keycloak not available', ms: 0 });
    continue;
  }
  const storeDir = mkdtempSync(join(tmpdir(), `mcp-auth-smoke-${example.id}-`)); // fresh tokens/DCR per example
  const servers: SpawnedExample[] = [];
  try {
    if (example.setup) await example.setup();
    const up = await timed(example.id, 'start servers', async () => {
      for (const s of example.servers) {
        const readyUrl = `${s.scheme ?? 'http'}://${publicHost()}:${s.port}/healthz`;
        servers.push(await spawnExample(s.script, { MCP_RATE_LIMIT: '0' }, { readyUrl: s.scheme === 'https' ? false : readyUrl, timeoutMs: 40_000 }));
        if (s.scheme === 'https') await new Promise((r) => setTimeout(r, 1500)); // /healthz needs a client cert; give it a moment
      }
      return example.servers.map((s) => `${s.scheme ?? 'http'}://${publicHost()}:${s.port}`).join(' ');
    });
    if (!up) continue;
    for (const step of example.steps) {
      await timed(example.id, step.name, () => runClient(example, step, storeDir));
    }
    if (example.negative) {
      const main = example.servers.at(-1)!;
      await timed(example.id, 'negative probe', () => example.negative!(`${main.scheme ?? 'http'}://${publicHost()}:${main.port}/mcp`));
    }
  } finally {
    if (!keep) {
      for (const s of servers) await s.stop();
      rmSync(storeDir, { recursive: true, force: true });
    } else {
      console.error(`--keep: servers of ${example.id} left running (pids ${servers.map((s) => s.child.pid).join(', ')}), store ${storeDir}`);
    }
  }
}

// ---------------------------------------------------------------- report

const width = { example: 7, step: 40, status: 7, ms: 8 };
const pad = (s: string, n: number) => s.padEnd(n).slice(0, n);
console.log(`\n${pad('example', width.example)} ${pad('step', width.step)} ${pad('status', width.status)} ${pad('ms', width.ms)} detail`);
for (const r of rows) console.log(`${pad(r.example, width.example)} ${pad(r.step, width.step)} ${pad(r.status, width.status)} ${pad(String(r.ms), width.ms)} ${r.detail}`);

const outDir = join(REPO_ROOT, 'test-results');
mkdirSync(outDir, { recursive: true });
const outFile = join(outDir, `smoke-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
writeFileSync(outFile, JSON.stringify({ publicHost: publicHost(), keycloakUp, rows }, null, 2));
const failed = rows.filter((r) => r.status === 'fail').length;
console.log(`\n${rows.filter((r) => r.status === 'pass').length} passed, ${failed} failed, ${rows.filter((r) => r.status === 'skip').length} skipped, ${rows.filter((r) => r.status === 'missing').length} missing → ${outFile}`);
process.exit(failed ? 1 : 0);
