/**
 * Repository conventions that silently break things when violated (design §4.2, §4.4, §4.6).
 * Pure file inspection — no server is started.
 */
import '../src/shared/env.ts'; // always first (see src/shared/README.md: import-order rule)
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { REPO_ROOT } from '../src/shared/env.ts';

/** All *.ts files below `dir` (recursively), repo-relative, excluding node_modules/certs. */
function tsFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const name of readdirSync(d)) {
      if (name === 'node_modules' || name.startsWith('.')) continue;
      const full = join(d, name);
      if (statSync(full).isDirectory()) walk(full);
      else if (name.endsWith('.ts')) out.push(relative(REPO_ROOT, full));
    }
  };
  try {
    walk(join(REPO_ROOT, dir));
  } catch {
    /* directory may not exist yet */
  }
  return out.sort();
}

const read = (file: string) => readFileSync(join(REPO_ROOT, file), 'utf8');

/** The first `import` statement of a module (comments skipped). */
function firstImport(source: string): string | undefined {
  const withoutComments = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  return withoutComments.match(/^\s*import\b[^;]*;/m)?.[0].trim();
}

const exampleEntrypoints = tsFiles('examples').filter((f) => !f.includes('/certs/'));
const scriptEntrypoints = tsFiles('scripts');
const sharedModules = tsFiles('src/shared').filter((f) => f !== 'src/shared/env.ts');

describe('import-order rule: src/shared/env.ts is the first import', () => {
  // env.ts loads .env and sets MCP_DANGEROUSLY_ALLOW_INSECURE_ISSUER_URL BEFORE the SDK's
  // server/auth/router.js is evaluated (it reads the flag once at module load).
  it.each([...exampleEntrypoints, ...scriptEntrypoints, ...sharedModules, ...tsFiles('tests')])('%s', (file) => {
    const first = firstImport(read(file));
    expect(first, `${file} has no import`).toBeDefined();
    expect(first, `${file}: first import must be src/shared/env.ts, got: ${first}`).toMatch(/from\s+['"](\.\.?\/)+(src\/shared\/)?env\.ts['"]|import\s+['"](\.\.?\/)+(src\/shared\/)?env\.ts['"]/);
  });
});

describe('client output contract', () => {
  const clients = exampleEntrypoints.filter((f) => /^examples\/[^/]+\/client\.ts$/.test(f));
  it.each(clients)('%s prints the RESULT line via printResult()', (file) => {
    expect(read(file)).toMatch(/\bprintResult\(/);
  });
});

describe('no localhost in server-side URLs', () => {
  // The demo is used from other LAN machines; every advertised URL comes from PUBLIC_HOST.
  // Allowed: the loopback constants of the Host allow-list / redirect-host checks / bind addresses.
  const serverFiles = [...sharedModules.filter((f) => !f.endsWith('.test.ts')), ...exampleEntrypoints.filter((f) => /\/(server|gateway|issuer|downstream|all)[^/]*\.ts$/.test(f) && !f.endsWith('.test.ts'))];
  it.each(serverFiles)('%s', (file) => {
    const offending = read(file)
      .split('\n')
      .filter((line) => /https?:\/\/localhost/.test(line.replace(/\/\/.*$/, ''))) // code, not comments
      .filter((line) => !/loopback-ok/.test(line)); // explicit opt-out marker, e.g. a URL-parse base
    expect(offending, `${file} builds a URL from localhost:\n${offending.join('\n')}`).toEqual([]);
  });
});

describe('verifier error messages are static', () => {
  // bearerAuth.js copies the message unescaped into WWW-Authenticate: no request-derived text
  // unless it went through headerSafe().
  const verifierFiles = [...sharedModules, ...exampleEntrypoints].filter((f) => !f.endsWith('.test.ts'));
  it.each(verifierFiles)('%s', (file) => {
    const source = read(file);
    const dynamic = [...source.matchAll(/new (?:InvalidTokenError|InsufficientScopeError)\(\s*`([^`]*)`/g)]
      .map((m) => m[1])
      .filter((template) => template.includes('${') && !template.includes('headerSafe('));
    expect(dynamic, `${file}: template literal without headerSafe() in a bearer error`).toEqual([]);
  });
});

describe('package.json scripts', () => {
  it('has server/client scripts for every example directory', () => {
    const scripts = (JSON.parse(read('package.json')) as { scripts: Record<string, string> }).scripts;
    for (const dir of readdirSync(join(REPO_ROOT, 'examples'))) {
      const nn = dir.slice(0, 2);
      expect(scripts[`ex:${nn}:server`], `ex:${nn}:server`).toBeDefined();
      expect(scripts[`ex:${nn}:client`], `ex:${nn}:client`).toBeDefined();
    }
  });
});
