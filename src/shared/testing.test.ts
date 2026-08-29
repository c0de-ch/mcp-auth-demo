/** The test helpers themselves: local JWT minting, challenge parsing, RESULT lines, spawnExample. */
import './env.ts'; // always first (see README: import-order rule)
import { describe, expect, it } from 'vitest';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import { createJwtVerifier } from './jwt.ts';
import { parseResultLine, printResult, serverUrlArg } from './client/run.ts';
import { decodeJwtPayload, expectOAuth401, freePort, mintLocalJwt, spawnExample, testKeyPair, wwwAuthenticate, type RawResponse } from './testing.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp';

describe('testKeyPair + mintLocalJwt', () => {
  it('mints tokens a createJwtVerifier() accepts, for RS256 and ES256', async () => {
    for (const alg of ['RS256', 'ES256'] as const) {
      const keys = await testKeyPair(alg);
      const token = await mintLocalJwt({ key: keys.privateKey, kid: keys.kid, alg, issuer: ISSUER, audience: 'mcp-server', sub: 'alice', scope: 'mcp:tools mcp:admin', roles: ['mcp-user', 'mcp-admin'] });
      const info = await createJwtVerifier({ issuer: ISSUER, audience: 'mcp-server', jwks: keys.jwks }).verifyAccessToken(token);
      expect(info.scopes).toEqual(['mcp:tools', 'mcp:admin']);
      expect(info.extra).toMatchObject({ sub: 'alice', username: 'alice', roles: ['mcp-user', 'mcp-admin'] });
      expect(decodeJwtPayload(token)).toMatchObject({ iss: ISSUER, aud: 'mcp-server', azp: 'mcp-cli' });
    }
  });

  it('supports negative variants (expired, other key)', async () => {
    const keys = await testKeyPair();
    const other = await testKeyPair('RS256', 'other');
    const verifier = createJwtVerifier({ issuer: ISSUER, audience: 'mcp-server', jwks: keys.jwks });
    await expect(verifier.verifyAccessToken(await mintLocalJwt({ key: keys.privateKey, issuer: ISSUER, audience: 'mcp-server', expiresIn: '-1m' }))).rejects.toThrow(InvalidTokenError);
    await expect(verifier.verifyAccessToken(await mintLocalJwt({ key: other.privateKey, kid: other.kid, issuer: ISSUER, audience: 'mcp-server' }))).rejects.toThrow(InvalidTokenError);
  });
});

describe('wwwAuthenticate / expectOAuth401', () => {
  const raw = (status: number, header?: string): RawResponse => ({
    status,
    headers: header ? { 'www-authenticate': header } : {},
    text: '',
    json: () => ({}) as never,
    messages: () => [],
  });

  it('parses the Bearer challenge parameters', () => {
    expect(wwwAuthenticate(raw(401, 'Bearer error="invalid_token", error_description="JWT rejected: token expired", scope="mcp:tools", resource_metadata="http://h/.well-known/oauth-protected-resource/mcp"'))).toEqual({
      scheme: 'Bearer',
      error: 'invalid_token',
      error_description: 'JWT rejected: token expired',
      scope: 'mcp:tools',
      resource_metadata: 'http://h/.well-known/oauth-protected-resource/mcp',
    });
    expect(wwwAuthenticate(new Response(null, { status: 401, headers: { 'www-authenticate': 'Bearer error="invalid_token"' } }))).toMatchObject({ error: 'invalid_token' });
    expect(wwwAuthenticate(raw(200))).toEqual({});
  });

  it('asserts presence or absence of resource_metadata', () => {
    const withPrm = raw(401, 'Bearer error="invalid_token", error_description="x", resource_metadata="http://h/prm"');
    expect(() => expectOAuth401(withPrm, { resourceMetadata: 'http://h/prm' })).not.toThrow();
    expect(() => expectOAuth401(withPrm, { resourceMetadata: false })).toThrow(/no resource_metadata/);
    expect(() => expectOAuth401(raw(401, 'Bearer error="invalid_token"'), { resourceMetadata: false })).not.toThrow();
    expect(() => expectOAuth401(raw(403, 'Bearer error="insufficient_scope"'))).toThrow(/expected 401/);
    expect(() => expectOAuth401(raw(401, 'Basic realm="x"'))).toThrow(/Bearer/);
  });
});

describe('printResult / parseResultLine / serverUrlArg', () => {
  const demo = {
    tools: ['whoami', 'add', 'admin_only'],
    whoami: { name: 'whoami', isError: false, text: '{"anonymous":true}', json: { anonymous: true } },
    add: { name: 'add', isError: false, text: '5' },
    adminOnly: { name: 'admin_only', isError: true, text: 'insufficient_scope: …' },
  };

  it('prints the RESULT line last and honours EXPECT_ADMIN', () => {
    const lines: string[] = [];
    delete process.env.EXPECT_ADMIN;
    expect(printResult('00', demo, { note: 1 }, (l) => lines.push(l))).toBe(0);
    expect(parseResultLine(`tools -> …\n${lines.join('\n')}\n`)).toEqual({ example: '00', tools: ['add', 'admin_only', 'whoami'], whoami: { anonymous: true }, add: '5', adminOnly: 'denied', extra: { note: 1 } });

    process.env.EXPECT_ADMIN = 'denied';
    expect(printResult('00', demo, undefined, () => undefined)).toBe(0);
    process.env.EXPECT_ADMIN = 'ok';
    expect(printResult('00', demo, undefined, () => undefined)).toBe(2);
    delete process.env.EXPECT_ADMIN;
  });

  it('prefers argv, then MCP_SERVER_URL, then the default', () => {
    const previous = process.env.MCP_SERVER_URL;
    delete process.env.MCP_SERVER_URL;
    expect(serverUrlArg('http://d/mcp', ['--logout'])).toBe('http://d/mcp');
    expect(serverUrlArg('http://d/mcp', ['--logout', 'http://a/mcp'])).toBe('http://a/mcp');
    process.env.MCP_SERVER_URL = 'http://e/mcp';
    expect(serverUrlArg('http://d/mcp', [])).toBe('http://e/mcp');
    expect(serverUrlArg('http://d/mcp', ['http://a/mcp'])).toBe('http://a/mcp');
    if (previous === undefined) delete process.env.MCP_SERVER_URL;
    else process.env.MCP_SERVER_URL = previous;
  });
});

describe('spawnExample', () => {
  it('starts the baseline server on a free port, waits for /healthz and stops it', async () => {
    const port = await freePort();
    const example = await spawnExample('examples/00-baseline-no-auth/server.ts', { MCP_PORT: String(port), MCP_LOG: '0' }, { readyUrl: `http://127.0.0.1:${port}/healthz` });
    try {
      expect(example.stdout()).toContain(`listening on 0.0.0.0:${port}`);
      const res = await fetch(`http://127.0.0.1:${port}/healthz`);
      expect(await res.json()).toEqual({ ok: true });
    } finally {
      await example.stop();
    }
    expect(example.child.exitCode ?? example.child.signalCode).not.toBeNull();
  });

  it('rejects when the process dies before it is ready', async () => {
    await expect(spawnExample('examples/00-baseline-no-auth/server.ts', { MCP_PORT: 'not-a-port' }, { readyUrl: 'http://127.0.0.1:1/healthz' })).rejects.toThrow(/exited with code/);
  });
});
