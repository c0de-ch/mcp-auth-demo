import './env.ts'; // always first (see README: import-order rule)
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { discoverOAuthProtectedResourceMetadata } from '@modelcontextprotocol/sdk/client/auth.js';
import { createApp, mountMcp } from './http.ts';
import { createJwtVerifier } from './jwt.ts';
import { mountProtectedResourceMetadata, protectedResourceMetadata, resourceMetadataUrl } from './prm.ts';
import { createDemoServer } from './tools.ts';
import { expectOAuth401, initializeSession, rawRequest, startTestServer, testKeyPair, type TestServer } from './testing.ts';

const ISSUER = 'http://192.0.2.10:8180/realms/mcp';

describe('resourceMetadataUrl', () => {
  it('is path-aware per RFC 9728', () => {
    expect(resourceMetadataUrl('http://192.168.78.87:4104/mcp')).toBe('http://192.168.78.87:4104/.well-known/oauth-protected-resource/mcp');
    expect(resourceMetadataUrl('http://192.168.78.87:4104/')).toBe('http://192.168.78.87:4104/.well-known/oauth-protected-resource');
  });
});

describe('mountProtectedResourceMetadata', () => {
  let server: TestServer;
  let resourceUrl: string;
  let prmUrl: string;

  beforeAll(async () => {
    const keys = await testKeyPair();
    const app = createApp({ log: false });
    // The resource URL is the canonical public one even though the test dials 127.0.0.1 — that
    // mirrors production, where PRM.resource must equal what clients are told to use.
    resourceUrl = 'http://192.0.2.20:4104/mcp';
    prmUrl = mountProtectedResourceMetadata(app, { resourceUrl, authorizationServers: [ISSUER], scopesSupported: ['mcp:tools', 'mcp:admin'], resourceName: 'prm-test' });
    const verifier = createJwtVerifier({ issuer: ISSUER, audience: 'mcp-server', jwks: keys.jwks });
    mountMcp(app, { createServer: () => createDemoServer({ name: 'prm-test' }), auth: requireBearerAuth({ verifier, requiredScopes: ['mcp:tools'], resourceMetadataUrl: prmUrl }) });
    server = await startTestServer(app);
  });

  afterAll(async () => {
    await server.close();
  });

  it('serves the PRM document at the path-aware well-known URL and returns that URL', async () => {
    expect(prmUrl).toBe('http://192.0.2.20:4104/.well-known/oauth-protected-resource/mcp');
    const res = await rawRequest(`${server.baseUrl}/.well-known/oauth-protected-resource/mcp`);
    expect(res.status).toBe(200);
    expect(res.headers['access-control-allow-origin']).toBe('*');
    expect(res.json()).toEqual({
      resource: resourceUrl,
      authorization_servers: [ISSUER],
      scopes_supported: ['mcp:tools', 'mcp:admin'],
      resource_name: 'prm-test',
      bearer_methods_supported: ['header'],
    });
  });

  it('does NOT mirror the authorization server metadata on the resource origin', async () => {
    expect((await rawRequest(`${server.baseUrl}/.well-known/oauth-authorization-server`)).status).toBe(404);
  });

  it('answers 405 for POST on the metadata URL', async () => {
    expect((await rawRequest(`${server.baseUrl}/.well-known/oauth-protected-resource/mcp`, { method: 'POST' })).status).toBe(405);
  });

  it('the 401 challenge points at the PRM and names the required scope', async () => {
    const { response } = await initializeSession(`${server.baseUrl}/mcp`);
    expectOAuth401(response, { resourceMetadata: prmUrl, scope: 'mcp:tools' });
  });

  it('is what the SDK client discovers from the 401', async () => {
    const { response } = await initializeSession(`${server.baseUrl}/mcp`);
    const header = response.headers['www-authenticate'] as string;
    // The advertised URL uses the public host; rewrite it to the test listener for the fetch.
    const advertised = /resource_metadata="([^"]+)"/.exec(header)![1];
    const local = new URL(advertised);
    local.host = new URL(server.baseUrl).host;
    const prm = await discoverOAuthProtectedResourceMetadata(`${server.baseUrl}/mcp`, { resourceMetadataUrl: local });
    expect(prm.resource).toBe(resourceUrl);
    expect(prm.authorization_servers).toEqual([ISSUER]);
  });
});

describe('protectedResourceMetadata', () => {
  it('defaults bearer_methods_supported to header', () => {
    expect(protectedResourceMetadata({ resourceUrl: 'http://h:1/mcp', authorizationServers: ['http://as/'] })).toMatchObject({ bearer_methods_supported: ['header'] });
  });
});
