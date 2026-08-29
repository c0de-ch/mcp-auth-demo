import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['examples/**/*.test.ts', 'src/**/*.test.ts', 'tests/**/*.test.ts'],
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Test files start real HTTP servers (ephemeral ports, but some OAuth tests bind the fixed
    // callback port): run files one after another in a single forked worker.
    pool: 'forks',
    fileParallelism: false,
    env: {
      // The SDK auth router rate-limits /token etc. (50 per 15 min); test loops would trip it.
      MCP_RATE_LIMIT: '0',
      // Never open a real browser from a test.
      MCP_NO_BROWSER: '1',
    },
  },
});
