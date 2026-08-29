/**
 * run.ts — the demo every example client performs once it is connected:
 * list tools → whoami → add(2, 3) → admin_only, printed as a compact report.
 * Returned as data too, so tests assert on it instead of scraping stdout.
 *
 * Output contract (consumed by scripts/smoke.ts): human-readable lines on stdout, diagnostics on
 * stderr, and as the LAST stdout line `RESULT <json>` from printResult(). Exit code: 0 when the
 * demo completed, 2 when EXPECT_ADMIN (`ok` | `denied`) was set and did not match, 1 on any error.
 */
import '../env.ts';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import type { CallToolResult } from '@modelcontextprotocol/sdk/types.js';

export function createClient(name: string, version = '0.1.0'): Client {
  return new Client({ name, version });
}

/**
 * The server URL an example client should dial: the first positional CLI argument, else
 * MCP_SERVER_URL, else the example's own canonical URL. Flags (`--logout`) are skipped.
 */
export function serverUrlArg(defaultUrl: string, argv: string[] = process.argv.slice(2)): string {
  const positional = argv.find((a) => !a.startsWith('--'));
  return positional ?? process.env.MCP_SERVER_URL?.trim() ?? defaultUrl;
}

export interface ToolOutcome {
  name: string;
  isError: boolean;
  text: string;
  /** `text` parsed as JSON when it is JSON. */
  json?: unknown;
}

/** Calls a tool and flattens the result into { isError, text, json }. */
export async function callTool(client: Client, name: string, args: Record<string, unknown> = {}): Promise<ToolOutcome> {
  const result = (await client.callTool({ name, arguments: args })) as CallToolResult;
  return toolOutcome(name, result);
}

export function toolOutcome(name: string, result: CallToolResult): ToolOutcome {
  const text = (result.content ?? [])
    .filter((c): c is { type: 'text'; text: string } => c.type === 'text')
    .map((c) => c.text)
    .join('\n');
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    json = undefined;
  }
  return { name, isError: result.isError === true, text, json };
}

export interface DemoResult {
  tools: string[];
  whoami: ToolOutcome;
  add: ToolOutcome;
  adminOnly: ToolOutcome;
}

export interface RunDemoOptions {
  /** Whether admin_only is expected to succeed for this caller; a mismatch is flagged in the report. */
  expectAdmin?: boolean;
  /** Where to print the report (default stdout); pass () => {} to silence. */
  print?: (line: string) => void;
}

export async function runDemo(client: Client, { expectAdmin, print = console.log }: RunDemoOptions = {}): Promise<DemoResult> {
  const tools = (await client.listTools()).tools.map((t) => t.name);
  print(`tools        -> ${tools.join(', ')}`);

  const whoami = await callTool(client, 'whoami');
  print(`whoami       -> ${format(whoami)}`);

  const add = await callTool(client, 'add', { a: 2, b: 3 });
  print(`add(2, 3)    -> ${format(add)}`);

  const adminOnly = await callTool(client, 'admin_only');
  print(`admin_only   -> ${format(adminOnly)}`);
  if (expectAdmin !== undefined && expectAdmin === adminOnly.isError) {
    print(`             !! expected admin_only to ${expectAdmin ? 'succeed' : 'be rejected'}`);
  }

  return { tools, whoami, add, adminOnly };
}

function format({ isError, text, json }: ToolOutcome): string {
  const body = json !== undefined ? JSON.stringify(json) : text;
  return isError ? `ERROR ${body}` : body;
}

/** The machine-readable line every client prints last. */
export interface ResultLine {
  example: string;
  tools: string[];
  whoami: unknown;
  add: string;
  adminOnly: 'ok' | 'denied';
  extra?: Record<string, unknown>;
}

/**
 * Prints `RESULT {"example","tools","whoami","add","adminOnly","extra"}` as the last stdout line
 * and returns the process exit code: 0, or 2 when EXPECT_ADMIN (`ok` | `denied`) disagrees with
 * what happened. Use it as `process.exit(printResult('04', result))` after closing the client.
 */
export function printResult(example: string, result: DemoResult, extra?: Record<string, unknown>, print: (line: string) => void = console.log): number {
  const line: ResultLine = {
    example,
    tools: [...result.tools].sort(),
    whoami: result.whoami.json ?? result.whoami.text,
    add: result.add.text,
    adminOnly: result.adminOnly.isError ? 'denied' : 'ok',
    ...(extra ? { extra } : {}),
  };
  print(`RESULT ${JSON.stringify(line)}`);
  const expected = process.env.EXPECT_ADMIN?.trim();
  if (expected && expected !== line.adminOnly) {
    console.error(`EXPECT_ADMIN=${expected} but admin_only was ${line.adminOnly}`);
    return 2;
  }
  return 0;
}

/** Parses the `RESULT …` line out of a client's stdout (the last one wins). */
export function parseResultLine(stdout: string): ResultLine | undefined {
  const lines = stdout.split('\n').filter((l) => l.startsWith('RESULT '));
  const last = lines.at(-1);
  return last ? (JSON.parse(last.slice('RESULT '.length)) as ResultLine) : undefined;
}
