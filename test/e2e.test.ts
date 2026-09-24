import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

import { verifyLog } from "../src/audit.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const CLI_PATH = join(__dirname, "..", "dist", "cli.js");
const TEST_SERVER_PATH = join(__dirname, "fixtures", "test-server.mjs");

const POLICY = `
version: 1
default: deny
rules:
  - name: allow-read
    match: "read_file"
    action: allow
  - name: deny-delete
    match: "delete_file"
    action: deny
  - name: ask-write
    match: "write_file"
    action: ask
`;

let workDir: string;
let policyPath: string;
let auditLogPath: string;
let readTarget: string;
let deleteTarget: string;
let writeTarget: string;
let client: Client | undefined;

/** Connects a real MCP client to `mcpseatbelt wrap` (spawned as a real child process), which in turn spawns the real test server. */
async function connectThroughSeatbelt(extraArgs: string[] = []): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [
      CLI_PATH,
      "wrap",
      "--policy",
      policyPath,
      "--audit-log",
      auditLogPath,
      ...extraArgs,
      "--",
      process.execPath,
      TEST_SERVER_PATH,
    ],
    stderr: "pipe",
  });
  const c = new Client({ name: "test-agent-client", version: "0.1.0" }, { capabilities: {} });
  await c.connect(transport);
  return c;
}

beforeEach(() => {
  workDir = mkdtempSync(join(tmpdir(), "mcpseatbelt-test-"));
  policyPath = join(workDir, "policy.yaml");
  auditLogPath = join(workDir, "audit.jsonl");
  readTarget = join(workDir, "hello.txt");
  deleteTarget = join(workDir, "to-delete.txt");
  writeTarget = join(workDir, "not-written.txt");

  writeFileSync(readTarget, "hello world", "utf8");
  writeFileSync(deleteTarget, "bye", "utf8");
  writeFileSync(policyPath, POLICY, "utf8");
});

afterEach(async () => {
  if (client) {
    await client.close();
    client = undefined;
  }
});

describe("mcpseatbelt wrap (real MCP proxy over real child processes)", () => {
  it("forwards an allowed call to the real server and returns its real result", async () => {
    client = await connectThroughSeatbelt();

    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual(["delete_file", "read_file", "write_file"]);

    const result = await client.callTool({ name: "read_file", arguments: { path: readTarget } });
    const content = result.content as Array<{ type: string; text: string }>;
    expect(content[0].text).toBe("hello world");
  });

  it("never lets a denied call reach the real server (no side effect occurs)", async () => {
    client = await connectThroughSeatbelt();

    await expect(client.callTool({ name: "delete_file", arguments: { path: deleteTarget } })).rejects.toThrow(
      /denied by policy rule "deny-delete"/,
    );

    // The real side effect (file deletion) must never have happened.
    expect(existsSync(deleteTarget)).toBe(true);
    expect(readFileSync(deleteTarget, "utf8")).toBe("bye");
  });

  it("fails closed on an 'ask' rule when there is no controlling terminal", async () => {
    client = await connectThroughSeatbelt();

    await expect(
      client.callTool({ name: "write_file", arguments: { path: writeTarget, content: "should not be written" } }),
    ).rejects.toThrow(/no interactive terminal is available; denying/);

    expect(existsSync(writeTarget)).toBe(false);
  });

  it("falls back to the policy default when no rule matches the tool name", async () => {
    writeFileSync(
      policyPath,
      `version: 1\ndefault: deny\nrules: []\n`,
      "utf8",
    );
    client = await connectThroughSeatbelt();

    await expect(client.callTool({ name: "read_file", arguments: { path: readTarget } })).rejects.toThrow(
      /denied by policy rule "default:deny"/,
    );
  });

  it("matches glob rules and argument conditions", async () => {
    writeFileSync(
      policyPath,
      `
version: 1
default: deny
rules:
  - name: allow-tmp-reads
    match: "read_*"
    action: allow
    when:
      path:
        matches: "hello"
`,
      "utf8",
    );
    client = await connectThroughSeatbelt();

    const ok = await client.callTool({ name: "read_file", arguments: { path: readTarget } });
    expect((ok.content as Array<{ text: string }>)[0].text).toBe("hello world");

    // A read_file call whose path does NOT contain "hello" should fall through to default: deny.
    const other = join(workDir, "other.txt");
    writeFileSync(other, "irrelevant", "utf8");
    await expect(client.callTool({ name: "read_file", arguments: { path: other } })).rejects.toThrow(/denied by policy rule "default:deny"/);
  });

  it("writes a correctly hash-chained audit log for every decision", async () => {
    client = await connectThroughSeatbelt();

    await client.callTool({ name: "read_file", arguments: { path: readTarget } });
    await expect(client.callTool({ name: "delete_file", arguments: { path: deleteTarget } })).rejects.toThrow();
    await expect(client.callTool({ name: "write_file", arguments: { path: writeTarget, content: "x" } })).rejects.toThrow();

    await client.close();
    client = undefined;

    const lines = readFileSync(auditLogPath, "utf8").trim().split("\n");
    expect(lines).toHaveLength(3);

    const entries = lines.map((l) => JSON.parse(l));
    expect(entries.map((e) => e.decision)).toEqual(["allow", "deny", "ask-deny"]);
    expect(entries[0].prevHash).toBe("0".repeat(64));
    expect(entries[1].prevHash).toBe(entries[0].hash);
    expect(entries[2].prevHash).toBe(entries[1].hash);

    const result = verifyLog(auditLogPath);
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(3);
  });

  it("detects a hand-tampered audit log entry via verify-log", async () => {
    client = await connectThroughSeatbelt();
    await client.callTool({ name: "read_file", arguments: { path: readTarget } });
    await expect(client.callTool({ name: "delete_file", arguments: { path: deleteTarget } })).rejects.toThrow();
    await client.close();
    client = undefined;

    // Sanity check: the untampered log verifies cleanly.
    expect(verifyLog(auditLogPath).ok).toBe(true);

    // Hand-tamper the first entry's recorded arguments without touching its hash.
    const lines = readFileSync(auditLogPath, "utf8").trim().split("\n");
    const tampered = JSON.parse(lines[0]);
    tampered.arguments.path = "/etc/passwd";
    lines[0] = JSON.stringify(tampered);
    writeFileSync(auditLogPath, lines.join("\n") + "\n", "utf8");

    const result = verifyLog(auditLogPath);
    expect(result.ok).toBe(false);
    expect(result.brokenAtLine).toBe(1);
    expect(result.error).toMatch(/hash mismatch/);
  });
});
