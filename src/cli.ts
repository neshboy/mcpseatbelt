#!/usr/bin/env node
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { Command } from "commander";

import { startProxy } from "./proxy.js";
import { loadPolicy, PolicyError } from "./policy.js";
import { verifyLog } from "./audit.js";

const DEFAULT_POLICY_PATH = ".mcp-seatbelt/policy.yaml";
const DEFAULT_AUDIT_LOG_PATH = ".mcp-seatbelt/audit.jsonl";

const STARTER_POLICY = `# MCP Seatbelt policy
#
# Rules are checked in order; the first rule whose "match" (an exact tool
# name or a glob like "delete_*") matches the called tool name AND whose
# optional "when" argument conditions all hold wins. If no rule matches,
# the top-level "default" action applies.
#
# action: allow | deny | ask
#   allow - forward the call to the real server.
#   deny  - reject the call; it never reaches the real server.
#   ask   - prompt for interactive y/n confirmation; fails closed (denies)
#           when there is no controlling terminal (e.g. when run
#           non-interactively by an agent client).

version: 1
default: ask

rules:
  # Reading things is generally safe.
  - name: allow-reads
    match: "read_*"
    action: allow

  # Never allow destructive calls, no matter what.
  - name: block-deletes
    match: "delete_*"
    action: deny

  # Writes require a human to confirm.
  - name: confirm-writes
    match: "write_*"
    action: ask
`;

const program = new Command();

program
  .name("mcpseatbelt")
  .description("A policy-enforcing gateway for the Model Context Protocol (MCP).")
  .version("0.1.0");

program
  .command("wrap")
  .description("Wrap a real MCP server, enforcing a policy on every tools/call before it reaches that server.")
  .option("-p, --policy <path>", "path to the policy YAML file", DEFAULT_POLICY_PATH)
  .option("-a, --audit-log <path>", "path to the append-only audit log (JSONL)", DEFAULT_AUDIT_LOG_PATH)
  .option("--non-interactive", "never prompt for 'ask' rules; always fail closed (deny)", false)
  .option("--server-label <label>", "label recorded in the audit log identifying the wrapped server")
  .argument("<command...>", "the command (and its arguments) that launches the real MCP server")
  .action(async (commandParts: string[], opts) => {
    const [command, ...args] = commandParts;
    if (!command) {
      console.error("mcpseatbelt: no command given to wrap. Usage: mcpseatbelt wrap -- <command> [args...]");
      process.exitCode = 1;
      return;
    }

    let policy;
    try {
      policy = loadPolicy(resolve(opts.policy));
    } catch (err) {
      if (err instanceof PolicyError) {
        console.error(`mcpseatbelt: ${err.message}`);
        process.exitCode = 1;
        return;
      }
      throw err;
    }

    const session = await startProxy({
      command,
      args,
      policy,
      auditLogPath: resolve(opts.auditLog),
      nonInteractive: Boolean(opts.nonInteractive),
      serverLabel: opts.serverLabel,
    });

    const shutdown = async () => {
      await session.close();
      process.exit(0);
    };
    process.once("SIGINT", shutdown);
    process.once("SIGTERM", shutdown);
  });

program
  .command("init")
  .description("Scaffold a starter policy at .mcp-seatbelt/policy.yaml")
  .option("-p, --policy <path>", "where to write the starter policy", DEFAULT_POLICY_PATH)
  .option("-f, --force", "overwrite an existing policy file", false)
  .action((opts) => {
    const path = resolve(opts.policy);
    if (existsSync(path) && !opts.force) {
      console.error(`mcpseatbelt: ${path} already exists. Use --force to overwrite.`);
      process.exitCode = 1;
      return;
    }
    const dir = dirname(path);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    writeFileSync(path, STARTER_POLICY, "utf8");
    console.log(`mcpseatbelt: wrote starter policy to ${path}`);
  });

program
  .command("verify-log")
  .description("Verify the tamper-evident hash chain of an audit log.")
  .option("-a, --audit-log <path>", "path to the audit log (JSONL)", DEFAULT_AUDIT_LOG_PATH)
  .action((opts) => {
    const path = resolve(opts.auditLog);
    const result = verifyLog(path);
    if (result.ok) {
      console.log(`mcpseatbelt: OK - ${result.entries} entr${result.entries === 1 ? "y" : "ies"} verified, hash chain intact.`);
      process.exitCode = 0;
    } else {
      console.error(
        `mcpseatbelt: TAMPERING DETECTED at line ${result.brokenAtLine} of ${result.entries}: ${result.error}`,
      );
      process.exitCode = 1;
    }
  });

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.stack ?? err.message : err);
  process.exitCode = 1;
});
