import { describe, expect, it, beforeEach } from "vitest";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AuditLog, verifyLog, GENESIS_HASH } from "../src/audit.js";

let logPath: string;

beforeEach(() => {
  const dir = mkdtempSync(join(tmpdir(), "mcpseatbelt-audit-test-"));
  logPath = join(dir, "audit.jsonl");
});

describe("AuditLog", () => {
  it("chains hashes starting from the genesis hash", () => {
    const log = new AuditLog(logPath);
    const first = log.record({ server: "s", tool: "a", arguments: {}, decision: "allow", rule: "r1" });
    const second = log.record({ server: "s", tool: "b", arguments: {}, decision: "deny", rule: "r2" });

    expect(first.prevHash).toBe(GENESIS_HASH);
    expect(second.prevHash).toBe(first.hash);
    expect(first.hash).not.toBe(second.hash);
  });

  it("resumes the chain correctly when reopened against an existing log file", () => {
    const log1 = new AuditLog(logPath);
    const first = log1.record({ server: "s", tool: "a", arguments: {}, decision: "allow", rule: "r1" });

    const log2 = new AuditLog(logPath);
    const second = log2.record({ server: "s", tool: "b", arguments: {}, decision: "allow", rule: "r1" });

    expect(second.prevHash).toBe(first.hash);
    expect(second.seq).toBe(2);
  });
});

describe("verifyLog", () => {
  it("reports ok for a missing (never-written) log", () => {
    const result = verifyLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.entries).toBe(0);
  });

  it("reports ok for an untampered log", () => {
    const log = new AuditLog(logPath);
    log.record({ server: "s", tool: "a", arguments: { x: 1 }, decision: "allow", rule: "r1" });
    log.record({ server: "s", tool: "b", arguments: { y: [1, 2] }, decision: "ask-allow", rule: "r2" });
    expect(verifyLog(logPath).ok).toBe(true);
  });

  it("detects a tampered field even when the tamperer recomputes nothing", () => {
    const log = new AuditLog(logPath);
    log.record({ server: "s", tool: "a", arguments: { x: 1 }, decision: "allow", rule: "r1" });

    const raw = readFileSync(logPath, "utf8").trim();
    const entry = JSON.parse(raw);
    entry.decision = "deny"; // flip the recorded decision after the fact
    writeFileSync(logPath, JSON.stringify(entry) + "\n", "utf8");

    const result = verifyLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.brokenAtLine).toBe(1);
  });

  it("detects a deleted (removed) entry breaking the chain", () => {
    const log = new AuditLog(logPath);
    log.record({ server: "s", tool: "a", arguments: {}, decision: "allow", rule: "r1" });
    log.record({ server: "s", tool: "b", arguments: {}, decision: "allow", rule: "r1" });
    log.record({ server: "s", tool: "c", arguments: {}, decision: "allow", rule: "r1" });

    const lines = readFileSync(logPath, "utf8").trim().split("\n");
    lines.splice(1, 1); // remove the middle entry
    writeFileSync(logPath, lines.join("\n") + "\n", "utf8");

    const result = verifyLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.brokenAtLine).toBe(2);
  });
});
