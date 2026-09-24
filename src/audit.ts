import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import type { AuditEvent } from "./types.js";

export const GENESIS_HASH = "0".repeat(64);

export interface AuditRecord {
  seq: number;
  ts: string;
  server: string;
  tool: string;
  arguments: unknown;
  decision: AuditEvent["decision"];
  rule: string;
  reason?: string;
  prevHash: string;
  hash: string;
}

/** Canonical, deterministic serialization used as input to the hash. */
function canonicalize(record: Omit<AuditRecord, "hash">): string {
  // Fixed key order so the hash is reproducible regardless of object construction order.
  return JSON.stringify({
    seq: record.seq,
    ts: record.ts,
    server: record.server,
    tool: record.tool,
    arguments: record.arguments,
    decision: record.decision,
    rule: record.rule,
    reason: record.reason ?? null,
    prevHash: record.prevHash,
  });
}

export function computeHash(record: Omit<AuditRecord, "hash">): string {
  return createHash("sha256").update(canonicalize(record), "utf8").digest("hex");
}

/**
 * Append-only, tamper-evident audit log. Each entry embeds the SHA-256 hash of
 * the previous entry, forming a hash chain: modifying, deleting, or
 * reordering any past entry invalidates every hash after it.
 */
export class AuditLog {
  private readonly path: string;
  private lastHash: string;
  private nextSeq: number;

  constructor(path: string) {
    this.path = path;
    const tail = readLastRecord(path);
    this.lastHash = tail?.hash ?? GENESIS_HASH;
    this.nextSeq = (tail?.seq ?? 0) + 1;
  }

  record(entry: {
    server: string;
    tool: string;
    arguments: unknown;
    decision: AuditEvent["decision"];
    rule: string;
    reason?: string;
  }): AuditRecord {
    const base: Omit<AuditRecord, "hash"> = {
      seq: this.nextSeq,
      ts: new Date().toISOString(),
      server: entry.server,
      tool: entry.tool,
      arguments: entry.arguments,
      decision: entry.decision,
      rule: entry.rule,
      reason: entry.reason,
      prevHash: this.lastHash,
    };
    const hash = computeHash(base);
    const full: AuditRecord = { ...base, hash };

    const dir = dirname(this.path);
    if (dir && !existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
    appendFileSync(this.path, JSON.stringify(full) + "\n", "utf8");

    this.lastHash = hash;
    this.nextSeq += 1;
    return full;
  }
}

function readLastRecord(path: string): AuditRecord | undefined {
  if (!existsSync(path)) return undefined;
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return undefined;
  return JSON.parse(lines[lines.length - 1]) as AuditRecord;
}

export interface VerifyResult {
  ok: boolean;
  entries: number;
  /** 1-based line number of the first problem found, if any. */
  brokenAtLine?: number;
  error?: string;
}

/** Re-walks the whole chain from genesis and confirms every hash and link is intact. */
export function verifyLog(path: string): VerifyResult {
  if (!existsSync(path)) {
    return { ok: true, entries: 0 };
  }
  const text = readFileSync(path, "utf8");
  const lines = text.split("\n").filter((l) => l.trim().length > 0);

  let expectedPrev = GENESIS_HASH;
  let expectedSeq = 1;

  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let parsed: AuditRecord;
    try {
      parsed = JSON.parse(lines[i]) as AuditRecord;
    } catch {
      return { ok: false, entries: lines.length, brokenAtLine: lineNo, error: "invalid JSON" };
    }

    if (parsed.prevHash !== expectedPrev) {
      return {
        ok: false,
        entries: lines.length,
        brokenAtLine: lineNo,
        error: `prevHash mismatch: expected ${expectedPrev}, found ${parsed.prevHash}`,
      };
    }
    if (parsed.seq !== expectedSeq) {
      return {
        ok: false,
        entries: lines.length,
        brokenAtLine: lineNo,
        error: `sequence mismatch: expected seq ${expectedSeq}, found ${parsed.seq}`,
      };
    }

    const { hash, ...rest } = parsed;
    const recomputed = computeHash(rest);
    if (recomputed !== hash) {
      return {
        ok: false,
        entries: lines.length,
        brokenAtLine: lineNo,
        error: `hash mismatch: entry content does not match its recorded hash (expected ${recomputed}, found ${hash})`,
      };
    }

    expectedPrev = hash;
    expectedSeq += 1;
  }

  return { ok: true, entries: lines.length };
}
