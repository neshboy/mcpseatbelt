/** Shared types for policy evaluation, audit logging, and the proxy. */

export type PolicyAction = "allow" | "deny" | "ask";

/**
 * A condition on a single argument value. All provided comparators inside a
 * single condition must hold (logical AND) for the condition to match.
 */
export interface ArgCondition {
  /** Argument must equal this value exactly (deep-equal for objects/arrays). */
  equals?: unknown;
  /** Argument (coerced to string) must match this regular expression. */
  matches?: string;
  /** Argument must be one of these values. */
  oneOf?: unknown[];
}

/** Map of argument name -> condition(s) that must all hold for the rule to apply. */
export type ArgConditions = Record<string, ArgCondition>;

export interface PolicyRule {
  /** Optional human-readable name, shown in audit log entries and prompts. */
  name?: string;
  /** Exact tool name or glob pattern (supports `*` and `?`). */
  match: string;
  /** What to do when this rule matches. */
  action: PolicyAction;
  /** Optional constraints on the call's arguments. */
  when?: ArgConditions;
}

export interface Policy {
  version: number;
  /** Fallback action when no rule matches. Defaults to "deny" (fail closed). */
  default: PolicyAction;
  rules: PolicyRule[];
}

export type Decision =
  | { outcome: "allow"; rule: string }
  | { outcome: "deny"; rule: string }
  | { outcome: "ask-allow"; rule: string }
  | { outcome: "ask-deny"; rule: string };

export interface AuditEvent {
  seq: number;
  ts: string;
  server: string;
  tool: string;
  arguments: unknown;
  decision: Decision["outcome"];
  rule: string;
  reason?: string;
}
