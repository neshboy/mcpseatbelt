import { readFileSync } from "node:fs";
import * as YAML from "js-yaml";
import type { ArgCondition, ArgConditions, Policy, PolicyRule, PolicyAction } from "./types.js";

const VALID_ACTIONS: PolicyAction[] = ["allow", "deny", "ask"];

export class PolicyError extends Error {}

/** Converts a glob pattern (supporting `*` and `?`) into a RegExp that must match the whole string. */
export function globToRegExp(pattern: string): RegExp {
  let re = "^";
  for (const ch of pattern) {
    if (ch === "*") {
      re += ".*";
    } else if (ch === "?") {
      re += ".";
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  re += "$";
  return new RegExp(re);
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function assertAction(value: unknown, context: string): PolicyAction {
  if (typeof value !== "string" || !VALID_ACTIONS.includes(value as PolicyAction)) {
    throw new PolicyError(`${context}: action must be one of ${VALID_ACTIONS.join(", ")}, got ${JSON.stringify(value)}`);
  }
  return value as PolicyAction;
}

function parseArgCondition(raw: unknown, context: string): ArgCondition {
  if (!isPlainObject(raw)) {
    throw new PolicyError(`${context}: condition must be a mapping`);
  }
  const cond: ArgCondition = {};
  if ("equals" in raw) cond.equals = raw.equals;
  if ("matches" in raw) {
    if (typeof raw.matches !== "string") {
      throw new PolicyError(`${context}: "matches" must be a string regular expression`);
    }
    cond.matches = raw.matches;
  }
  if ("oneOf" in raw) {
    if (!Array.isArray(raw.oneOf)) {
      throw new PolicyError(`${context}: "oneOf" must be an array`);
    }
    cond.oneOf = raw.oneOf;
  }
  if (cond.equals === undefined && cond.matches === undefined && cond.oneOf === undefined) {
    throw new PolicyError(`${context}: condition must specify one of equals/matches/oneOf`);
  }
  return cond;
}

function parseWhen(raw: unknown, context: string): ArgConditions | undefined {
  if (raw === undefined) return undefined;
  if (!isPlainObject(raw)) {
    throw new PolicyError(`${context}: "when" must be a mapping of argument name -> condition`);
  }
  const out: ArgConditions = {};
  for (const [key, value] of Object.entries(raw)) {
    out[key] = parseArgCondition(value, `${context}.when.${key}`);
  }
  return out;
}

function parseRule(raw: unknown, index: number): PolicyRule {
  const context = `rules[${index}]`;
  if (!isPlainObject(raw)) {
    throw new PolicyError(`${context}: must be a mapping`);
  }
  if (typeof raw.match !== "string" || raw.match.length === 0) {
    throw new PolicyError(`${context}: "match" must be a non-empty string`);
  }
  const action = assertAction(raw.action, context);
  const rule: PolicyRule = {
    match: raw.match,
    action,
    name: typeof raw.name === "string" ? raw.name : undefined,
    when: parseWhen(raw.when, context),
  };
  return rule;
}

/** Parses and validates a policy document already loaded from YAML/JSON into a plain object. */
export function parsePolicy(raw: unknown): Policy {
  if (!isPlainObject(raw)) {
    throw new PolicyError("policy document must be a mapping at the top level");
  }
  const version = typeof raw.version === "number" ? raw.version : 1;
  const fallback = raw.default === undefined ? "deny" : assertAction(raw.default, "default");
  const rulesRaw = raw.rules;
  if (rulesRaw !== undefined && !Array.isArray(rulesRaw)) {
    throw new PolicyError('"rules" must be an array');
  }
  const rules = (rulesRaw ?? []).map((r: unknown, i: number) => parseRule(r, i));
  return { version, default: fallback, rules };
}

/** Loads and validates a policy YAML file from disk. */
export function loadPolicy(path: string): Policy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new PolicyError(`could not read policy file at ${path}: ${(err as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = YAML.load(text);
  } catch (err) {
    throw new PolicyError(`could not parse policy YAML at ${path}: ${(err as Error).message}`);
  }
  return parsePolicy(raw);
}

function stringify(value: unknown): string {
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return a === b;
  if (typeof a === "object" && typeof b === "object") {
    return JSON.stringify(a) === JSON.stringify(b);
  }
  return false;
}

function matchesCondition(value: unknown, condition: ArgCondition): boolean {
  if (condition.equals !== undefined && !deepEqual(value, condition.equals)) return false;
  if (condition.matches !== undefined) {
    const re = new RegExp(condition.matches);
    if (!re.test(stringify(value))) return false;
  }
  if (condition.oneOf !== undefined && !condition.oneOf.some((candidate) => deepEqual(value, candidate))) {
    return false;
  }
  return true;
}

function matchesWhen(args: unknown, when: ArgConditions | undefined): boolean {
  if (!when) return true;
  const argObj = isPlainObject(args) ? args : {};
  for (const [key, condition] of Object.entries(when)) {
    if (!matchesCondition(argObj[key], condition)) return false;
  }
  return true;
}

/** Finds the first rule that matches a given tool name + arguments, in declaration order. */
export function findMatchingRule(policy: Policy, toolName: string, args: unknown): PolicyRule | undefined {
  for (const rule of policy.rules) {
    const re = globToRegExp(rule.match);
    if (re.test(toolName) && matchesWhen(args, rule.when)) {
      return rule;
    }
  }
  return undefined;
}

export function ruleLabel(rule: PolicyRule | undefined, policy: Policy): string {
  if (!rule) return `default:${policy.default}`;
  return rule.name ?? rule.match;
}
