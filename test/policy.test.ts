import { describe, expect, it } from "vitest";
import { findMatchingRule, globToRegExp, parsePolicy, PolicyError, ruleLabel } from "../src/policy.js";

describe("globToRegExp", () => {
  it("matches exact strings", () => {
    expect(globToRegExp("read_file").test("read_file")).toBe(true);
    expect(globToRegExp("read_file").test("read_file2")).toBe(false);
  });

  it("supports * and ? wildcards", () => {
    expect(globToRegExp("delete_*").test("delete_file")).toBe(true);
    expect(globToRegExp("delete_*").test("delete_")).toBe(true);
    expect(globToRegExp("delete_*").test("undelete_file")).toBe(false);
    expect(globToRegExp("rm_?").test("rm_1")).toBe(true);
    expect(globToRegExp("rm_?").test("rm_12")).toBe(false);
  });

  it("escapes regex metacharacters in the literal parts", () => {
    expect(globToRegExp("a.b").test("aXb")).toBe(false);
    expect(globToRegExp("a.b").test("a.b")).toBe(true);
  });
});

describe("parsePolicy", () => {
  it("parses a minimal valid policy", () => {
    const policy = parsePolicy({ version: 1, default: "deny", rules: [{ match: "read_*", action: "allow" }] });
    expect(policy.default).toBe("deny");
    expect(policy.rules).toHaveLength(1);
  });

  it("defaults to deny (fail closed) when 'default' is omitted", () => {
    const policy = parsePolicy({ rules: [] });
    expect(policy.default).toBe("deny");
  });

  it("rejects an invalid action", () => {
    expect(() => parsePolicy({ rules: [{ match: "x", action: "maybe" }] })).toThrow(PolicyError);
  });

  it("rejects a rule with no match", () => {
    expect(() => parsePolicy({ rules: [{ action: "allow" }] })).toThrow(PolicyError);
  });

  it("rejects a non-mapping document", () => {
    expect(() => parsePolicy([1, 2, 3])).toThrow(PolicyError);
  });

  it("parses 'when' argument conditions", () => {
    const policy = parsePolicy({
      rules: [{ match: "read_*", action: "allow", when: { path: { matches: "^/tmp/" } } }],
    });
    expect(policy.rules[0].when?.path?.matches).toBe("^/tmp/");
  });
});

describe("findMatchingRule / ruleLabel", () => {
  const policy = parsePolicy({
    default: "deny",
    rules: [
      { name: "allow-read", match: "read_*", action: "allow" },
      { name: "deny-delete", match: "delete_*", action: "deny" },
      { name: "scoped-write", match: "write_file", action: "ask", when: { path: { matches: "^/tmp/" } } },
    ],
  });

  it("returns the first matching rule in declaration order", () => {
    const rule = findMatchingRule(policy, "read_file", { path: "/tmp/x" });
    expect(rule?.name).toBe("allow-read");
  });

  it("returns undefined when no rule matches", () => {
    expect(findMatchingRule(policy, "unknown_tool", {})).toBeUndefined();
  });

  it("respects 'when' argument conditions", () => {
    expect(findMatchingRule(policy, "write_file", { path: "/tmp/ok" })?.name).toBe("scoped-write");
    expect(findMatchingRule(policy, "write_file", { path: "/etc/passwd" })).toBeUndefined();
  });

  it("labels the default fallback distinctly from named rules", () => {
    expect(ruleLabel(undefined, policy)).toBe("default:deny");
    const rule = findMatchingRule(policy, "delete_file", {});
    expect(ruleLabel(rule, policy)).toBe("deny-delete");
  });
});
