# MCP Seatbelt

MCP Seatbelt is a policy-enforcing gateway for the [Model Context
Protocol](https://modelcontextprotocol.io) (MCP). It sits between an agent
client (Claude Desktop, Cursor, your own agent, etc.) and a real downstream
MCP server, and it checks every `tools/call` request against a declarative
allow/deny/ask policy **before** that call ever reaches the real server.

```
agent client  <--stdio-->  mcpseatbelt wrap  <--stdio-->  real MCP server
                                  |
                         policy.yaml (allow/deny/ask)
                                  |
                         audit.jsonl (hash-chained log)
```

It works by being a real, protocol-speaking MCP proxy on both sides: it
exposes a genuine MCP *server* over stdio (what the agent client connects
to), and it opens a genuine MCP *client* connection over stdio to the real,
wrapped server as a child process, using the official
[`@modelcontextprotocol/sdk`](https://github.com/modelcontextprotocol/typescript-sdk).
Every `tools/call` is intercepted at that boundary, evaluated against the
policy, logged, and only then (if allowed) forwarded to the real server.

## Why this is not just another command wrapper

This portfolio also contains `agentseatbelt` (a generic shell-command
sandbox/wrapper with no protocol awareness - it doesn't know what a "tool"
or an MCP server is, it just wraps a shell command) and `mcpsqueeze` (which
speaks MCP but is about deduplicating/truncating tool *results* after the
fact, purely for token savings, with no authorization concept). MCP
Seatbelt is different from both: it is specifically about **authorization
at the MCP tool-call boundary**. It parses the real MCP `tools/call`
request, matches on the real tool name (and optionally the shape of the
real arguments), and can deny or require confirmation for a call *before*
it ever reaches the downstream server - something a shell wrapper
structurally cannot do (it only ever sees bytes on stdio, not "the agent is
about to call `delete_file`"), and something a result-squeezer has no
reason to do (it only ever sees results, after the real call already
happened).

## Features

- **Real MCP proxy.** Genuine `Server`/`Client` objects from the official
  SDK on both sides, talking real JSON-RPC over stdio - not a mock.
- **Declarative policy.** A YAML file with ordered rules matching tool
  names (exact or glob, e.g. `delete_*`) and, optionally, the shape of the
  call's arguments (equality, regex, or a fixed set of values).
- **Three actions.** `allow` forwards the call. `deny` rejects it outright.
  `ask` prompts for a real interactive y/n confirmation on the controlling
  terminal, and **fails closed** (denies) whenever no controlling terminal
  is available - which is the normal case, since agent clients launch
  `mcpseatbelt` with piped stdio.
- **Tamper-evident audit log.** Every decision (allow/deny/ask-allow/
  ask-deny) is appended to a JSONL file where each entry embeds the
  SHA-256 hash of the previous entry. Editing, deleting, or reordering any
  past entry breaks the chain, and `mcpseatbelt verify-log` detects it.

## Install

```bash
git clone <this repo>
cd mcpseatbelt
npm install
npm run build
```

This produces `dist/cli.js`, runnable as `node dist/cli.js <command>`, or
link it onto your `PATH` for local development:

```bash
npm link   # now `mcpseatbelt` is available as a global command
```

## Quick start

1. Scaffold a starter policy in your project:

   ```bash
   mcpseatbelt init
   # writes .mcp-seatbelt/policy.yaml
   ```

2. Point your agent client's MCP server config at `mcpseatbelt wrap`
   instead of the real server, passing the real server's command after
   `--`. For example, if your client previously launched a server with:

   ```json
   { "command": "node", "args": ["real-server.js"] }
   ```

   change it to:

   ```json
   { "command": "mcpseatbelt", "args": ["wrap", "--", "node", "real-server.js"] }
   ```

   `mcpseatbelt wrap` itself behaves as a real MCP server over stdio, so
   from the agent client's point of view nothing else changes - it still
   gets the same tools, the same results, just policy-checked.

3. Every `tools/call` is now checked against `.mcp-seatbelt/policy.yaml`
   before it reaches `real-server.js`, and recorded in
   `.mcp-seatbelt/audit.jsonl`.

4. Periodically verify the audit log hasn't been tampered with:

   ```bash
   mcpseatbelt verify-log
   ```

### Example policy

See [`examples/policy.yaml`](examples/policy.yaml) for a fuller example.
A minimal one:

```yaml
version: 1
default: deny        # fail closed: anything not explicitly matched is denied

rules:
  - name: allow-reads
    match: "read_*"
    action: allow

  - name: block-deletes
    match: "delete_*"
    action: deny

  - name: confirm-writes
    match: "write_file"
    action: ask
    when:
      path:
        matches: "^/home/"   # only prompt for writes under /home
```

Rules are checked in order; the first rule whose `match` (exact tool name
or a glob supporting `*`/`?`) matches the called tool, and whose `when`
conditions (if any) all hold against the call's arguments, wins. If no rule
matches, `default` applies.

### CLI reference

```
mcpseatbelt wrap [options] -- <command> [args...]
    -p, --policy <path>      policy YAML file (default .mcp-seatbelt/policy.yaml)
    -a, --audit-log <path>   audit log JSONL file (default .mcp-seatbelt/audit.jsonl)
    --non-interactive        never prompt for "ask" rules; always fail closed
    --server-label <label>   label recorded in the audit log for the wrapped server

mcpseatbelt init [options]
    -p, --policy <path>      where to write the starter policy
    -f, --force              overwrite an existing policy file

mcpseatbelt verify-log [options]
    -a, --audit-log <path>   audit log to verify
```

## How `ask` actually works

`mcpseatbelt wrap`'s own stdin/stdout are the MCP JSON-RPC channel to the
agent client - the SDK's `StdioServerTransport` owns those streams, so a
confirmation prompt cannot read/write them without corrupting the protocol.
Instead, `ask` opens the OS terminal device directly (`/dev/tty` on
POSIX, the console on Windows) for the actual y/n exchange, and only
attempts this at all when `mcpseatbelt`'s own stdio look like a real
terminal rather than a pipe. In essentially every real deployment, an
agent client launches `mcpseatbelt` with piped stdio, so this check is
false and `ask` rules fail closed automatically, with no flag required.
See "Limitations" below for the honest version of this story.

## Testing

```bash
npm test
```

The test suite (`vitest`) builds the project, then spawns `mcpseatbelt
wrap` as a real child process wrapping a small real test MCP server
(`test/fixtures/test-server.mjs`, with real `read_file`/`write_file`/
`delete_file` tools that touch the real filesystem), and drives it with a
real `@modelcontextprotocol/sdk` `Client`. It asserts: an allowed call
reaches the real server and returns its real result; a denied call never
reaches the real server (checked via the absence of its filesystem side
effect); an `ask` rule fails closed with no controlling terminal; the
audit log is correctly hash-chained; and `verify-log` detects a
hand-tampered entry.

## Limitations

This is a focused MVP, not a hardened security boundary. Specifically:

- **`ask` is rarely reachable in the primary deployment model.** Since
  agent clients almost always spawn `mcpseatbelt wrap` with fully piped
  stdio (no controlling terminal reachable from this process), `ask`
  rules will in practice almost always resolve to fail-closed deny in
  production use. It is genuinely implemented and tested, but is really
  only interactive when a human runs `mcpseatbelt wrap` directly from a
  real terminal for local testing/debugging. Treat `ask` as "no automatic
  approval" rather than "prompts a human in the loop" for now.
- **Argument matching is intentionally simple.** `when` conditions support
  `equals`/`matches` (regex)/`oneOf` against top-level argument keys only;
  there's no JSONPath, nested-object matching, or numeric range support.
- **No policy hot-reload.** Editing `policy.yaml` requires restarting
  `mcpseatbelt wrap` (i.e. restarting the agent client's connection to it).
- **Only stdio transport.** Both the facade (agent-client-facing) and the
  upstream (real-server-facing) sides use MCP's stdio transport; HTTP/SSE
  MCP servers are not supported.
- **Only `tools/call` is policy-checked.** `resources/*` and `prompts/*`
  requests, if the wrapped server supports them, are passed straight
  through unchecked - only tool calls are in scope for this MVP.
- **The audit log detects tampering, it doesn't prevent it.** Anyone with
  filesystem access to `audit.jsonl` can still truncate the whole file and
  start a fresh, internally-consistent chain from a new genesis; the hash
  chain guarantees *internal* consistency of what's present, not that
  nothing was ever removed wholesale. Ship it to a separate,
  access-controlled sink (e.g. syslog, a WORM bucket) if you need stronger
  guarantees.
- **No signature/identity on audit entries.** The hash chain proves
  entries weren't altered after the fact relative to each other, but
  doesn't cryptographically attest *who* ran `mcpseatbelt` (no signing key).

## License

MIT, see [LICENSE](LICENSE).
