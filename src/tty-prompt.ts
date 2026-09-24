import { closeSync, openSync, readSync, writeSync } from "node:fs";
import { isatty } from "node:tty";

/**
 * The seatbelt process's own stdin/stdout are almost always occupied by the
 * MCP JSON-RPC stream to the agent client (or, in tests, to the harness), so
 * an interactive "ask" prompt cannot read/write those streams without
 * corrupting the protocol. Instead we open the controlling terminal device
 * directly, the same trick tools like `sudo`/`ssh` use for password prompts.
 */
function ttyDevicePath(): string {
  return process.platform === "win32" ? "\\\\.\\CONIN$" : "/dev/tty";
}

/**
 * True if this process is plausibly attached to a real interactive terminal
 * rather than being driven by an agent client (or a test harness) over
 * piped stdio.
 *
 * Every real MCP deployment launches mcpseatbelt with `stdio: "pipe"` (that
 * is the whole point of the stdio transport), so `process.stdin`/`stdout`
 * are OS pipes, not TTYs, and this correctly reports `false` there - which is
 * exactly the case that must fail closed. This deliberately does NOT just
 * check for the presence of *any* console on the process (e.g. by opening
 * the raw terminal device), because on Windows a child process can still
 * have an inherited console handle available even while its own stdio
 * handles are redirected pipes; checking the actual stdio fds is the signal
 * that matches "is something other than a protocol pipe driving me".
 */
export function hasControllingTerminal(): boolean {
  return Boolean(process.stdin.isTTY) && Boolean(process.stdout.isTTY);
}

/**
 * Prints `question` to the controlling terminal and reads a single line of
 * y/n input from it. Returns `undefined` if no controlling terminal is
 * available (callers should fail closed in that case) or if the answer
 * couldn't be parsed as yes/no.
 */
export function promptYesNo(question: string): boolean | undefined {
  let fd = -1;
  try {
    fd = openSync(ttyDevicePath(), "r+");
  } catch {
    return undefined;
  }

  try {
    if (!isatty(fd)) return undefined;
    writeSync(fd, question);

    const buf = Buffer.alloc(1024);
    const bytesRead = readSync(fd, buf, 0, buf.length, null);
    const answer = buf.subarray(0, bytesRead).toString("utf8").trim().toLowerCase();

    if (answer === "y" || answer === "yes") return true;
    if (answer === "n" || answer === "no" || answer === "") return false;
    return undefined;
  } catch {
    return undefined;
  } finally {
    try {
      closeSync(fd);
    } catch {
      /* ignore */
    }
  }
}
