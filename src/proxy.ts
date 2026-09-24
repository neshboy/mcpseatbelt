import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ListResourcesRequestSchema,
  ListResourceTemplatesRequestSchema,
  ReadResourceRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

import { findMatchingRule, ruleLabel } from "./policy.js";
import { AuditLog } from "./audit.js";
import { hasControllingTerminal, promptYesNo } from "./tty-prompt.js";
import type { Policy } from "./types.js";

const PACKAGE_NAME = "mcpseatbelt";
const PACKAGE_VERSION = "0.1.0";

export interface RunProxyOptions {
  /** The command used to launch the real, underlying MCP server. */
  command: string;
  /** Arguments for that command. */
  args: string[];
  /** Parsed, validated policy to enforce. */
  policy: Policy;
  /** Path to the append-only audit log (JSONL). */
  auditLogPath: string;
  /** When true, "ask" rules always fail closed without attempting to prompt. */
  nonInteractive?: boolean;
  /** Optional label identifying the wrapped server in audit entries; defaults to the command line. */
  serverLabel?: string;
}

export interface ProxySession {
  /** Cleanly shuts down both the facade server and the upstream client connection. */
  close(): Promise<void>;
}

/**
 * Starts MCP Seatbelt: spawns the wrapped ("upstream") MCP server as a child
 * process and connects to it as a real MCP client over stdio, then exposes a
 * real MCP server facade over *this* process's own stdio for the agent
 * client to connect to. Every `tools/call` request is checked against the
 * policy before (if ever) being forwarded upstream.
 */
export async function startProxy(options: RunProxyOptions): Promise<ProxySession> {
  const { policy } = options;
  const serverLabel = options.serverLabel ?? `${options.command} ${options.args.join(" ")}`.trim();
  const audit = new AuditLog(options.auditLogPath);

  const upstreamTransport = new StdioClientTransport({
    command: options.command,
    args: options.args,
    stderr: "inherit",
  });

  const upstreamClient = new Client(
    { name: `${PACKAGE_NAME}-upstream-client`, version: PACKAGE_VERSION },
    { capabilities: {} },
  );

  await upstreamClient.connect(upstreamTransport);

  const upstreamCaps = upstreamClient.getServerCapabilities() ?? {};

  const facade = new Server(
    { name: PACKAGE_NAME, version: PACKAGE_VERSION },
    {
      capabilities: {
        ...(upstreamCaps.tools ? { tools: upstreamCaps.tools } : {}),
        ...(upstreamCaps.prompts ? { prompts: upstreamCaps.prompts } : {}),
        ...(upstreamCaps.resources ? { resources: upstreamCaps.resources } : {}),
        ...(upstreamCaps.logging ? { logging: upstreamCaps.logging } : {}),
      },
    },
  );

  if (upstreamCaps.tools) {
    facade.setRequestHandler(ListToolsRequestSchema, async (request) => {
      return upstreamClient.listTools(request.params);
    });

    facade.setRequestHandler(CallToolRequestSchema, async (request) => {
      const toolName = request.params.name;
      const args = request.params.arguments;

      const rule = findMatchingRule(policy, toolName, args);
      const action = rule?.action ?? policy.default;
      const label = ruleLabel(rule, policy);

      if (action === "allow") {
        audit.record({ server: serverLabel, tool: toolName, arguments: args, decision: "allow", rule: label });
        return await upstreamClient.callTool(request.params);
      }

      if (action === "deny") {
        audit.record({ server: serverLabel, tool: toolName, arguments: args, decision: "deny", rule: label });
        throw new McpError(ErrorCode.InvalidRequest, `mcpseatbelt: call to "${toolName}" denied by policy rule "${label}"`);
      }

      // action === "ask"
      if (options.nonInteractive || !hasControllingTerminal()) {
        audit.record({
          server: serverLabel,
          tool: toolName,
          arguments: args,
          decision: "ask-deny",
          rule: label,
          reason: "no controlling terminal available; failing closed",
        });
        throw new McpError(
          ErrorCode.InvalidRequest,
          `mcpseatbelt: call to "${toolName}" requires confirmation (rule "${label}") but no interactive terminal is available; denying (fail closed)`,
        );
      }

      const question = `mcpseatbelt: allow call to "${toolName}" with arguments ${safeJson(args)}? [y/N] `;
      const approved = promptYesNo(question);

      if (approved === true) {
        audit.record({ server: serverLabel, tool: toolName, arguments: args, decision: "ask-allow", rule: label });
        return await upstreamClient.callTool(request.params);
      }

      audit.record({
        server: serverLabel,
        tool: toolName,
        arguments: args,
        decision: "ask-deny",
        rule: label,
        reason: approved === undefined ? "no/invalid response" : "declined by operator",
      });
      throw new McpError(ErrorCode.InvalidRequest, `mcpseatbelt: call to "${toolName}" declined (rule "${label}")`);
    });
  }

  if (upstreamCaps.prompts) {
    facade.setRequestHandler(ListPromptsRequestSchema, async (request) => {
      return upstreamClient.listPrompts(request.params);
    });
    facade.setRequestHandler(GetPromptRequestSchema, async (request) => {
      return upstreamClient.getPrompt(request.params);
    });
  }

  if (upstreamCaps.resources) {
    facade.setRequestHandler(ListResourcesRequestSchema, async (request) => {
      return upstreamClient.listResources(request.params);
    });
    facade.setRequestHandler(ListResourceTemplatesRequestSchema, async (request) => {
      return upstreamClient.listResourceTemplates(request.params);
    });
    facade.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      return upstreamClient.readResource(request.params);
    });
  }

  const facadeTransport = new StdioServerTransport();
  await facade.connect(facadeTransport);

  return {
    async close() {
      await facade.close();
      await upstreamClient.close();
    },
  };
}

function safeJson(value: unknown): string {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}
