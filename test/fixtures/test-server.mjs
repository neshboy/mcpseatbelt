#!/usr/bin/env node
// A small, real MCP server used as a test fixture: it actually speaks MCP
// over stdio via the real SDK, and its tools have real filesystem side
// effects (reading/writing/deleting real files), so tests can assert that a
// denied call never reaches this process (no side effect occurs) and an
// allowed call really does.
import { readFileSync, writeFileSync, unlinkSync } from "node:fs";
import { z } from "zod";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

const server = new McpServer({ name: "mcpseatbelt-test-server", version: "0.1.0" });

server.registerTool(
  "read_file",
  {
    description: "Read the contents of a text file.",
    inputSchema: { path: z.string() },
  },
  async ({ path }) => {
    try {
      const text = readFileSync(path, "utf8");
      return { content: [{ type: "text", text }] };
    } catch (err) {
      return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
    }
  },
);

server.registerTool(
  "write_file",
  {
    description: "Write text content to a file, creating or overwriting it.",
    inputSchema: { path: z.string(), content: z.string() },
  },
  async ({ path, content }) => {
    try {
      writeFileSync(path, content, "utf8");
      return { content: [{ type: "text", text: `Wrote ${content.length} bytes to ${path}` }] };
    } catch (err) {
      return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
    }
  },
);

server.registerTool(
  "delete_file",
  {
    description: "Permanently delete a file.",
    inputSchema: { path: z.string() },
  },
  async ({ path }) => {
    try {
      unlinkSync(path);
      return { content: [{ type: "text", text: `Deleted ${path}` }] };
    } catch (err) {
      return { content: [{ type: "text", text: `Error: ${err.message}` }], isError: true };
    }
  },
);

const transport = new StdioServerTransport();
await server.connect(transport);
