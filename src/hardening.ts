/**
 * TekTrendz hardening for the IT Glue MCP server, in one place.
 *
 * Upstream registers every tool through a low-level `Server`: one
 * `tools/list` handler (a literal array) and one `tools/call` handler (a
 * switch on the tool name). `hardenServer` replaces `server.setRequestHandler`
 * on the instance, so the handlers registered afterwards are wrapped without
 * editing upstream code:
 *
 *   tools/call:   guard (audit, access policy) -> removed tools -> PII -> fields/count_only -> upstream
 *   tools/list:   removed tools hidden; fields/count_only added (shaping.ts);
 *                 document card link dropped when PII is on
 *   prompts/list, prompts/get: removed prompts hidden and refused
 *
 * Call it right after `new Server(...)`, before any handler is registered.
 *
 * Removed for good (Nickolas, 2026-10-29): the IT Glue password tools and
 * anything that reaches password records. Password values must never reach a
 * model or a transcript. This is not a setting: it applies in every mode.
 */

import type { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type CallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import { guardCallTool, type GuardConfig } from "./guard/wrap-guard.js";
import { ANONYMOUS, type Identity } from "./guard/identity.js";
import { piiCallTool, stripCardMeta } from "./pii/wrap-server.js";
import { addShapingParams, shapeCallTool } from "./shaping.js";
import type { PiiContext } from "./pii/mask-json.js";

export type CallToolHandler = (
  request: CallToolRequest,
  extra: unknown,
) => Promise<CallToolResult>;

/** Tools that are never listed and never run. */
export const REMOVED_TOOLS: ReadonlySet<string> = new Set(["search_passwords", "get_password"]);

/** Prompts that are never listed and never served. */
export const REMOVED_PROMPTS: ReadonlySet<string> = new Set(["password-audit"]);

/**
 * Attachment tools take a caller-chosen `resource_type`. These values reach
 * password records, so they are refused.
 */
const REMOVED_RESOURCE_TYPES: ReadonlySet<string> = new Set(["passwords", "password"]);

export interface HardeningOptions {
  identity?: Identity;
  guard?: GuardConfig;
  pii?: PiiContext;
  /** Where audit lines go. Default: stderr. */
  emitAudit?: (line: string) => void;
}

function refused(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

/** Refuse removed tools and password resource types before anything reaches IT Glue. */
function removedToolsCallTool(inner: CallToolHandler): CallToolHandler {
  return async (request, extra) => {
    const name = String(request.params.name);
    if (REMOVED_TOOLS.has(name)) {
      return refused(`Unknown tool: ${name}`);
    }
    const resourceType = request.params.arguments?.resource_type;
    if (typeof resourceType === "string" && REMOVED_RESOURCE_TYPES.has(resourceType.trim().toLowerCase())) {
      return refused(
        "Password records are not available through this server. Nothing was sent to IT Glue.",
      );
    }
    return inner(request, extra);
  };
}

type AnyHandler = (request: unknown, extra: unknown) => unknown;

interface ToolDef {
  name: string;
  _meta?: Record<string, unknown>;
}

export function hardenServer(server: Server, options: HardeningOptions = {}): void {
  const original = server.setRequestHandler.bind(server) as unknown as (
    schema: unknown,
    handler: AnyHandler,
  ) => void;
  const identity = options.identity ?? ANONYMOUS;

  (server as unknown as { setRequestHandler: unknown }).setRequestHandler = (
    schema: unknown,
    handler: AnyHandler,
  ) => {
    if (schema === CallToolRequestSchema) {
      // Innermost first. The one applied last is outermost: the guard.
      let wrapped: CallToolHandler = shapeCallTool(handler as CallToolHandler);
      if (options.pii) wrapped = piiCallTool(wrapped, options.pii);
      wrapped = removedToolsCallTool(wrapped);
      if (options.guard) {
        wrapped = guardCallTool(wrapped, {
          identity,
          config: options.guard,
          emit: options.emitAudit,
        });
      }
      return original(schema, wrapped as AnyHandler);
    }

    if (schema === ListToolsRequestSchema) {
      return original(schema, async (request, extra) => {
        const result = (await handler(request, extra)) as { tools: ToolDef[] };
        let tools = result.tools.filter((t) => !REMOVED_TOOLS.has(t.name)).map(addShapingParams);
        if (options.pii) tools = tools.map(stripCardMeta);
        return { ...result, tools };
      });
    }

    if (schema === ListPromptsRequestSchema) {
      return original(schema, async (request, extra) => {
        const result = (await handler(request, extra)) as { prompts: { name: string }[] };
        return { ...result, prompts: result.prompts.filter((p) => !REMOVED_PROMPTS.has(p.name)) };
      });
    }

    if (schema === GetPromptRequestSchema) {
      return original(schema, async (request, extra) => {
        const name = String((request as { params: { name: unknown } }).params.name);
        if (REMOVED_PROMPTS.has(name)) throw new Error(`Unknown prompt: ${name}`);
        return handler(request, extra);
      });
    }

    return original(schema, handler);
  };
}
