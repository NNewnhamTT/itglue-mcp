/**
 * Add PII masking to every tool without editing the tools.
 *
 * `piiCallTool` wraps the one `tools/call` request handler of this server.
 * Each call runs as:
 *
 *   args -> unmask tokens -> inner handler -> mask result
 *
 * It is the one chokepoint for all tools, so a tool added upstream later is
 * covered with no change.
 *
 * Masked output: every text block, `structuredContent`, and the message of a
 * thrown error. `get_document` puts the whole record in `structuredContent`,
 * so that part matters here. The document card payload (`_card`) is removed
 * because the card would show real values to the host; `stripCardMeta` drops
 * the card link from the tool list for the same reason.
 */

import { maskJson, unmaskDeep, type PiiContext } from "./mask-json.js";
import type { CallToolHandler } from "../hardening.js";

interface ToolResult {
  content?: { type: string; text?: string }[];
  structuredContent?: unknown;
  [key: string]: unknown;
}

function looksLikeJson(text: string): boolean {
  const t = text.trimStart();
  return t.startsWith("{") || t.startsWith("[");
}

/**
 * Upstream wraps IT Glue data in `<itglue-data>` markers plus a fixed notice
 * (utils/untrusted-content.ts), so the text is no longer bare JSON. Mask the
 * payload inside the markers with the field rules and keep the frame as is.
 * Closing tags inside the payload are already neutralised upstream, so the
 * last one is the real end.
 */
const UNTRUSTED_FRAME = /^(<itglue-data>\n)([\s\S]*)(\n<\/itglue-data>\n\n[\s\S]*)$/;

async function maskText(text: string, ctx: PiiContext): Promise<string> {
  const framed = UNTRUSTED_FRAME.exec(text);
  if (framed) {
    return framed[1] + (await maskText(framed[2], ctx)) + framed[3];
  }
  if (looksLikeJson(text)) {
    try {
      return JSON.stringify(await maskJson(JSON.parse(text), ctx), null, 2);
    } catch {
      // Not valid JSON after all: treat it as plain text below.
    }
  }
  return (await maskJson(text, ctx)) as string;
}

async function maskResult(result: unknown, ctx: PiiContext): Promise<unknown> {
  if (result === null || typeof result !== "object") return result;
  const r = result as ToolResult;
  const out: ToolResult = { ...r };

  if (Array.isArray(r.content)) {
    out.content = await Promise.all(
      r.content.map(async (block) =>
        block.type === "text" && typeof block.text === "string"
          ? { ...block, text: await maskText(block.text, ctx) }
          : block,
      ),
    );
  }
  if (r.structuredContent !== undefined) {
    const { _card: _dropped, ...rest } = (r.structuredContent ?? {}) as Record<string, unknown>;
    out.structuredContent = await maskJson(rest, ctx);
  }
  return out;
}

export function piiCallTool(inner: CallToolHandler, ctx: PiiContext): CallToolHandler {
  return async (request, extra) => {
    const args = request.params.arguments;
    let callRequest = request;
    if (args !== undefined) {
      const { value, unknownTokens } = await unmaskDeep(args, ctx);
      if (unknownTokens.length > 0) {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text:
                `Unknown or expired PII token(s): ${unknownTokens.join(", ")}. ` +
                "Fetch the record again to get current tokens. The call was not sent to IT Glue.",
            },
          ],
        };
      }
      callRequest = {
        ...request,
        params: { ...request.params, arguments: value as Record<string, unknown> },
      };
    }
    let result: unknown;
    try {
      result = await inner(callRequest, extra);
    } catch (err) {
      // An error message can echo field values. Mask it before the SDK returns it.
      const message = err instanceof Error ? err.message : String(err);
      // No `cause`: the original error carries the unmasked message.
      // eslint-disable-next-line preserve-caught-error
      throw new Error(await maskText(message, ctx));
    }
    return (await maskResult(result, ctx)) as Awaited<ReturnType<CallToolHandler>>;
  };
}

/** Remove the MCP Apps card link from a tool definition: the card cannot show masked data. */
export function stripCardMeta<T extends { _meta?: Record<string, unknown> }>(tool: T): T {
  const meta = tool._meta;
  if (!meta) return tool;
  const { ui: _ui, "ui/resourceUri": _uri, ...rest } = meta;
  const out = { ...tool };
  if (Object.keys(rest).length > 0) out._meta = rest;
  else delete out._meta;
  return out;
}
