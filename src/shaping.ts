/**
 * Smaller tool results: `fields` and `count_only`.
 *
 * The IT Glue API documents no sparse fieldsets and no count endpoints
 * (developer docs, read 2026-10-29). Both are done here, on the server's own
 * result, before it reaches the model:
 *
 * - `fields`: comma-separated attribute names, as they appear in results
 *   (camelCase, e.g. `name,hostname,configurationTypeName`). `id` and `type`
 *   are always kept. `traits.<key>` keeps one flexible asset trait. IT Glue
 *   still sends whole records; only the model's copy is trimmed.
 * - `count_only`: the search runs with page size 1 and only
 *   `{ "count": meta.totalCount }` is returned, plus any note the tool added
 *   (for example the account-wide search warning). IT Glue sends
 *   `meta.total-count` on list responses (seen live 2026-10-29).
 *
 * `shapeCallTool` wraps the upstream `tools/call` handler (innermost, so PII
 * masking still applies to what is left). `addShapingParams` adds the two
 * parameters to the tool list. Upstream ignores unknown arguments, but both
 * are removed before the call anyway.
 */

import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import type { CallToolHandler } from "./hardening.js";

/** Tools that take `fields`. Each returns JSON records in its text. */
export const FIELDS_TOOLS: ReadonlySet<string> = new Set([
  "search_organizations",
  "search_configurations",
  "search_locations",
  "search_documents",
  "search_flexible_assets",
  "search_user_metrics",
  "list_flexible_asset_types",
  "list_document_folders",
  "list_attachments",
  "get_organization",
  "get_configuration",
  "get_location",
]);

/**
 * Tools that take `count_only`. search_documents is left out: it filters by
 * name on the client side and can fall back to a different listing, so its
 * meta count does not always match what the search would return.
 */
export const COUNT_TOOLS: ReadonlySet<string> = new Set([
  "search_organizations",
  "search_configurations",
  "search_locations",
  "search_flexible_assets",
  "search_user_metrics",
]);

const FIELD_NAME = /^[A-Za-z0-9_-]+(\.[A-Za-z0-9 _-]+)?$/;
const MAX_FIELDS = 50;
const ALWAYS_KEPT = ["id", "type"];

function refused(text: string): CallToolResult {
  return { isError: true, content: [{ type: "text", text }] };
}

/** Parse `fields`. Returns the names, or an error message. */
export function parseFields(value: unknown): { names: string[] } | { error: string } {
  if (typeof value !== "string") return { error: "fields must be a comma-separated string" };
  const names = [...new Set(value.split(",").map((f) => f.trim()).filter(Boolean))];
  if (names.length === 0) return { error: "fields is empty" };
  if (names.length > MAX_FIELDS) return { error: `fields may list at most ${MAX_FIELDS} names` };
  const bad = names.filter((n) => !FIELD_NAME.test(n));
  if (bad.length > 0) return { error: `fields has invalid names: ${bad.slice(0, 5).join(", ")}` };
  return { names };
}

// ---------------------------------------------------------------------------
// Tool text: [<itglue-data> frame] [notes "\n\n"] JSON
// ---------------------------------------------------------------------------

const UNTRUSTED_FRAME = /^(<itglue-data>\n)([\s\S]*)(\n<\/itglue-data>\n\n[\s\S]*)$/;

interface ParsedText {
  /** Notes the tool put before the JSON, joined. Empty when none. */
  note: string;
  json: unknown;
  /** Rebuild the text with new JSON, keeping the frame and the notes. */
  rebuild: (json: unknown, note?: string) => string;
}

export function parseToolText(text: string): ParsedText | null {
  const framed = UNTRUSTED_FRAME.exec(text);
  if (framed) {
    const inner = parseToolText(framed[2]);
    if (!inner) return null;
    return {
      note: inner.note,
      json: inner.json,
      rebuild: (json, note) => framed[1] + inner.rebuild(json, note) + framed[3],
    };
  }
  const trimmed = text.trimStart();
  let note = "";
  let body = text;
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    // Notes come first, separated by a blank line. The JSON is the last block.
    const at = Math.max(text.lastIndexOf("\n\n{"), text.lastIndexOf("\n\n["));
    if (at < 0) return null;
    note = text.slice(0, at);
    body = text.slice(at + 2);
  }
  let json: unknown;
  try {
    json = JSON.parse(body);
  } catch {
    return null;
  }
  return {
    note,
    json,
    rebuild: (newJson, newNote = note) =>
      [newNote, JSON.stringify(newJson, null, 2)].filter(Boolean).join("\n\n"),
  };
}

// ---------------------------------------------------------------------------
// fields
// ---------------------------------------------------------------------------

type Rec = Record<string, unknown>;

function isRecord(v: unknown): v is Rec {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function projectRecord(record: Rec, names: string[], found: Set<string>): Rec {
  const out: Rec = {};
  for (const k of ALWAYS_KEPT) if (k in record) out[k] = record[k];
  for (const name of names) {
    const dot = name.indexOf(".");
    if (dot < 0) {
      if (name in record) {
        out[name] = record[name];
        found.add(name);
      }
      continue;
    }
    const parent = name.slice(0, dot);
    const child = name.slice(dot + 1);
    const nested = record[parent];
    if (isRecord(nested) && child in nested) {
      const target = (isRecord(out[parent]) ? out[parent] : (out[parent] = {})) as Rec;
      target[child] = nested[child];
      found.add(name);
    }
  }
  return out;
}

/**
 * Keep only the named fields in every record of a tool's JSON. Records are
 * found in `data` (list or single), a bare array, or a bare record. Other keys
 * of the envelope (`meta`, notes) are kept. Names that matched no record are
 * listed in `fieldsNotFound`, so a typo is visible.
 */
export function projectFields(json: unknown, names: string[]): unknown {
  const found = new Set<string>();
  let out: unknown;
  if (isRecord(json) && Array.isArray(json.data)) {
    out = { ...json, data: json.data.map((r) => (isRecord(r) ? projectRecord(r, names, found) : r)) };
  } else if (isRecord(json) && isRecord(json.data)) {
    out = { ...json, data: projectRecord(json.data, names, found) };
  } else if (Array.isArray(json)) {
    out = json.map((r) => (isRecord(r) ? projectRecord(r, names, found) : r));
  } else if (isRecord(json)) {
    out = projectRecord(json, names, found);
  } else {
    return json;
  }
  const missing = names.filter((n) => !found.has(n));
  if (missing.length > 0 && isRecord(out)) return { ...out, fieldsNotFound: missing };
  if (missing.length > 0 && Array.isArray(out)) return { data: out, fieldsNotFound: missing };
  return out;
}

// ---------------------------------------------------------------------------
// Handler wrapper and tool list
// ---------------------------------------------------------------------------

export function shapeCallTool(inner: CallToolHandler): CallToolHandler {
  return async (request, extra) => {
    const name = String(request.params.name);
    const args = request.params.arguments;
    if (!args || (!("fields" in args) && !("count_only" in args))) return inner(request, extra);

    const { fields, count_only: countOnly, ...rest } = args;
    let names: string[] | undefined;
    if (fields !== undefined && fields !== "") {
      if (!FIELDS_TOOLS.has(name)) return refused(`${name} does not take fields. Nothing was sent to IT Glue.`);
      const parsed = parseFields(fields);
      if ("error" in parsed) return refused(`${parsed.error}. Nothing was sent to IT Glue.`);
      names = parsed.names;
    }
    // A client with a stale tool list does not know count_only is a boolean and
    // sends the string "true" (seen live 2026-10-29). Accept both spellings.
    const flag = typeof countOnly === "string" ? countOnly.trim().toLowerCase() : countOnly;
    const counting = flag === true || flag === "true";
    if (flag !== undefined && flag !== false && flag !== "false" && !counting) {
      return refused("count_only must be true or false. Nothing was sent to IT Glue.");
    }
    if (counting && !COUNT_TOOLS.has(name)) {
      return refused(`${name} does not take count_only. Nothing was sent to IT Glue.`);
    }

    const callArgs: Record<string, unknown> = counting ? { ...rest, page_size: 1, page_number: 1 } : rest;
    const result = await inner({ ...request, params: { ...request.params, arguments: callArgs } }, extra);
    if (result.isError || (!names && !counting)) return result;

    const block = result.content?.[0];
    if (!block || block.type !== "text") return result;
    const parsed = parseToolText(block.text);
    if (!parsed) {
      // Not JSON (for example an "organizations match" question). Never return
      // the untrimmed record set when the caller asked for less.
      return counting
        ? refused(`Could not count: ${name} did not return a list. Its message was:\n\n${block.text}`)
        : result;
    }

    let text: string;
    if (counting) {
      const total = isRecord(parsed.json) && isRecord(parsed.json.meta) ? parsed.json.meta.totalCount : undefined;
      if (typeof total !== "number") {
        return refused(`Could not count: IT Glue returned no total for ${name}.`);
      }
      text = parsed.rebuild({ count: total });
    } else {
      text = parsed.rebuild(projectFields(parsed.json, names!));
    }
    return { ...result, content: [{ ...block, text }, ...(result.content?.slice(1) ?? [])] };
  };
}

interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: { properties?: Record<string, unknown>; [k: string]: unknown };
}

const FIELDS_SCHEMA = {
  type: "string",
  description:
    "Optional. Comma-separated attribute names to return, as they appear in results (camelCase), " +
    "e.g. 'name,hostname,configurationTypeName,organizationName'. id and type are always returned. " +
    "Use traits.<key> for one flexible asset trait. Use this to keep large results small; names that " +
    "match nothing are listed in fieldsNotFound.",
};

const COUNT_SCHEMA = {
  type: "boolean",
  description:
    "Optional. true returns only {\"count\": N} for the same filters (no records). Use it to size a search before paging.",
};

export function addShapingParams<T extends ToolDef>(tool: T): T {
  const fields = FIELDS_TOOLS.has(tool.name);
  const count = COUNT_TOOLS.has(tool.name);
  if (!fields && !count) return tool;
  const schema = tool.inputSchema ?? { type: "object" };
  return {
    ...tool,
    inputSchema: {
      ...schema,
      properties: {
        ...(schema.properties ?? {}),
        ...(fields ? { fields: FIELDS_SCHEMA } : {}),
        ...(count ? { count_only: COUNT_SCHEMA } : {}),
      },
    },
  };
}
