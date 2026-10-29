/**
 * Audit log and access policy for every tool, without editing the tools.
 *
 * This server registers all tools through one `tools/call` request handler
 * (low-level `Server`, a switch on the tool name). `guardCallTool` wraps that
 * handler, so each call runs as:
 *
 *   policy check -> inner handler -> audit line
 *
 * The guard must be the outermost wrapper (see hardening.ts). It then sees
 * the arguments exactly as Claude sent them (PII tokens, not real values) and
 * the result after masking. A denied call is stopped here, before any token
 * is turned back into a real value.
 *
 * Settings (environment), read by loadGuardConfig:
 *   MCP_AUDIT   on | off (default off). One JSON line per tool call on stderr.
 *   MCP_POLICY  read | write | admin. Default access level for callers without
 *               a role of their own. Unset: no restriction for such callers.
 * A bad value throws, so a typo cannot switch a control off.
 */

import { randomUUID } from "node:crypto";
import {
  collectTokens,
  formatAuditLine,
  summarizeArgs,
  type AuditStatus,
} from "./audit.js";
import { parseAccessLevel, type AccessLevel, type Identity } from "./identity.js";
import { classifyTool, isAllowed } from "./policy.js";
import type { CallToolHandler } from "../hardening.js";

export interface GuardConfig {
  audit: boolean;
  /** Level for callers whose identity has no role. Undefined: unrestricted. */
  defaultLevel?: AccessLevel;
}

type Env = Record<string, string | undefined>;

/** Returns undefined when both controls are off. Throws on a bad setting. */
export function loadGuardConfig(
  env: Env = typeof process !== "undefined" ? process.env : {},
): GuardConfig | undefined {
  const auditRaw = (env.MCP_AUDIT ?? "off").trim().toLowerCase();
  if (auditRaw !== "on" && auditRaw !== "off") throw new Error("MCP_AUDIT must be 'on' or 'off'");

  const policyRaw = env.MCP_POLICY?.trim();
  let defaultLevel: AccessLevel | undefined;
  if (policyRaw) {
    defaultLevel = parseAccessLevel(policyRaw);
    if (!defaultLevel) throw new Error("MCP_POLICY must be 'read', 'write' or 'admin'");
  }

  const audit = auditRaw === "on";
  return audit || defaultLevel ? { audit, defaultLevel } : undefined;
}

export interface GuardOptions {
  identity: Identity;
  config: GuardConfig;
  /** Where audit lines go. Default: stderr. */
  emit?: (line: string) => void;
}

interface ToolResultLike {
  isError?: boolean;
  content?: unknown;
}

function resultBytes(result: unknown): number {
  try {
    return JSON.stringify((result as ToolResultLike | undefined)?.content ?? "").length;
  } catch {
    return 0;
  }
}

function deniedResult(message: string) {
  return { isError: true, content: [{ type: "text" as const, text: message }] };
}

export function guardCallTool(inner: CallToolHandler, opts: GuardOptions): CallToolHandler {
  const { identity, config } = opts;
  const emit = opts.emit ?? ((line: string) => console.error(line));

  return async (request, extra) => {
    const started = performance.now();
    const requestId = randomUUID();
    const name = String(request.params.name);
    const args = request.params.arguments;
    const toolClass = classifyTool(name);

    const enforce = config.defaultLevel !== undefined || identity.role !== undefined;
    const level: AccessLevel = identity.role ?? config.defaultLevel ?? "admin";

    const log = (status: AuditStatus, result: unknown, reason?: string): void => {
      if (!config.audit) return;
      emit(
        formatAuditLine({
          ts: new Date().toISOString(),
          requestId,
          identity,
          tool: name,
          toolClass,
          args: summarizeArgs(args),
          tokens: collectTokens(args),
          status,
          credential: "shared",
          reason,
          ms: Math.round(performance.now() - started),
          bytes: resultBytes(result),
        }),
      );
    };

    if (enforce && !isAllowed(level, name)) {
      const denied = deniedResult(
        `Blocked by access policy: ${name} is a ${toolClass} tool and this caller's access level is "${level}". ` +
          "Nothing was sent to IT Glue.",
      );
      log("denied", denied, `policy:${level}`);
      return denied;
    }

    let result: Awaited<ReturnType<CallToolHandler>>;
    try {
      result = await inner(request, extra);
    } catch (err) {
      log("error", undefined);
      throw err;
    }
    log((result as ToolResultLike | undefined)?.isError ? "error" : "ok", result);
    return result;
  };
}
