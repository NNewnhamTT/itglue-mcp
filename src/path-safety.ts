/**
 * Keeps caller-supplied IDs from steering requests to other IT Glue endpoints.
 *
 * Upstream builds request paths with template strings such as
 * `/configurations/${args.id}`. A string like `../passwords/5?show_password=true`
 * in `id` would be normalised by `fetch` into a request for a password record,
 * which the removed password tools were meant to prevent (review 2026-11-03,
 * item IG-1). Two layers:
 *
 *   1. `invalidPathArgument` refuses non-numeric values for the arguments that
 *      end up in a path (tools/call wrapper in hardening.ts).
 *   2. `assertSafeApiPath` is checked inside the client before any request, so a
 *      new tool or a missed argument cannot reach a password path either.
 */

/** Tool arguments that the handlers put into a request path. IT Glue IDs are numeric. */
export const PATH_ID_ARGUMENTS: readonly string[] = [
  "id",
  "organization_id",
  "document_id",
  "section_id",
  "resource_id",
  "configuration_id",
];

const NUMERIC_ID = /^\d{1,18}$/;

function isNumericId(value: unknown): boolean {
  if (typeof value === "number") return Number.isSafeInteger(value) && value > 0;
  if (typeof value === "string") return NUMERIC_ID.test(value);
  return false;
}

/**
 * Name of the first path argument that is not a plain numeric ID, or undefined.
 * Absent values (undefined, null, 0 and "") are left to the handler: it reports
 * missing arguments itself, and search tools treat a falsy `organization_id` as
 * "no filter". If one of them ever reached a path, `assertSafeApiPath` refuses
 * the empty segment. The value is never returned, so it cannot be echoed.
 */
export function invalidPathArgument(args: Record<string, unknown> | undefined): string | undefined {
  if (!args) return undefined;
  for (const key of PATH_ID_ARGUMENTS) {
    const value = args[key];
    if (value === undefined || value === null || value === 0 || value === "") continue;
    if (!isNumericId(value)) return key;
  }
  return undefined;
}

const PATH_SEGMENT = /^(?:[a-z][a-z0-9_]*|\d{1,18})$/;

/**
 * Throws unless `path` is `/` followed by segments that are lowercase words
 * (letters, digits, underscore) or numbers, and no segment names a password
 * endpoint. Dots, slashes inside a segment, `?`, `#`, `%` and `\` all fail.
 * The query string is added by the client afterwards, so it is not part of `path`.
 */
export function assertSafeApiPath(path: string): void {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error("Refused: unsafe IT Glue request path. Nothing was sent to IT Glue.");
  }
  const segments = path.slice(1).split("/");
  const ok = segments.every((s) => PATH_SEGMENT.test(s) && !s.startsWith("password"));
  if (!ok) {
    throw new Error("Refused: unsafe IT Glue request path. Nothing was sent to IT Glue.");
  }
}
