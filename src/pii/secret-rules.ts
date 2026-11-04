/**
 * Secrets that must never reach a model: passwords, BitLocker recovery keys,
 * tokens, private keys. Added 2026-11-04 after the data leak review (IG-2):
 * flexible asset traits, documents and notes carried such values and only the
 * person-PII scan ran on them.
 *
 * Secrets are replaced with a fixed marker, not a token. A token can be turned
 * back into the real value when Claude passes it in a tool argument; a secret
 * must never come back. Redaction does not depend on Presidio, so it also holds
 * when the analyzer is down.
 *
 * Two layers, both edited by hand here (expect few changes):
 *   1. Key names. A value under a key whose words look like a secret is
 *      replaced whole. Flexible asset types name their own trait keys, so the
 *      word lists below are the place to add a new one.
 *   2. Value patterns. Secrets typed into free text or into a generically
 *      named field (notes, content, a trait called "details").
 *
 * Known limits: a secret in an HTML table cell next to a label cell
 * (`<td>Password</td><td>value</td>`) is not caught, and neither is a bare
 * secret with no label or recognisable shape. Over-masking is accepted.
 *
 * This module is side-effect free.
 */

export const REDACTED_SECRET = "[REDACTED: secret]";

/** A single word in a key name that marks the value as a secret. */
const SECRET_WORDS = new Set([
  "password",
  "passwords",
  "passwd",
  "pwd",
  "passphrase",
  "passcode",
  "secret",
  "secrets",
  "token",
  "tokens",
  "otp",
  "totp",
  "seed",
  "credential",
  "credentials",
  "bitlocker",
]);

/** Two words in a row ("recovery key", "api key") that mark the value as a secret. */
const SECRET_WORD_PAIRS: readonly (readonly [string, string])[] = [
  ["recovery", "key"],
  ["recovery", "password"],
  ["private", "key"],
  ["api", "key"],
  ["access", "key"],
  ["secret", "key"],
  ["shared", "key"],
  ["pre", "shared"],
  ["encryption", "key"],
  ["mfa", "code"],
  ["backup", "code"],
  ["backup", "codes"],
  ["security", "answer"],
];

/**
 * A last word that says the key holds a flag, date, id or label about a
 * secret, not the secret itself ("passwordChangedAt", "passwordFolderId").
 */
const NON_VALUE_LAST_WORDS = new Set([
  "at",
  "on",
  "date",
  "time",
  "count",
  "id",
  "ids",
  "url",
  "policy",
  "required",
  "enabled",
  "protected",
  "expires",
  "expiry",
  "age",
  "length",
  "type",
  "status",
  "folder",
  "category",
  "categories",
]);

/** Split a key into lowercase words: `bitlockerRecovery_Key`, `Recovery Key`, `recovery-key`. */
function keyWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((w) => w !== "")
    .map((w) => w.toLowerCase());
}

/** True when the key name says its value is a secret. */
export function isSecretKey(key: string): boolean {
  const words = keyWords(key);
  if (words.length === 0) return false;
  if (NON_VALUE_LAST_WORDS.has(words[words.length - 1])) return false;
  if (words.some((w) => SECRET_WORDS.has(w))) return true;
  return SECRET_WORD_PAIRS.some(([a, b]) => words.some((w, i) => w === a && words[i + 1] === b));
}

/** Words that, followed by `:`, `=` or "is", introduce a secret value in running text. */
const LABEL =
  "(?:password|passwd|pwd|passphrase|passcode|secret|token|otp|api[ _-]?key|access[ _-]?key|private[ _-]?key|recovery[ _-]?(?:key|password)|bitlocker[ _-]?key|pre-?shared[ _-]?key|psk)";

/**
 * Secret shapes found in text. `group` is the capture group holding the
 * secret; the label before it stays readable. Without `group` the whole match
 * is replaced.
 */
export const SECRET_PATTERNS: { re: RegExp; group?: number }[] = [
  // PEM private key block, with or without the END line.
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g },
  // BitLocker recovery key: eight groups of six digits.
  { re: /(?<!\d)\d{6}(?:-\d{6}){7}(?!\d)/g },
  // JSON Web Token.
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g },
  // Well-known token prefixes: AWS access key id, GitHub, Slack, "sk-" API keys.
  { re: /\bAKIA[0-9A-Z]{16}\b/g },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g },
  { re: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  // "Password: value", "recovery key = value", "password is value". Quoted values may hold spaces.
  {
    re: new RegExp(
      `\\b${LABEL}\\b[\\s"'\\]*]{0,3}(?:[:=]|\\bis\\b)[ \\t]*("[^"\\n<]{1,200}"|'[^'\\n<]{1,200}'|[^\\s<"'&;]{1,200})`,
      "gi",
    ),
    group: 1,
  },
];
