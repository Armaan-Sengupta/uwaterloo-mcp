/**
 * Speko inbound SMS Duo passcode provider.
 *
 * Polls Speko's public REST API (`GET /v1/sms/messages`) for an inbound Duo SMS
 * after "Text me" is clicked during WatIAM sign-in.
 *
 * Security invariants:
 * - Never log `SPEKO_API_KEY`, raw SMS bodies, or parsed passcodes (not even truncated).
 * - Never put `SPEKO_API_KEY` in URL query strings; always send via Authorization Bearer header.
 * - Never reuse a message ID once consumed.
 */

import type { DuoPasscodeContext, DuoPasscodeProvider } from "./duoPasscode.js";

const DEFAULT_SPEKO_API_BASE_URL = "https://api.speko.dev";
const DEFAULT_SPEKO_SMS_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_INTERVAL_MS = 5_000;
const DEFAULT_MAX_POLL_INTERVAL_MS = 15_000;
const DEFAULT_PAGE_LIMIT = 50;
const MAX_PAGES_PER_POLL = 5;
const CLOCK_SKEW_LOOKBACK_MS = 2_000;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const E164_RE = /^\+[1-9]\d{6,14}$/;

export interface SpekoSmsMessage {
  id?: unknown;
  message_id?: unknown;
  sid?: unknown;
  direction?: unknown;
  from?: unknown;
  sender?: unknown;
  from_number?: unknown;
  to?: unknown;
  recipient?: unknown;
  to_number?: unknown;
  text?: unknown;
  body?: unknown;
  message?: unknown;
  content?: unknown;
  status?: unknown;
  phone_number_id?: unknown;
  from_phone_number_id?: unknown;
  created_at?: unknown;
  occurred_at?: unknown;
  received_at?: unknown;
  sent_at?: unknown;
  timestamp?: unknown;
}

export interface SpekoDuoPasscodeProviderOptions {
  apiKey?: string | undefined;
  baseUrl?: string | undefined;
  phoneNumber?: string | undefined;
  phoneNumberId?: string | undefined;
  duoSender?: string | undefined;
  timeoutMs?: number | undefined;
  pollIntervalMs?: number | undefined;
  maxPollIntervalMs?: number | undefined;
  consumedIds?: Set<string> | undefined;
  fetch?: typeof globalThis.fetch | undefined;
  sleep?: ((ms: number, signal?: AbortSignal) => Promise<void>) | undefined;
  now?: (() => number) | undefined;
}

type EnvLike = Record<string, string | undefined>;

/** Reads the configured Duo passcode provider name (`DUO_CODE_PROVIDER` or `UWATERLOO_DUO_CODE_PROVIDER`). */
export function getDuoCodeProviderName(env: EnvLike = process.env): string | null {
  const raw = (env.DUO_CODE_PROVIDER ?? env.UWATERLOO_DUO_CODE_PROVIDER)?.trim().toLowerCase();
  return raw || null;
}

/** True when `DUO_CODE_PROVIDER=speko` and `SPEKO_API_KEY` are both set. */
export function isSpekoPasscodeProviderConfigured(env: EnvLike = process.env): boolean {
  return getDuoCodeProviderName(env) === "speko" && Boolean(env.SPEKO_API_KEY?.trim());
}

/** Last 4 digits of the Duo SMS target phone (`DUO_PHONE_LAST4`, default `"9915"`). */
export function getDuoPhoneLast4(env: EnvLike = process.env): string {
  const digits = (env.DUO_PHONE_LAST4 ?? "").replace(/\D/g, "");
  return digits.length >= 4 ? digits.slice(-4) : "9915";
}

/** Maximum automated/interactive Duo SMS requests allowed per America/Toronto day (default 3). */
export function getDuoSmsMaxAttemptsPerDay(env: EnvLike = process.env): number {
  const raw = env.DUO_SMS_MAX_ATTEMPTS_PER_DAY?.trim();
  if (!raw) return 3;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : 3;
}

function parseTimeoutMs(raw: string | undefined): number {
  if (!raw?.trim()) return DEFAULT_SPEKO_SMS_TIMEOUT_MS;
  const parsed = Number.parseInt(raw.trim(), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_SPEKO_SMS_TIMEOUT_MS;
}

function normalizeBaseUrl(raw: string | undefined): string {
  const candidate = (raw?.trim() || DEFAULT_SPEKO_API_BASE_URL).replace(/\/+$/, "");
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error("SPEKO_API_BASE_URL must be a valid http(s) URL.");
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error("SPEKO_API_BASE_URL must use https:// or http://.");
  }
  return candidate;
}

function defaultSleep(ms: number, signal?: AbortSignal): Promise<void> {
  if (ms <= 0 || signal?.aborted) return Promise.resolve();
  return new Promise((resolve) => {
    const onAbort = () => {
      clearTimeout(timer);
      resolve();
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    timer.unref?.();
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

function extractString(value: unknown): string | undefined {
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed || undefined;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return String(value);
  }
  if (value && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return (
      extractString(record.phone_number) ??
      extractString(record.number) ??
      extractString(record.address) ??
      extractString(record.e164)
    );
  }
  return undefined;
}

function extractRecipients(msg: SpekoSmsMessage): string[] {
  const raw = msg.to ?? msg.recipient ?? msg.to_number;
  if (Array.isArray(raw)) {
    return raw.map(extractString).filter((s): s is string => !!s);
  }
  const single = extractString(raw);
  return single ? [single] : [];
}

function extractTimestampMs(msg: SpekoSmsMessage): number | null {
  // Prefer `created_at` when present, else `occurred_at`, then common aliases.
  const candidates = [
    msg.created_at,
    msg.occurred_at,
    msg.received_at,
    msg.sent_at,
    msg.timestamp,
  ];
  for (const candidate of candidates) {
    if (typeof candidate === "number" && Number.isFinite(candidate)) {
      return candidate < 1e12 ? candidate * 1000 : candidate;
    }
    if (typeof candidate === "string" && candidate.trim()) {
      const parsed = Date.parse(candidate.trim());
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
}

function normalizePhoneDigits(value: string): string {
  return value.replace(/\D/g, "");
}

function phonesMatch(a: string, b: string): boolean {
  const da = normalizePhoneDigits(a);
  const db = normalizePhoneDigits(b);
  if (da && db) return da === db;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Matches a message sender (`from`) against `SPEKO_DUO_SENDER` / `DUO_SMS_SENDER`
 * via case-insensitive exact/substring match or trailing digits (>= 4 chars).
 */
export function matchesDuoSender(from: string | undefined, filter: string): boolean {
  const trimmedFilter = filter.trim().toLowerCase();
  if (!trimmedFilter) return true;
  if (!from) return false;

  const normFrom = from.trim().toLowerCase();
  if (normFrom === trimmedFilter || normFrom.includes(trimmedFilter)) {
    return true;
  }

  const digitsFrom = normalizePhoneDigits(normFrom);
  const digitsFilter = normalizePhoneDigits(trimmedFilter);
  if (digitsFilter.length >= 4 && digitsFrom.length >= 4) {
    return digitsFrom.endsWith(digitsFilter) || digitsFilter.endsWith(digitsFrom);
  }
  return false;
}

/**
 * Checks whether an SMS body looks like a Duo verification/passcode message
 * when no explicit sender filter is configured.
 */
export function isDuoSmsText(text: string): boolean {
  if (!text || typeof text !== "string") return false;
  const normalized = text.replace(/[\u00a0\s]+/g, " ").trim();
  if (!normalized) return false;
  if (/\bduo\b/i.test(normalized)) return true;
  if (/\bsms\s+passcodes?\b/i.test(normalized)) return true;
  return /^(?:your\s+)?(?:verification\s+code|passcode)\s*(?:is|:)/i.test(normalized);
}

// Digit-group patterns for 6-7 digit passcodes, avoiding slices of phone numbers (519-555-1234) or dates (2026-11-15).
const CODE_TOKEN_SOURCE =
  "(?<![\\d+-])(?<!\\d\\.)(?<!\\d[\\s-])(" +
  "\\d{6,7}" +
  "|\\d{3}[\\s-]\\d{3,4}" +
  "|\\d{4}[\\s-]\\d{3}" +
  "|\\d(?:[\\s-]\\d){5,6}" +
  ")(?![\\d-])(?!\\.\\d)(?![\\s-]\\d)";

function extractCodeFromMatch(rawToken: string | undefined): string | null {
  if (!rawToken) return null;
  const digits = rawToken.replace(/\D/g, "");
  return digits.length === 6 || digits.length === 7 ? digits : null;
}

/**
 * Extracts a 6–7 digit Duo passcode from an SMS body.
 * Prefers codes adjacent to Duo / verification / passcode wording and rejects
 * unrelated numbers (phone numbers, dates, or messages lacking passcode wording).
 */
export function parseDuoSmsPasscode(text: string): string | null {
  if (!text || typeof text !== "string") return null;
  const normalized = text.replace(/[\u00a0\s]+/g, " ").trim();
  if (!normalized) return null;

  const patterns = [
    // Label immediately followed by code: "Your Duo verification code is 123456", "Passcode: 1234567", "Duo Mobile: 123-456"
    new RegExp(
      `(?:duo(?:\\s+(?:mobile|security))?(?:\\s+verification)?(?:\\s+(?:pass)?code)?|sms\\s+passcodes?|passcodes?|verification\\s+code|security\\s+code|login\\s+code)\\s*(?:is|:|-)?\\s*${CODE_TOKEN_SOURCE}`,
      "i",
    ),
    // Code immediately followed by "is your Duo/verification passcode/code": "123456 is your Duo code"
    new RegExp(
      `${CODE_TOKEN_SOURCE}\\s*(?:is\\s+(?:your\\s+)?)?(?:duo\\s+(?:mobile\\s+)?(?:verification\\s+)?(?:pass)?code|duo\\s+passcode|verification\\s+code|passcode)`,
      "i",
    ),
    // Fallback within a short window of Duo/verification/passcode wording
    new RegExp(
      `(?:duo|passcodes?|verification)\\D{0,40}${CODE_TOKEN_SOURCE}`,
      "i",
    ),
    new RegExp(
      `${CODE_TOKEN_SOURCE}\\D{0,40}(?:duo|passcodes?|verification)`,
      "i",
    ),
  ];

  for (const pattern of patterns) {
    const match = pattern.exec(normalized);
    const code = extractCodeFromMatch(match?.[1]);
    if (code) return code;
  }

  return null;
}

export class SpekoDuoPasscodeProvider implements DuoPasscodeProvider {
  readonly kind = "speko";

  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly fromPhoneNumberId: string | undefined;
  private readonly recipient: string | undefined;
  private readonly duoSender: string | undefined;
  private readonly timeoutMs: number;
  private readonly pollIntervalMs: number;
  private readonly maxPollIntervalMs: number;
  private readonly consumedIds: Set<string>;
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly sleepFn: (ms: number, signal?: AbortSignal) => Promise<void>;
  private readonly nowFn: () => number;

  constructor(options: SpekoDuoPasscodeProviderOptions = {}) {
    this.apiKey = options.apiKey?.trim() ?? "";
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_SPEKO_SMS_TIMEOUT_MS;
    this.pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.maxPollIntervalMs = options.maxPollIntervalMs ?? DEFAULT_MAX_POLL_INTERVAL_MS;
    this.consumedIds = options.consumedIds ?? new Set<string>();
    this.fetchFn = options.fetch ?? globalThis.fetch;
    this.sleepFn = options.sleep ?? defaultSleep;
    this.nowFn = options.now ?? Date.now;
    this.duoSender = options.duoSender?.trim() || undefined;

    const rawPhoneId = options.phoneNumberId?.trim();
    const rawPhone = options.phoneNumber?.trim();

    if (rawPhoneId) {
      this.fromPhoneNumberId = rawPhoneId;
    } else if (rawPhone && UUID_RE.test(rawPhone)) {
      this.fromPhoneNumberId = rawPhone;
    }

    if (rawPhone && E164_RE.test(rawPhone)) {
      this.recipient = rawPhone;
    }
  }

  static fromEnv(
    env: EnvLike = process.env,
    deps: Pick<
      SpekoDuoPasscodeProviderOptions,
      "consumedIds" | "fetch" | "sleep" | "now" | "pollIntervalMs" | "maxPollIntervalMs"
    > = {},
  ): SpekoDuoPasscodeProvider {
    return new SpekoDuoPasscodeProvider({
      apiKey: env.SPEKO_API_KEY,
      baseUrl: env.SPEKO_API_BASE_URL,
      phoneNumber: env.SPEKO_PHONE_NUMBER,
      phoneNumberId: env.SPEKO_PHONE_NUMBER_ID,
      duoSender: env.SPEKO_DUO_SENDER ?? env.DUO_SMS_SENDER,
      timeoutMs: parseTimeoutMs(env.SPEKO_SMS_TIMEOUT_MS),
      ...deps,
    });
  }

  async getPasscode(ctx: DuoPasscodeContext): Promise<string | null> {
    if (!this.apiKey) {
      console.warn("[speko-duo] SPEKO_API_KEY is not configured; cannot poll Speko SMS.");
      return null;
    }
    if (ctx.signal?.aborted) return null;

    const requestedAtMs = ctx.requestedAt ?? this.nowFn();
    const deadline = this.nowFn() + this.timeoutMs;
    console.info("[speko-duo] waiting for SMS passcode");

    let pollAttempt = 0;
    while (!ctx.signal?.aborted) {
      const outcome = await this.pollOnce(requestedAtMs, ctx.signal);
      if (outcome.fatal) return null;
      if (outcome.code) {
        console.info("[speko-duo] received Duo SMS passcode");
        return outcome.code;
      }

      const remaining = deadline - this.nowFn();
      if (remaining <= 0) break;

      const waitMs = Math.min(this.nextDelayMs(pollAttempt), remaining);
      pollAttempt += 1;
      await this.sleepFn(waitMs, ctx.signal);
    }

    if (!ctx.signal?.aborted) {
      console.warn("[speko-duo] timed out waiting for SMS passcode");
    }
    return null;
  }

  private nextDelayMs(attempt: number): number {
    if (attempt <= 0) return this.pollIntervalMs;
    // Mild backoff: 5s, 5s, 7s, 10s, 14s, 15s (cap)
    const scaled = Math.round(this.pollIntervalMs * Math.pow(1.4, attempt - 1));
    return Math.min(this.maxPollIntervalMs, Math.max(this.pollIntervalMs, scaled));
  }

  private buildListUrl(requestedAtMs: number, cursor: string | null): string {
    const url = new URL(`${this.baseUrl}/v1/sms/messages`);
    url.searchParams.set("direction", "inbound");
    url.searchParams.set(
      "created_after",
      new Date(Math.max(0, requestedAtMs - CLOCK_SKEW_LOOKBACK_MS)).toISOString(),
    );
    url.searchParams.set("limit", String(DEFAULT_PAGE_LIMIT));
    if (this.fromPhoneNumberId) {
      url.searchParams.set("from_phone_number_id", this.fromPhoneNumberId);
    }
    if (this.recipient) {
      url.searchParams.set("recipient", this.recipient);
    }
    if (cursor) {
      url.searchParams.set("cursor", cursor);
    }
    return url.toString();
  }

  private async pollOnce(
    requestedAtMs: number,
    signal?: AbortSignal,
  ): Promise<{ code: string | null; fatal?: boolean }> {
    let cursor: string | null = null;

    for (let page = 0; page < MAX_PAGES_PER_POLL; page += 1) {
      if (signal?.aborted) return { code: null };

      const reqSignal = signal
        ? AbortSignal.any([signal, AbortSignal.timeout(15_000)])
        : AbortSignal.timeout(15_000);

      let res: Response;
      try {
        res = await this.fetchFn(this.buildListUrl(requestedAtMs, cursor), {
          method: "GET",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            Accept: "application/json",
          },
          signal: reqSignal,
        });
      } catch (err) {
        if (signal?.aborted) return { code: null };
        console.warn("[speko-duo] Speko API request error", {
          error: err instanceof Error ? err.message : "network error",
        });
        return { code: null };
      }

      if (res.status === 401 || res.status === 403) {
        console.warn("[speko-duo] Speko API rejected credentials", { status: res.status });
        return { code: null, fatal: true };
      }
      if (!res.ok) {
        console.warn("[speko-duo] Speko API returned non-OK status", { status: res.status });
        return { code: null };
      }

      let payload: unknown;
      try {
        payload = await res.json();
      } catch {
        console.warn("[speko-duo] Speko API returned invalid JSON");
        return { code: null };
      }

      const record = payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
      const rawMessages = Array.isArray(record.data)
        ? record.data
        : Array.isArray(record.messages)
          ? record.messages
          : Array.isArray(record.items)
            ? record.items
            : [];

      let sawAtOrBeforeRequest = false;
      for (const item of rawMessages) {
        if (!item || typeof item !== "object") continue;
        const msg = item as SpekoSmsMessage;
        const ts = extractTimestampMs(msg);
        if (ts === null || ts <= requestedAtMs) {
          if (ts !== null && ts <= requestedAtMs) {
            sawAtOrBeforeRequest = true;
          }
          continue;
        }

        const matched = this.matchMessage(msg);
        if (matched) {
          return { code: matched };
        }
      }

      const nextCursor = extractString(record.next_cursor ?? record.nextCursor);
      if (!nextCursor || sawAtOrBeforeRequest) break;
      cursor = nextCursor;
    }

    return { code: null };
  }

  private matchMessage(msg: SpekoSmsMessage): string | null {
    const id = extractString(msg.id ?? msg.message_id ?? msg.sid);
    if (id && this.consumedIds.has(id)) return null;

    const direction = extractString(msg.direction)?.toLowerCase();
    if (direction && direction !== "inbound" && direction !== "incoming") {
      return null;
    }

    if (this.fromPhoneNumberId) {
      const msgPhoneId = extractString(msg.from_phone_number_id ?? msg.phone_number_id);
      if (msgPhoneId && msgPhoneId.toLowerCase() !== this.fromPhoneNumberId.toLowerCase()) {
        return null;
      }
    }

    if (this.recipient) {
      const recipients = extractRecipients(msg);
      if (recipients.length > 0 && !recipients.some((r) => phonesMatch(r, this.recipient!))) {
        return null;
      }
    }

    const from = extractString(msg.from ?? msg.sender ?? msg.from_number);
    const text = extractString(msg.text ?? msg.body ?? msg.message ?? msg.content);
    if (!text) return null;

    if (this.duoSender) {
      if (!matchesDuoSender(from, this.duoSender)) return null;
    } else if (!isDuoSmsText(text)) {
      return null;
    }

    const code = parseDuoSmsPasscode(text);
    if (!code) return null;

    if (id) {
      this.consumedIds.add(id);
      if (this.consumedIds.size > 500) {
        const oldest = this.consumedIds.values().next().value;
        if (oldest !== undefined) this.consumedIds.delete(oldest);
      }
    }
    return code;
  }
}
