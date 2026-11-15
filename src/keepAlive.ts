/**
 * Automated keep-alive service for UWaterloo Learn.
 *
 * Brightspace session cookies expire after 180 minutes of inactivity. Pinging Learn periodically
 * (every 45 minutes) keeps the sliding window alive so the session stays valid.
 *
 * Security & Duo safeguards:
 * - Background/silent keep-alive NEVER triggers Duo Push or interactive MFA prompts.
 * - Every failed attempt records `lastAttemptAt` and applies exponential backoff.
 * - After consecutive failures reach `MAX_CONSECUTIVE_FAILURES`, or immediately on
 *   `duo_required`, `keepAlive` is disabled until the user completes `/setup`.
 * - On `invalid_credentials`, saved WatIAM credentials are cleared and `keepAlive` is disabled.
 */

import type { Config } from "./config.js";
import { D2LClient } from "./d2l/client.js";
import {
  type SessionRecord,
  sessionStore,
  storedWaterlooCredentials,
  syncSession,
} from "./sessionStore.js";
import {
  type WaterlooLoginOptions,
  type WaterlooLoginResult,
  WaterlooLoginError,
  signInUWaterloo,
} from "./waterlooLogin.js";

export const KEEP_ALIVE_INTERVAL_MS = 45 * 60_000; // 45 minutes
export const INITIAL_BACKOFF_MS = 5 * 60_000; // 5 minutes after first failure
export const MAX_CONSECUTIVE_FAILURES = 3;

export interface PingResult {
  ok: boolean;
  message: string;
  who?: string;
  reauthenticated?: boolean;
  disabledKeepAlive?: boolean;
  errorCode?: string;
}

export interface KeepAliveDeps {
  now?: () => number;
  checkSession?: (
    host: string,
    cookie: string,
  ) => Promise<{ alive: true; who: string } | { alive: false; reason: string }>;
  silentSignIn?: (
    credentials: NonNullable<SessionRecord["waterloo"]>,
    host: string,
    options?: WaterlooLoginOptions,
  ) => Promise<WaterlooLoginResult>;
}

const inFlightPings = new WeakMap<Config, Promise<PingResult>>();

/** Exponential backoff delay in ms for `consecutiveFailures` >= 1. */
export function computeBackoffMs(consecutiveFailures: number): number {
  if (consecutiveFailures <= 0) return 0;
  return Math.min(
    KEEP_ALIVE_INTERVAL_MS,
    INITIAL_BACKOFF_MS * Math.pow(2, consecutiveFailures - 1),
  );
}

/**
 * Returns true if keep-alive is enabled, hasn't hit the failure cap, and enough time has
 * passed since the last ping/attempt (respecting exponential backoff on failure).
 */
export function isKeepAliveDue(
  record: Pick<
    SessionRecord,
    "keepAlive" | "lastPingAt" | "lastAttemptAt" | "consecutiveFailures"
  > | null | undefined,
  now = Date.now(),
): boolean {
  if (!record?.keepAlive) return false;

  const failures = record.consecutiveFailures ?? 0;
  if (failures >= MAX_CONSECUTIVE_FAILURES) return false;

  if (failures > 0) {
    const lastAttempt = record.lastAttemptAt ?? record.lastPingAt ?? 0;
    return now - lastAttempt >= computeBackoffMs(failures);
  }

  const lastActivity = Math.max(record.lastPingAt ?? 0, record.lastAttemptAt ?? 0);
  return now - lastActivity >= KEEP_ALIVE_INTERVAL_MS;
}

async function defaultCheckSession(
  host: string,
  cookie: string,
): Promise<{ alive: true; who: string } | { alive: false; reason: string }> {
  const client = new D2LClient({ host, cookie, csrfToken: undefined });
  const status = await client.sessionStatus();
  if (!status.alive) return { alive: false, reason: status.reason };
  return { alive: true, who: `${status.user.FirstName} ${status.user.LastName}` };
}

/**
 * Pings the live Learn session or attempts silent trusted-browser re-authentication if it
 * expired. Never sends Duo Push notifications or prompts for MFA passcodes.
 */
export async function pingLearnSession(
  config: Config,
  deps?: KeepAliveDeps,
): Promise<PingResult> {
  if (!deps) {
    const existing = inFlightPings.get(config);
    if (existing) return existing;
    const promise = executePing(config).finally(() => {
      inFlightPings.delete(config);
    });
    inFlightPings.set(config, promise);
    return promise;
  }
  return executePing(config, deps);
}

async function executePing(
  config: Config,
  deps: KeepAliveDeps = {},
): Promise<PingResult> {
  const now = deps.now ?? Date.now;
  const checkSession = deps.checkSession ?? defaultCheckSession;
  const silentSignIn = deps.silentSignIn ?? signInUWaterloo;

  await syncSession(config);
  const store = sessionStore(config);
  const record = await store.current();
  const creds = await storedWaterlooCredentials(config);

  if (!config.d2l && !(record?.keepAlive && creds && record?.browserCookies)) {
    return { ok: false, message: "No Learn session has been established yet." };
  }

  let status: { alive: true; who: string } | { alive: false; reason: string };
  if (config.d2l) {
    status = await checkSession(config.d2l.host, config.d2l.cookie);
    if (status.alive) {
      const ts = now();
      await store.update({
        lastPingAt: ts,
        lastAttemptAt: ts,
        consecutiveFailures: 0,
        lastPingError: undefined,
      });
      return {
        ok: true,
        who: status.who,
        message: `Session verified active for ${status.who}. Sliding 3-hour window refreshed.`,
      };
    }
  } else {
    status = { alive: false, reason: "Learn session cookie is missing." };
  }

  // Session has lapsed: try strictly silent trusted-browser sign-in if credentials & cookies exist
  if (creds && record?.browserCookies) {
    console.info("[keep-alive] Session expired; attempting silent re-authentication...");
    try {
      const login = await silentSignIn(creds, config.d2lHost, {
        mode: "silent",
        browserCookies: record.browserCookies,
      });
      const newStatus = await checkSession(config.d2lHost, login.cookie);
      if (newStatus.alive) {
        const ts = now();
        config.d2l = { host: config.d2lHost, cookie: login.cookie, csrfToken: undefined };
        process.env.D2L_COOKIE = login.cookie;
        await store.update({
          cookie: login.cookie,
          browserCookies: login.browserCookies,
          lastPingAt: ts,
          lastAttemptAt: ts,
          consecutiveFailures: 0,
          lastPingError: undefined,
        });
        return {
          ok: true,
          who: newStatus.who,
          reauthenticated: true,
          message: `Session expired and was automatically restored for ${newStatus.who}.`,
        };
      }

      const ts = now();
      const nextFailures = (record.consecutiveFailures ?? 0) + 1;
      const disable = record.keepAlive ? nextFailures >= MAX_CONSECUTIVE_FAILURES : false;
      const reason = `Re-login returned an unusable session: ${newStatus.reason}`;
      await store.update({
        lastAttemptAt: ts,
        consecutiveFailures: nextFailures,
        lastPingError: reason,
        ...(disable ? { keepAlive: false } : {}),
      });
      return {
        ok: false,
        disabledKeepAlive: disable,
        message: reason,
      };
    } catch (err) {
      const ts = now();
      const nextFailures = (record.consecutiveFailures ?? 0) + 1;
      const code = err instanceof WaterlooLoginError ? err.code : undefined;
      const rawMessage = err instanceof Error ? err.message : String(err);

      if (code === "invalid_credentials") {
        config.waterloo = null;
        const message =
          "Saved WatIAM credentials were rejected; saved credentials were deleted and keep-alive was disabled. Sign in again via /setup.";
        await store.update({
          waterloo: undefined,
          keepAlive: false,
          lastAttemptAt: ts,
          consecutiveFailures: nextFailures,
          lastPingError: message,
        });
        console.warn("[keep-alive] Dropped saved WatIAM credentials after invalid_credentials.");
        return {
          ok: false,
          disabledKeepAlive: true,
          errorCode: code,
          message,
        };
      }

      if (code === "duo_required" || code === "duo_denied") {
        const message =
          "Silent re-login requires interactive Duo MFA. Complete sign-in via /setup (passcode flow) to re-enable keep-alive.";
        await store.update({
          keepAlive: false,
          lastAttemptAt: ts,
          consecutiveFailures: nextFailures,
          lastPingError: message,
        });
        console.warn(`[keep-alive] Disabled keep-alive (${code}): interactive /setup required.`);
        return {
          ok: false,
          disabledKeepAlive: true,
          errorCode: code,
          message,
        };
      }

      const disable = record.keepAlive ? nextFailures >= MAX_CONSECUTIVE_FAILURES : false;
      await store.update({
        lastAttemptAt: ts,
        consecutiveFailures: nextFailures,
        lastPingError: rawMessage,
        ...(disable ? { keepAlive: false } : {}),
      });
      console.warn(`[keep-alive] Silent re-login failed (attempt ${nextFailures}/${MAX_CONSECUTIVE_FAILURES}):`, rawMessage);
      return {
        ok: false,
        disabledKeepAlive: disable,
        ...(code ? { errorCode: code } : {}),
        message: disable
          ? `${rawMessage} Keep-alive disabled after ${nextFailures} consecutive failures.`
          : rawMessage,
      };
    }
  }

  // Session lapsed without automated re-login capability: still record attempt & backoff
  const ts = now();
  const nextFailures = (record?.consecutiveFailures ?? 0) + 1;
  const disable = record?.keepAlive ? nextFailures >= MAX_CONSECUTIVE_FAILURES : false;
  await store.update({
    lastAttemptAt: ts,
    consecutiveFailures: nextFailures,
    lastPingError: status.reason,
    ...(disable ? { keepAlive: false } : {}),
  });

  return {
    ok: false,
    disabledKeepAlive: disable,
    message: disable
      ? `${status.reason} Keep-alive disabled after ${nextFailures} consecutive failures.`
      : status.reason,
  };
}

/**
 * Called before authenticated MCP requests so serverless deployments can refresh or silently
 * re-authenticate expired sessions when Keep Signed In is enabled and backoff allows it.
 */
export async function ensureKeepAliveOnRequest(config: Config): Promise<void> {
  await syncSession(config);
  const store = sessionStore(config);
  const record = await store.current();
  if (!config.d2l && !(record?.keepAlive && (await storedWaterlooCredentials(config)) && record?.browserCookies)) {
    return;
  }

  if (isKeepAliveDue(record)) {
    await pingLearnSession(config).catch((err) => {
      console.warn("[keep-alive] On-request refresh error:", err);
    });
  }
}

/** Background interval runner for long-running processes (Node / Docker). */
export function startKeepAliveRunner(config: Config): () => void {
  const store = sessionStore(config);

  const timer = setInterval(async () => {
    try {
      await syncSession(config);
      const record = await store.current();
      if (!record?.keepAlive) return;
      if (!config.d2l && !((await storedWaterlooCredentials(config)) && record?.browserCookies)) {
        return;
      }

      if (isKeepAliveDue(record)) {
        console.info("[keep-alive] Scheduled session ping starting...");
        const result = await pingLearnSession(config);
        console.info("[keep-alive] Ping result:", result.message);
      }
    } catch (err) {
      console.warn("[keep-alive] Scheduled ping error:", err);
    }
  }, 60_000);

  timer.unref?.();
  return () => clearInterval(timer);
}
