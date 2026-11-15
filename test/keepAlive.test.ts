import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { Config } from "../src/config.js";
import {
  INITIAL_BACKOFF_MS,
  KEEP_ALIVE_INTERVAL_MS,
  MAX_CONSECUTIVE_FAILURES,
  computeBackoffMs,
  isKeepAliveDue,
  pingLearnSession,
} from "../src/keepAlive.js";
import {
  canRequestDuoSms,
  getDailySmsAttemptCount,
  nextDailySmsAttempts,
  sessionStore,
  torontoDayKey,
} from "../src/sessionStore.js";
import { WaterlooLoginError } from "../src/waterlooLogin.js";

function makeConfig(): Config {
  return {
    port: 8787,
    host: "127.0.0.1",
    trustProxy: false,
    trustPlatformHost: false,
    authToken: "keep-alive-test-token-24chars",
    cronSecret: null,
    sessionEncryptionKey: "keep-alive-enc-key-24chars",
    publicUrl: null,
    allowedOrigins: [],
    allowedHosts: [],
    d2lHost: "https://learn.uwaterloo.ca",
    d2l: { host: "https://learn.uwaterloo.ca", cookie: "d2lSessionVal=expired" },
    waterloo: null,
    piazza: null,
    crowdmarkHost: "https://app.crowdmark.com",
    crowdmark: null,
  };
}

async function withTempDataDir(fn: () => Promise<void>): Promise<void> {
  const dir = await mkdtemp(path.join(tmpdir(), "uwmcp-ka-"));
  const orig = process.env.DATA_DIR;
  process.env.DATA_DIR = dir;
  try {
    await fn();
  } finally {
    if (orig === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = orig;
    await rm(dir, { recursive: true, force: true });
  }
}

test("computeBackoffMs doubles up to KEEP_ALIVE_INTERVAL_MS and isKeepAliveDue honors failure cap", () => {
  assert.equal(computeBackoffMs(0), 0);
  assert.equal(computeBackoffMs(1), INITIAL_BACKOFF_MS);
  assert.equal(computeBackoffMs(2), INITIAL_BACKOFF_MS * 2);

  const now = 1_000_000_000;
  assert.equal(
    isKeepAliveDue({ keepAlive: true, lastPingAt: now - KEEP_ALIVE_INTERVAL_MS + 1000 }, now),
    false,
  );
  assert.equal(
    isKeepAliveDue({ keepAlive: true, lastPingAt: now - KEEP_ALIVE_INTERVAL_MS }, now),
    true,
  );

  // Backoff after 1 failure: not due after 1 minute, due after INITIAL_BACKOFF_MS
  assert.equal(
    isKeepAliveDue(
      { keepAlive: true, lastAttemptAt: now - 60_000, consecutiveFailures: 1 },
      now,
    ),
    false,
  );
  assert.equal(
    isKeepAliveDue(
      { keepAlive: true, lastAttemptAt: now - INITIAL_BACKOFF_MS, consecutiveFailures: 1 },
      now,
    ),
    true,
  );

  // Disabled once consecutiveFailures reaches MAX_CONSECUTIVE_FAILURES
  assert.equal(
    isKeepAliveDue(
      { keepAlive: true, lastAttemptAt: 0, consecutiveFailures: MAX_CONSECUTIVE_FAILURES },
      now,
    ),
    false,
  );
});

test("pingLearnSession invokes signInUWaterloo strictly in silent mode and disables keep-alive on duo_required", async () => {
  await withTempDataDir(async () => {
    const config = makeConfig();
    const store = sessionStore(config);
    await store.update({
      cookie: "d2lSessionVal=expired",
      keepAlive: true,
      waterloo: { username: "jdoe@uwaterloo.ca", password: "pw" },
      browserCookies: [
        {
          name: "duo",
          value: "1",
          domain: "duosecurity.com",
          path: "/",
          expires: -1,
          httpOnly: true,
          secure: true,
        },
      ],
    });

    let seenMode: string | undefined;
    let seenProvider: unknown;
    const nowMs = 1_700_000_000_000;

    const result = await pingLearnSession(config, {
      now: () => nowMs,
      checkSession: async () => ({ alive: false, reason: "Session expired." }),
      silentSignIn: async (_creds, _host, opts) => {
        seenMode = opts?.mode;
        seenProvider = opts?.passcodeProvider;
        throw new WaterlooLoginError("duo_required", "Interactive Duo MFA required.");
      },
    });

    assert.equal(seenMode, "silent");
    assert.equal(seenProvider, undefined);
    assert.equal(result.ok, false);
    assert.equal(result.disabledKeepAlive, true);
    assert.equal(result.errorCode, "duo_required");

    const updated = await store.current(true);
    assert.equal(updated?.keepAlive, false);
    assert.equal(updated?.lastAttemptAt, nowMs);
    assert.equal(updated?.consecutiveFailures, 1);
  });
});

test("pingLearnSession drops saved WatIAM credentials and disables keep-alive on invalid_credentials", async () => {
  await withTempDataDir(async () => {
    const config = makeConfig();
    const store = sessionStore(config);
    await store.update({
      cookie: "d2lSessionVal=expired",
      keepAlive: true,
      waterloo: { username: "jdoe@uwaterloo.ca", password: "wrong" },
      browserCookies: [],
    });

    const result = await pingLearnSession(config, {
      now: () => 5000,
      checkSession: async () => ({ alive: false, reason: "Expired" }),
      silentSignIn: async () => {
        throw new WaterlooLoginError("invalid_credentials", "Bad password");
      },
    });

    assert.equal(result.ok, false);
    assert.equal(result.disabledKeepAlive, true);
    assert.equal(result.errorCode, "invalid_credentials");

    const updated = await store.current(true);
    assert.equal(updated?.keepAlive, false);
    assert.equal(updated?.waterloo, undefined);
    assert.equal(updated?.lastAttemptAt, 5000);
  });
});

test("pingLearnSession disables keep-alive after MAX_CONSECUTIVE_FAILURES and resets on success", async () => {
  await withTempDataDir(async () => {
    const config = makeConfig();
    const store = sessionStore(config);
    await store.update({ cookie: "d2lSessionVal=stale", keepAlive: true });

    for (let i = 1; i <= MAX_CONSECUTIVE_FAILURES; i++) {
      const res = await pingLearnSession(config, {
        now: () => i * 10_000,
        checkSession: async () => ({ alive: false, reason: "Transient failure" }),
      });
      const rec = await store.current(true);
      assert.equal(rec?.lastAttemptAt, i * 10_000);
      assert.equal(rec?.consecutiveFailures, i);
      assert.equal(res.disabledKeepAlive, i === MAX_CONSECUTIVE_FAILURES);
      assert.equal(rec?.keepAlive, i < MAX_CONSECUTIVE_FAILURES);
    }

    // Re-enabling and succeeding resets consecutiveFailures to 0
    await store.update({ keepAlive: true });
    const ok = await pingLearnSession(config, {
      now: () => 999_000,
      checkSession: async () => ({ alive: true, who: "Jane Doe" }),
    });
    assert.equal(ok.ok, true);
    const rec = await store.current(true);
    assert.equal(rec?.consecutiveFailures, 0);
    assert.equal(rec?.lastPingAt, 999_000);
    assert.equal(rec?.lastPingError, undefined);
  });
});

test("daily Duo SMS attempt cap enforces 3/day in America/Toronto and resets next calendar day", () => {
  // 2026-11-15T20:00:00-05:00 (America/Toronto)
  const day1 = Date.parse("2026-11-16T01:00:00.000Z");
  // 2026-11-16T00:05:00-05:00 (America/Toronto)
  const day2 = Date.parse("2026-11-16T05:05:00.000Z");

  assert.equal(torontoDayKey(day1), "2026-11-15");
  assert.equal(torontoDayKey(day2), "2026-11-16");

  let attempts = undefined;
  assert.equal(canRequestDuoSms({ duoSmsAttempts: attempts }, 3, day1), true);
  assert.equal(getDailySmsAttemptCount({ duoSmsAttempts: attempts }, day1), 0);

  attempts = nextDailySmsAttempts(attempts, day1);
  attempts = nextDailySmsAttempts(attempts, day1);
  assert.equal(canRequestDuoSms({ duoSmsAttempts: attempts }, 3, day1), true);

  attempts = nextDailySmsAttempts(attempts, day1);
  assert.deepEqual(attempts, { day: "2026-11-15", count: 3 });
  assert.equal(canRequestDuoSms({ duoSmsAttempts: attempts }, 3, day1), false);

  // Next America/Toronto calendar day resets available quota
  assert.equal(getDailySmsAttemptCount({ duoSmsAttempts: attempts }, day2), 0);
  assert.equal(canRequestDuoSms({ duoSmsAttempts: attempts }, 3, day2), true);
});

test("pingLearnSession uses automatic mode with Speko configured, enforces daily SMS cap, and resumes next day", async () => {
  await withTempDataDir(async () => {
    const config = makeConfig();
    const store = sessionStore(config);
    const day1 = Date.parse("2026-11-16T01:00:00.000Z"); // 2026-11-15 in Toronto
    const day2 = Date.parse("2026-11-16T05:05:00.000Z"); // 2026-11-16 in Toronto

    await store.update({
      cookie: "d2lSessionVal=expired",
      keepAlive: true,
      waterloo: { username: "jdoe@uwaterloo.ca", password: "pw" },
      browserCookies: [],
      duoSmsAttempts: { day: torontoDayKey(day1), count: 2 },
    });

    let seenMode: string | undefined;
    let seenProviderKind: string | undefined;
    let seenPhoneLast4: string | undefined;

    const spekoEnv = {
      DUO_CODE_PROVIDER: "speko",
      SPEKO_API_KEY: "sk_live_test",
      DUO_PHONE_LAST4: "9915",
    };

    // 3rd SMS attempt succeeds
    const okRes = await pingLearnSession(config, {
      now: () => day1,
      env: spekoEnv,
      checkSession: async (_host, cookie) =>
        cookie === "d2lSessionVal=fresh"
          ? { alive: true, who: "Jane Doe" }
          : { alive: false, reason: "Expired" },
      silentSignIn: async (_creds, _host, opts) => {
        seenMode = opts?.mode;
        seenProviderKind = opts?.passcodeProvider?.kind;
        seenPhoneLast4 = opts?.phoneLast4;
        assert.equal(await opts?.onBeforeSmsRequest?.(), true);
        await opts?.onSmsRequested?.(day1);
        return { cookie: "d2lSessionVal=fresh", duoPrompted: true, browserCookies: [] };
      },
    });

    assert.equal(okRes.ok, true);
    assert.equal(seenMode, "automatic");
    assert.equal(seenProviderKind, "speko");
    assert.equal(seenPhoneLast4, "9915");
    assert.deepEqual((await store.current(true))?.duoSmsAttempts, {
      day: "2026-11-15",
      count: 3,
    });

    // 4th attempt on same day hits the SMS cap before clicking Text me and disables keep-alive
    config.d2l = { host: "https://learn.uwaterloo.ca", cookie: "d2lSessionVal=expired", csrfToken: undefined };
    const cappedRes = await pingLearnSession(config, {
      now: () => day1 + 60_000,
      env: spekoEnv,
      checkSession: async () => ({ alive: false, reason: "Expired" }),
      silentSignIn: async (_creds, _host, opts) => {
        const allowed = await opts?.onBeforeSmsRequest?.();
        assert.equal(allowed, false);
        throw new WaterlooLoginError("duo_sms_capped", "Daily SMS cap reached");
      },
    });

    assert.equal(cappedRes.ok, false);
    assert.equal(cappedRes.disabledKeepAlive, true);
    assert.equal(cappedRes.errorCode, "duo_sms_capped");

    const cappedRec = await store.current(true);
    assert.equal(cappedRec?.keepAlive, false);
    assert.equal(cappedRec?.duoSmsCappedDay, "2026-11-15");
    assert.equal(isKeepAliveDue(cappedRec, day1 + 3_600_000), false);
    assert.equal(isKeepAliveDue(cappedRec, day2), true);
  });
});
