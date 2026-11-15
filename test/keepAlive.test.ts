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
import { sessionStore } from "../src/sessionStore.js";
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
