import assert from "node:assert/strict";
import test from "node:test";
import {
  SpekoDuoPasscodeProvider,
  createConfiguredPasscodeProviders,
  createPasscodeProviderFromEnv,
  parseDuoSmsPasscode,
} from "../src/duoPasscode.js";

test("parseDuoSmsPasscode parses Duo SMS formats and rejects phone numbers and non-Duo texts", () => {
  assert.equal(parseDuoSmsPasscode("Your Duo verification code is 123456"), "123456");
  assert.equal(parseDuoSmsPasscode("Duo Mobile: 123456 is your passcode"), "123456");
  assert.equal(parseDuoSmsPasscode("123456 is your Duo code"), "123456");
  assert.equal(parseDuoSmsPasscode("Passcode: 1234567"), "1234567");
  assert.equal(parseDuoSmsPasscode("Your Duo code is 123 456."), "123456");
  assert.equal(parseDuoSmsPasscode("Your Duo verification code is 123-456."), "123456");
  assert.equal(parseDuoSmsPasscode("SMS passcodes: 123-4567"), "1234567");
  assert.equal(parseDuoSmsPasscode("Duo Security code: 987654. Call 519-555-1234 for help."), "987654");

  // Reject phone numbers, dates, invalid lengths, and unrelated texts
  assert.equal(parseDuoSmsPasscode("Call me at 519-555-1234"), null);
  assert.equal(parseDuoSmsPasscode("Duo warning: never share codes. Help: +1 519-555-1234"), null);
  assert.equal(parseDuoSmsPasscode("Your Duo login was on 2026-11-15"), null);
  assert.equal(parseDuoSmsPasscode("Order #123456 shipped today"), null);
  assert.equal(parseDuoSmsPasscode("Your Duo code is 12345"), null);
  assert.equal(parseDuoSmsPasscode("Your Duo code is 12345678"), null);
});

test("SpekoDuoPasscodeProvider returns null without calling fetch when SPEKO_API_KEY is missing", async () => {
  let fetched = false;
  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "",
    fetch: (async () => {
      fetched = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch,
  });

  const code = await provider.getPasscode({ username: "jdoe", attempt: 1 });
  assert.equal(code, null);
  assert.equal(fetched, false);
});

test("SpekoDuoPasscodeProvider sends Bearer auth, ignores messages <= requestedAt, and accepts newer Duo SMS", async () => {
  const requestedAt = Date.parse("2026-11-15T17:00:00.000Z");
  const seenRequests: Array<{ url: string; auth: string | null }> = [];

  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "sk_speko_test_secret_value",
    baseUrl: "https://api.speko.dev///",
    timeoutMs: 10_000,
    now: () => requestedAt + 500,
    fetch: (async (input, init) => {
      const headers = new Headers(init?.headers);
      seenRequests.push({
        url: String(input),
        auth: headers.get("Authorization"),
      });
      return new Response(
        JSON.stringify({
          data: [
            {
              id: "msg-non-duo",
              direction: "inbound",
              from: "+15550001111",
              text: "Your Uber verification code is 999888",
              created_at: "2026-11-15T17:00:02.000Z",
            },
            {
              id: "msg-newer-duo",
              direction: "inbound",
              from: "91827",
              text: "Your Duo verification code is 654 321",
              occurred_at: "2026-11-15T17:00:01.000Z",
            },
            {
              id: "msg-at-request",
              direction: "inbound",
              from: "91827",
              text: "Your Duo verification code is 111222",
              created_at: "2026-11-15T17:00:00.000Z",
            },
            {
              id: "msg-older",
              direction: "inbound",
              from: "91827",
              text: "Your Duo verification code is 000111",
              created_at: "2026-11-15T16:59:50.000Z",
            },
          ],
          next_cursor: null,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as typeof fetch,
  });

  const code = await provider.getPasscode({
    username: "jdoe",
    attempt: 1,
    requestedAt,
  });

  assert.equal(code, "654321");
  assert.equal(seenRequests.length, 1);
  assert.equal(seenRequests[0]?.auth, "Bearer sk_speko_test_secret_value");
  const parsedUrl = new URL(seenRequests[0]!.url);
  assert.equal(parsedUrl.origin, "https://api.speko.dev");
  assert.equal(parsedUrl.pathname, "/v1/sms/messages");
  assert.equal(parsedUrl.searchParams.get("direction"), "inbound");
  assert.equal(parsedUrl.searchParams.get("limit"), "50");
  assert.ok(parsedUrl.searchParams.get("created_after"));
  assert.equal(seenRequests[0]!.url.includes("sk_speko_test_secret_value"), false);
});

test("SpekoDuoPasscodeProvider enforces sender and phone filters and paginates with next_cursor", async () => {
  const requestedAt = Date.parse("2026-11-15T17:00:00.000Z");
  const requestedUrls: URL[] = [];

  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "sk_live_test",
    phoneNumber: "+15195559915",
    phoneNumberId: "123e4567-e89b-12d3-a456-426614174000",
    duoSender: "1827",
    timeoutMs: 10_000,
    now: () => requestedAt + 500,
    fetch: (async (input) => {
      const url = new URL(String(input));
      requestedUrls.push(url);
      const cursor = url.searchParams.get("cursor");
      if (!cursor) {
        return new Response(
          JSON.stringify({
            data: [
              // Wrong sender
              {
                id: "m1",
                direction: "inbound",
                from: "+15550001234",
                to: "+15195559915",
                from_phone_number_id: "123e4567-e89b-12d3-a456-426614174000",
                text: "Your Duo verification code is 111111",
                created_at: "2026-11-15T17:00:05.000Z",
              },
              // Wrong recipient phone
              {
                id: "m2",
                direction: "inbound",
                from: "91827",
                to: "+15195550000",
                from_phone_number_id: "123e4567-e89b-12d3-a456-426614174000",
                text: "Passcode: 222222",
                created_at: "2026-11-15T17:00:04.000Z",
              },
            ],
            next_cursor: "page-2",
          }),
          { status: 200 },
        );
      }

      return new Response(
        JSON.stringify({
          data: [
            {
              id: "m3",
              direction: "inbound",
              from: "91827",
              to: "+15195559915",
              from_phone_number_id: "123e4567-e89b-12d3-a456-426614174000",
              text: "Passcode: 7654321",
              created_at: "2026-11-15T17:00:03.000Z",
            },
          ],
          next_cursor: null,
        }),
        { status: 200 },
      );
    }) as typeof fetch,
  });

  const code = await provider.getPasscode({
    username: "jdoe",
    attempt: 1,
    requestedAt,
  });

  assert.equal(code, "7654321");
  assert.equal(requestedUrls.length, 2);
  assert.equal(requestedUrls[0]?.searchParams.get("from_phone_number_id"), "123e4567-e89b-12d3-a456-426614174000");
  assert.equal(requestedUrls[0]?.searchParams.get("recipient"), "+15195559915");
  assert.equal(requestedUrls[1]?.searchParams.get("cursor"), "page-2");
});

test("SpekoDuoPasscodeProvider never reuses a consumed message id", async () => {
  const requestedAt = Date.parse("2026-11-15T17:00:00.000Z");
  let clock = requestedAt;

  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "sk_live_test",
    timeoutMs: 1_000,
    pollIntervalMs: 500,
    now: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    fetch: (async () =>
      new Response(
        JSON.stringify({
          data: [
            {
              id: "msg-once",
              direction: "inbound",
              from: "Duo",
              text: "Duo Mobile: 314159 is your passcode",
              created_at: "2026-11-15T17:00:01.000Z",
            },
          ],
          next_cursor: null,
        }),
        { status: 200 },
      )) as typeof fetch,
  });

  assert.equal(
    await provider.getPasscode({ username: "jdoe", attempt: 1, requestedAt }),
    "314159",
  );
  // Second poll with the same message id still present must return null on timeout
  clock = requestedAt;
  assert.equal(
    await provider.getPasscode({ username: "jdoe", attempt: 2, requestedAt }),
    null,
  );
});

test("SpekoDuoPasscodeProvider polls with backoff until timeout and returns null", async () => {
  let clock = 1_700_000_000_000;
  const sleeps: number[] = [];

  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "sk_live_test",
    timeoutMs: 30_000,
    pollIntervalMs: 5_000,
    maxPollIntervalMs: 15_000,
    now: () => clock,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
    fetch: (async () =>
      new Response(JSON.stringify({ data: [], next_cursor: null }), { status: 200 })) as typeof fetch,
  });

  const code = await provider.getPasscode({ username: "jdoe", attempt: 1, requestedAt: clock });
  assert.equal(code, null);
  // 5000 + 5000 + 7000 + 9800 + 3200 (remaining to 30_000)
  assert.deepEqual(sleeps, [5_000, 5_000, 7_000, 9_800, 3_200]);
});

test("SpekoDuoPasscodeProvider honors AbortSignal", async () => {
  const controller = new AbortController();
  const provider = new SpekoDuoPasscodeProvider({
    apiKey: "sk_live_test",
    timeoutMs: 120_000,
    pollIntervalMs: 5_000,
    fetch: (async () => {
      controller.abort();
      return new Response(JSON.stringify({ data: [], next_cursor: null }), { status: 200 });
    }) as typeof fetch,
  });

  const code = await provider.getPasscode({
    username: "jdoe",
    attempt: 1,
    signal: controller.signal,
  });
  assert.equal(code, null);
});

test("createConfiguredPasscodeProviders and createPasscodeProviderFromEnv wire DUO_CODE_PROVIDER=speko", () => {
  const none = createPasscodeProviderFromEnv({});
  assert.equal(none, null);

  const providers = createConfiguredPasscodeProviders({
    DUO_CODE_PROVIDER: "speko",
    SPEKO_API_KEY: "sk_live_test",
    SPEKO_PHONE_NUMBER: "123e4567-e89b-12d3-a456-426614174000",
  });
  assert.equal(providers.length, 1);
  assert.equal(providers[0]?.kind, "speko");

  const aliasProvider = createPasscodeProviderFromEnv({
    UWATERLOO_DUO_CODE_PROVIDER: "speko",
    SPEKO_API_KEY: "sk_live_test",
  });
  assert.ok(aliasProvider);
  assert.equal(aliasProvider.kind, "speko");
});
