import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtemp, rm, stat } from "node:fs/promises";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import type { Config } from "../src/config.js";
import { createApp } from "../src/app.js";
import { D2LClient, D2LError, isAllowedBrightspaceApiUrl, resolveSameOriginUrl } from "../src/d2l/client.js";
import { resolveCourseFilePath } from "../src/d2l/coursePaths.js";
import { listPageLinks } from "../src/d2l/pageLinks.js";
import { resolveQuickLink } from "../src/d2l/quicklinks.js";
import { fetchGradedRubric } from "../src/d2l/rubrics.js";
import { fetchRubricDefinition } from "../src/d2l/rubricDefinitions.js";
import { calendarToken } from "../src/d2l/ics.js";
import {
  completeAuthorize,
  isPublicIp,
  registerClient,
  resolveClientIdMetadata,
} from "../src/oauth.js";
import { sessionStore } from "../src/sessionStore.js";

function makeTestConfig(overrides: Partial<Config> = {}): Config {
  return {
    port: 8787,
    host: "127.0.0.1",
    trustProxy: false,
    trustPlatformHost: false,
    authToken: "test-mcp-auth-token-24plus-chars",
    cronSecret: null,
    sessionEncryptionKey: null,
    publicUrl: null,
    allowedOrigins: [],
    allowedHosts: [],
    d2lHost: "https://learn.uwaterloo.ca",
    d2l: null,
    waterloo: null,
    piazza: null,
    crowdmarkHost: "https://app.crowdmark.com",
    crowdmark: null,
    ...overrides,
  };
}

async function withServer(
  config: Config,
  fn: (baseUrl: string) => Promise<void>,
): Promise<void> {
  const app = createApp(config);
  const server = await new Promise<import("node:http").Server>((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  try {
    const port = (server.address() as AddressInfo).port;
    await fn(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve())),
    );
  }
}

test("localhost / 127.0.0.1 Host header cannot bypass /setup or /api/keep-alive auth", async () => {
  const config = makeTestConfig();
  await withServer(config, async (baseUrl) => {
    // GET /setup on 127.0.0.1 with Host: localhost must require token and not render MCP_AUTH_TOKEN
    const getSetup = await fetch(`${baseUrl}/setup`, {
      headers: { Host: "localhost" },
    });
    assert.equal(getSetup.status, 200);
    const html = await getSetup.text();
    assert.match(html, /Server Access Token/);
    assert.equal(html.includes(config.authToken!), false);
    assert.equal(getSetup.headers.get("x-frame-options"), "DENY");
    assert.match(getSetup.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);

    // POST /setup without token must return 401
    const postSetup = await fetch(`${baseUrl}/setup`, {
      method: "POST",
      headers: {
        Host: "localhost",
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "action=check",
    });
    assert.equal(postSetup.status, 401);

    // /setup/duo-passcode without auth must return 401
    const postPasscode = await fetch(`${baseUrl}/setup/duo-passcode`, {
      method: "POST",
      headers: { Host: "localhost", "Content-Type": "application/json" },
      body: JSON.stringify({ loginId: "abc", passcode: "123456" }),
    });
    assert.equal(postPasscode.status, 401);

    // /api/keep-alive without auth must return 401 even from 127.0.0.1 with Host: localhost
    const keepAlive = await fetch(`${baseUrl}/api/keep-alive`, {
      headers: { Host: "localhost" },
    });
    assert.equal(keepAlive.status, 401);
  });
});

test("/api/keep-alive rejects bare X-Vercel-Cron and enforces timing-safe CRON_SECRET", async () => {
  // CRON_SECRET unset -> X-Vercel-Cron must NOT grant access
  await withServer(makeTestConfig({ cronSecret: null }), async (baseUrl) => {
    const res = await fetch(`${baseUrl}/api/keep-alive`, {
      headers: { "X-Vercel-Cron": "1" },
    });
    assert.equal(res.status, 401);
  });

  // CRON_SECRET set -> X-Vercel-Cron alone still 401; matching X-Cron-Secret or Bearer passes auth
  // (reaches keep-alive handler which returns 502 because no D2L session exists in fixture)
  await withServer(makeTestConfig({ cronSecret: "my-cron-secret-value" }), async (baseUrl) => {
    const bareCron = await fetch(`${baseUrl}/api/keep-alive`, {
      headers: { "X-Vercel-Cron": "1" },
    });
    assert.equal(bareCron.status, 401);

    const badSecret = await fetch(`${baseUrl}/api/keep-alive`, {
      headers: { "X-Cron-Secret": "wrong-secret" },
    });
    assert.equal(badSecret.status, 401);

    const validCron = await fetch(`${baseUrl}/api/keep-alive`, {
      headers: { "X-Cron-Secret": "my-cron-secret-value" },
    });
    assert.equal(validCron.status, 502);
    const body = (await validCron.json()) as { ok: boolean; message: string };
    assert.equal(body.ok, false);
  });
});

test("/healthz omits credential/session/env inventory", async () => {
  await withServer(
    makeTestConfig({
      d2l: { host: "https://learn.uwaterloo.ca", cookie: "d2lSessionVal=secret" },
      waterloo: { username: "jdoe@uwaterloo.ca", password: "secret" },
      piazza: { email: "jdoe@uwaterloo.ca", password: "secret" },
    }),
    async (baseUrl) => {
      const res = await fetch(`${baseUrl}/healthz`);
      assert.equal(res.status, 200);
      const data = (await res.json()) as Record<string, unknown>;
      assert.equal(data.status, "ok");
      for (const forbidden of [
        "hasSession",
        "hasWaterloo",
        "hasPiazza",
        "keepAlive",
        "lastPingAt",
        "storageEnvKeys",
      ]) {
        assert.equal(forbidden in data, false, `unexpected field in /healthz: ${forbidden}`);
      }
    },
  );
});

test("/setup cookie authenticates /setup and HTML-escapes dynamic values", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "uwmcp-sec-"));
  const origDataDir = process.env.DATA_DIR;
  process.env.DATA_DIR = dir;
  try {
    const config = makeTestConfig({
      publicUrl: 'https://example.com/"<script>alert(1)</script>',
      allowedHosts: ["example.com"],
    });
    await withServer(config, async (baseUrl) => {
      const login = await fetch(`${baseUrl}/setup`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: `token=${encodeURIComponent(config.authToken!)}`,
      });
      assert.equal(login.status, 200);
      const html = await login.text();
      assert.equal(html.includes("<script>alert(1)</script>"), false);
      assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
      // Remember credentials checkbox must NOT be pre-checked
      assert.equal(/name="remember"[^>]*\bchecked\b/i.test(html), false);
    });
  } finally {
    if (origDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = origDataDir;
    await rm(dir, { recursive: true, force: true });
  }
});

test("/calendar.ics requires MCP_AUTH_TOKEN Bearer or derived ?token=", async () => {
  const config = makeTestConfig();
  await withServer(config, async (baseUrl) => {
    const unauth = await fetch(`${baseUrl}/calendar.ics`);
    assert.equal(unauth.status, 401);

    const wrongQuery = await fetch(`${baseUrl}/calendar.ics?token=wrong`);
    assert.equal(wrongQuery.status, 401);

    // Valid derived token passes auth (503 because D2L session is not set in fixture)
    const derived = calendarToken(config.authToken!);
    const okAuth = await fetch(`${baseUrl}/calendar.ics?token=${encodeURIComponent(derived)}`);
    assert.equal(okAuth.status, 503);
  });
});

test("resolveSameOriginUrl, D2LClient.fetchText/fetchRaw, listPageLinks, and resolveQuickLink block SSRF and off-origin cookies", async () => {
  assert.equal(
    resolveSameOriginUrl("https://learn.uwaterloo.ca", "/d2l/home"),
    "https://learn.uwaterloo.ca/d2l/home",
  );

  for (const bad of [
    "http://learn.uwaterloo.ca/d2l/home",
    "https://evil.example/steal",
    "http://169.254.169.254/latest/meta-data/",
    "//evil.example/steal",
    "/\\evil.example/steal",
    "https://user:pass@learn.uwaterloo.ca/d2l/home",
  ]) {
    assert.throws(() => resolveSameOriginUrl("https://learn.uwaterloo.ca", bad), D2LError);
  }

  let fetchCount = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    fetchCount += 1;
    return new Response("unexpected", { status: 500 });
  }) as typeof fetch;

  try {
    const client = new D2LClient({
      host: "https://learn.uwaterloo.ca",
      cookie: "d2lSessionVal=secret",
    });

    await assert.rejects(() => client.fetchText("https://evil.example/steal"), D2LError);
    await assert.rejects(() => client.fetchText("//evil.example/steal"), D2LError);
    await assert.rejects(() => client.fetchRaw("http://evil.example/steal"), D2LError);
    assert.equal(fetchCount, 0);

    // External URLs in listPageLinks are classified directly without fetching
    const links = await listPageLinks(client, 1001, "https://piazza.com/class/123");
    assert.equal(links.length, 1);
    assert.equal(links[0]?.kind, "external");
    assert.equal(links[0]?.url, "https://piazza.com/class/123");
    assert.equal(fetchCount, 0);

    // Scheme-relative paths in listPageLinks are rejected without fetching
    await assert.rejects(() => listPageLinks(client, 1001, "//evil.example/x"), D2LError);
    assert.equal(fetchCount, 0);

    // resolveQuickLink accepts only bare rcodes or quickLink.d2l paths
    await assert.rejects(() => resolveQuickLink(client, 1001, "/d2l/api/lp/1.43/users/whoami"), D2LError);
    await assert.rejects(() => resolveQuickLink(client, 1001, "https://evil.example/quickLink.d2l"), D2LError);
    await assert.rejects(() => resolveQuickLink(client, 1001, "javascript:alert(1)"), D2LError);
    assert.equal(fetchCount, 0);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("Rubric Siren bearer fetches allow only brightspace.com HTTPS or D2L host", async () => {
  assert.equal(
    isAllowedBrightspaceApiUrl("https://abc.assessments.api.brightspace.com/foo", "https://learn.uwaterloo.ca"),
    true,
  );
  assert.equal(
    isAllowedBrightspaceApiUrl("https://evil.example/foo", "https://learn.uwaterloo.ca"),
    false,
  );
  assert.equal(
    isAllowedBrightspaceApiUrl("http://abc.brightspace.com/foo", "https://learn.uwaterloo.ca"),
    false,
  );

  let fetchCalled = 0;
  const origFetch = globalThis.fetch;
  globalThis.fetch = (async () => {
    fetchCalled += 1;
    return new Response("{}", { status: 200 });
  }) as typeof fetch;

  try {
    const client = new D2LClient({
      host: "https://learn.uwaterloo.ca",
      cookie: "d2lSessionVal=secret",
    });
    const graded = await fetchGradedRubric(client, "https://evil.example/siren");
    assert.equal(graded, null);
    assert.equal(fetchCalled, 0);

    const def = await fetchRubricDefinition(client, "//evil.example/rubric");
    assert.equal(def, null);
    assert.equal(fetchCalled, 0);
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("resolveCourseFilePath rejects encoded path separators", () => {
  assert.throws(
    () =>
      resolveCourseFilePath(
        12345,
        "https://learn.uwaterloo.ca",
        "/content/enforced/12345-CS/..%2fsecret.pdf",
      ),
    /percent-encoded/i,
  );
  assert.throws(
    () =>
      resolveCourseFilePath(
        12345,
        "https://learn.uwaterloo.ca",
        "/content/enforced/12345-CS/sub%5cfile.pdf",
      ),
    /percent-encoded/i,
  );
});

test("completeAuthorize revalidates client_id, redirect_uri, response_type, S256, and handles bad URLs", async () => {
  const secret = "oauth-test-secret-0123456789abcdef";
  const reg = registerClient({ redirect_uris: ["https://client.example/callback"] }, secret);
  assert.equal(reg.status, 201);
  const clientId = String((reg.payload as Record<string, unknown>).client_id);
  const challenge = createHash("sha256").update("verifier-value-12345").digest("base64url");

  // Tampered redirect_uri in POST /authorize -> 400
  const tamperedRedirect = await completeAuthorize(
    {
      responseType: "code",
      clientId,
      redirectUri: "https://attacker.example/steal",
      state: "s1",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      scope: "uwaterloo:read",
      resource: "https://mcp.example/mcp",
    },
    secret,
    secret,
    secret,
    "https://mcp.example",
    "https://mcp.example/mcp",
  );
  assert.equal(tamperedRedirect.kind, "error");
  assert.equal(tamperedRedirect.status, 400);

  // Malformed redirect_uri -> 400 (must not throw 500)
  const badUrl = await completeAuthorize(
    {
      responseType: "code",
      clientId,
      redirectUri: "not a url",
      state: null,
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      scope: null,
      resource: null,
    },
    secret,
    secret,
    secret,
    "https://mcp.example",
    "https://mcp.example/mcp",
  );
  assert.equal(badUrl.kind, "error");
  assert.equal(badUrl.status, 400);

  // Non-S256 PKCE -> 400
  const plainPkce = await completeAuthorize(
    {
      responseType: "code",
      clientId,
      redirectUri: "https://client.example/callback",
      state: null,
      codeChallenge: challenge,
      codeChallengeMethod: "plain",
      scope: null,
      resource: null,
    },
    secret,
    secret,
    secret,
    "https://mcp.example",
    "https://mcp.example/mcp",
  );
  assert.equal(plainPkce.kind, "error");
  assert.equal(plainPkce.status, 400);

  // Valid request issues redirect with code
  const ok = await completeAuthorize(
    {
      responseType: "code",
      clientId,
      redirectUri: "https://client.example/callback",
      state: "s1",
      codeChallenge: challenge,
      codeChallengeMethod: "S256",
      scope: "uwaterloo:read",
      resource: "https://mcp.example/mcp",
    },
    secret,
    secret,
    secret,
    "https://mcp.example",
    "https://mcp.example/mcp",
  );
  assert.equal(ok.kind, "redirect");
  const redirected = new URL(ok.location);
  assert.equal(redirected.origin, "https://client.example");
  assert.ok(redirected.searchParams.get("code"));
});

test("resolveClientIdMetadata blocks private/metadata IPs before fetching", async () => {
  assert.equal(isPublicIp("127.0.0.1"), false);
  assert.equal(isPublicIp("169.254.169.254"), false);
  assert.equal(isPublicIp("10.0.0.5"), false);
  assert.equal(isPublicIp("172.16.0.1"), false);
  assert.equal(isPublicIp("192.168.1.1"), false);
  assert.equal(isPublicIp("::1"), false);
  assert.equal(isPublicIp("::ffff:127.0.0.1"), false);
  assert.equal(isPublicIp("fc00::1"), false);
  assert.equal(isPublicIp("fe80::1"), false);
  assert.equal(isPublicIp("93.184.216.34"), true);

  let fetched = false;
  const blocked = await resolveClientIdMetadata("https://internal.example/client.json", {
    lookup: async () => [{ address: "169.254.169.254", family: 4 }],
    fetchFn: (async () => {
      fetched = true;
      return new Response("{}", { status: 200 });
    }) as typeof fetch,
  });
  assert.equal(blocked, null);
  assert.equal(fetched, false);

  const clientUrl = "https://client.example/oauth-client.json";
  const allowed = await resolveClientIdMetadata(clientUrl, {
    lookup: async () => [{ address: "93.184.216.34", family: 4 }],
    fetchFn: (async () => {
      fetched = true;
      return new Response(
        JSON.stringify({
          client_id: clientUrl,
          redirect_uris: ["https://client.example/cb"],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }) as typeof fetch,
  });
  assert.equal(fetched, true);
  assert.deepEqual(allowed?.ru, ["https://client.example/cb"]);
});

test("SessionStore separates SESSION_ENCRYPTION_KEY from MCP_AUTH_TOKEN and writes mode 0600", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "uwmcp-store-"));
  const origDataDir = process.env.DATA_DIR;
  const origSessionFile = process.env.LEARN_SESSION_FILE;
  delete process.env.LEARN_SESSION_FILE;
  process.env.DATA_DIR = dir;
  const encryptionKey = randomBytes(24).toString("base64url");
  const authToken = randomBytes(24).toString("base64url");

  try {
    const writerConfig = makeTestConfig({ sessionEncryptionKey: encryptionKey, authToken });
    const store = sessionStore(writerConfig);
    await store.update({ cookie: "d2lSessionVal=test-cookie" });

    const info = await stat(path.join(dir, ".learn-session"));
    assert.equal(info.mode & 0o777, 0o600);

    // Without SESSION_ENCRYPTION_KEY (only MCP_AUTH_TOKEN), the record cannot be decrypted
    const wrongConfig = makeTestConfig({ sessionEncryptionKey: null, authToken });
    const wrongRecord = await sessionStore(wrongConfig).current(true);
    assert.equal(wrongRecord, null);

    // Same SESSION_ENCRYPTION_KEY decrypts it even if MCP_AUTH_TOKEN changes
    const goodConfig = makeTestConfig({
      sessionEncryptionKey: encryptionKey,
      authToken: randomBytes(24).toString("base64url"),
    });
    const goodRecord = await sessionStore(goodConfig).current(true);
    assert.equal(goodRecord?.cookie, "d2lSessionVal=test-cookie");
  } finally {
    if (origDataDir === undefined) delete process.env.DATA_DIR;
    else process.env.DATA_DIR = origDataDir;
    if (origSessionFile === undefined) delete process.env.LEARN_SESSION_FILE;
    else process.env.LEARN_SESSION_FILE = origSessionFile;
    await rm(dir, { recursive: true, force: true });
  }
});
