/**
 * Builds the unified Express app — MCP over Streamable HTTP, protocol revision 2026-07-28.
 *
 *   POST /mcp                                     → MCP endpoint (bearer token required)
 *   GET  /                                        → plain-text status page
 *   GET  /healthz                                 → liveness probe
 *   GET  /.well-known/oauth-protected-resource    → RFC 9728 metadata
 *
 * Deliberately contains no `listen()` and no reference to any hosting provider: this is the
 * whole server as a plain Express app, so a long-running process (`index.ts`) and a serverless
 * function (`api/index.ts`) can both use it unchanged. Adding a platform means adding one small
 * adapter, never editing this file.
 *
 * Runs in **stateless mode**: a fresh McpServer and transport are built per request and torn
 * down when it completes. Under 2026-07-28 that is the natural shape rather than an
 * optimisation — the revision removed protocol-level sessions and the `initialize` handshake, so
 * every request carries its own protocol version and capabilities and can land on any instance.
 * It is also precisely what makes serverless hosting work without an external session store.
 */

import { createMcpExpressApp, requireBearerAuth } from "@modelcontextprotocol/express";
import { getOAuthProtectedResourceMetadataUrl } from "@modelcontextprotocol/server";
import { NodeStreamableHTTPServerTransport } from "@modelcontextprotocol/node";
import express from "express";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import type { Express, NextFunction, Request, Response } from "express";
import { CURRENT_PROTOCOL_VERSION, SERVER_NAME, VERSION, type Config } from "./config.js";
import { createServer, SUPPORTED_PROTOCOL_VERSIONS } from "./server.js";
import { combinedVerifier } from "./auth.js";
import { validateMirroredHeaders } from "./headerValidation.js";
import { D2LClient } from "./d2l/client.js";
import { calendarToken, generateDueDatesIcs, verifyCalendarToken } from "./d2l/ics.js";
import { streamCourseFile, streamSubmissionFile, streamTopicFile } from "./d2l/files.js";
import { getUpcoming } from "./d2l/upcoming.js";
import { CrowdmarkClient } from "./crowdmark/client.js";
import { verifyFileToken } from "./fileUrls.js";
import {
  CompositeDuoPasscodeProvider,
  createConfiguredPasscodeProviders,
  getDuoPhoneLast4,
  getDuoSmsMaxAttemptsPerDay,
  ManualPasscodeCoordinator,
  sanitizePasscode,
  type DuoPasscodeProvider,
} from "./duoPasscode.js";
import {
  D2L_IDLE_WINDOW_MS,
  readCookie,
  SETUP_COOKIE,
  SETUP_COOKIE_MAX_AGE_SECONDS,
  setupCookieValue,
  setupPage,
  tokenMatches,
  validateCookie,
  type PageState,
  type SessionSnapshot,
} from "./setup.js";
import {
  canRequestDuoSms,
  nextDailySmsAttempts,
  sessionStore,
  storedPiazzaCredentials,
  storedWaterlooCredentials,
  syncSession,
  torontoDayKey,
} from "./sessionStore.js";
import { signInUWaterloo, WaterlooLoginError, type WaterlooLoginEvent } from "./waterlooLogin.js";
import { PiazzaClient } from "./piazza/client.js";
import { ensureKeepAliveOnRequest, pingLearnSession } from "./keepAlive.js";
import {
  authorizationServerMetadata,
  beginAuthorize,
  completeAuthorize,
  exchangeToken,
  OAUTH_SCOPE,
  protectedResourceMetadata,
  registerClient,
  type AuthorizeParams,
  type AuthorizeResult,
} from "./oauth.js";

function inlineScriptValue(value: string): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function setFrameDenyHeaders(res: Response): void {
  res.set("X-Frame-Options", "DENY");
  res.set("Content-Security-Policy", "frame-ancestors 'none'");
}

function beginWaterlooSetupProgress(res: Response): void {
  res.status(200).set({
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Accel-Buffering": "no",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "frame-ancestors 'none'",
  });
  res.flushHeaders();
  res.write(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UWaterloo sign-in</title><style>
:root{color-scheme:light dark}body{font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;max-width:34rem;margin:8vh auto;padding:0 1.25rem;line-height:1.55}h1{font-size:1.35rem}.card{border:1px solid #bbb;border-radius:.65rem;padding:1.2rem;margin-top:1.2rem}.code{font:700 3rem/1 ui-monospace,monospace;letter-spacing:.3em;margin:.5rem 0 1rem;color:#1675d1}p{color:#666}.error{color:#b42318}.success{color:#16794b}a{color:#1675d1}input{width:100%;box-sizing:border-box;padding:.55rem .7rem;border:1px solid #bbb;border-radius:.45rem;font:inherit;margin:.4rem 0 .8rem}button{background:#1675d1;color:#fff;border:0;border-radius:.45rem;padding:.55rem .95rem;font:inherit;font-weight:600;cursor:pointer}
</style></head><body><h1>Signing in to UWaterloo Learn</h1>
<div class="card"><p id="status">Opening UWaterloo and checking Duo options…</p>
<div id="code-panel" hidden><div class="code" id="duo-code"></div><strong>Enter this code in Duo Mobile now.</strong></div>
<div id="passcode-panel" hidden>
  <p id="passcode-hint">Enter a Duo SMS text passcode or Duo Mobile passcode.</p>
  <form id="passcode-form">
    <input id="passcode-input" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="6-7 digit passcode" required>
    <button type="submit">Submit Passcode</button>
  </form>
  <p id="passcode-err" class="error"></p>
</div>
<p id="return" hidden><a href="/setup">Return to setup</a></p></div>
<script>
let activeLoginId = null;
window.waterlooCode=(code,waiting)=>{document.getElementById("passcode-panel").hidden=true;document.getElementById("duo-code").textContent=code;document.getElementById("code-panel").hidden=false;document.getElementById("status").textContent=waiting?("Still waiting for Duo verification ("+waiting+"s)."):"Duo verification code ready."};
window.waterlooNeedPasscode=(loginId,hint)=>{activeLoginId=loginId;document.getElementById("code-panel").hidden=true;document.getElementById("passcode-panel").hidden=false;document.getElementById("status").textContent="Duo MFA passcode required.";if(hint)document.getElementById("passcode-hint").textContent=hint;document.getElementById("passcode-err").textContent="";document.getElementById("passcode-input").focus()};
document.getElementById("passcode-form").addEventListener("submit",async(e)=>{e.preventDefault();const code=document.getElementById("passcode-input").value.trim();if(!code||!activeLoginId)return;const r=await fetch("/setup/duo-passcode",{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",body:JSON.stringify({loginId:activeLoginId,passcode:code})});if(!r.ok){document.getElementById("passcode-err").textContent="Passcode could not be submitted. Try again.";return}document.getElementById("passcode-panel").hidden=true;document.getElementById("status").textContent="Submitting passcode to Duo…"});
window.waterlooDone=(kind,message)=>{document.getElementById("code-panel").hidden=true;document.getElementById("passcode-panel").hidden=true;const status=document.getElementById("status");status.className=kind;status.textContent=message;document.getElementById("return").hidden=false};
</script>`);
}

function writeWaterlooSetupCode(res: Response, event: WaterlooLoginEvent): void {
  if (event.type === "duo_passcode_required") {
    res.write(
      `<script>window.waterlooNeedPasscode(${inlineScriptValue(event.loginId)},${inlineScriptValue(event.hint ?? "")})</script>`,
    );
    return;
  }
  const waiting = event.type === "duo_waiting" ? event.secondsWaiting : 0;
  res.write(
    `<script>window.waterlooCode(${inlineScriptValue(event.code)},${waiting})</script>`,
  );
}

function finishWaterlooSetupProgress(
  res: Response,
  kind: "error" | "success",
  message: string,
): void {
  res.end(
    `<script>window.waterlooDone(${inlineScriptValue(kind)},${inlineScriptValue(message)})</script></body></html>`,
  );
}

/** Collects the OAuth authorization parameters from a query string or form body. */
function authorizeParams(source: Record<string, string | undefined>): AuthorizeParams {
  return {
    responseType: source["response_type"] ?? null,
    clientId: source["client_id"] ?? null,
    redirectUri: source["redirect_uri"] ?? null,
    state: source["state"] ?? null,
    codeChallenge: source["code_challenge"] ?? null,
    codeChallengeMethod: source["code_challenge_method"] ?? null,
    scope: source["scope"] ?? null,
    resource: source["resource"] ?? null,
  };
}

/**
 * `/setup` — establish the Learn session.
 *
 * Guarded by the same token that guards `/mcp`: whoever can call the tools can already read
 * every course, so this grants no new access, and it keeps the number of secrets at one. A device
 * that has entered the token once gets a cookie derived from it, so a phone is not asked again.
 *
 * The MCP token and the Piazza login are deploy-time environment variables. The WatIAM login can
 * be one too, or it can be typed here and (if the person chooses) kept in the session store
 * beside the session it produced.
 */
function registerSetupRoute(app: Express, config: Config): void {
  const form = express.urlencoded({ extended: false, limit: "16kb" });
  const store = sessionStore(config);
  const manualPasscodes = new ManualPasscodeCoordinator();
  const setupConsumedSpekoIds = new Set<string>();

  const bearerMatches = (req: Request, expected: string | null): boolean => {
    if (!expected) return false;
    const authHeader = req.headers.authorization ?? "";
    const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
    return !!(bearer && tokenMatches(bearer, expected));
  };

  const setupState = async (
    req?: Request,
    authenticated = false,
  ): Promise<Omit<PageState, "authenticated">> => {
    if (!authenticated) {
      return {
        knownUsername: null,
        loginSaved: false,
        store: store.kind,
        piazzaConfigured: false,
      };
    }
    await syncSession(config, true);
    const record = await store.current();
    const saved = config.waterloo ? null : (record?.waterloo ?? null);
    const piazza = await storedPiazzaCredentials(config);
    const base =
      config.publicUrl ??
      (req ? `${req.protocol}://${req.get("host") || "localhost:" + config.port}` : `http://localhost:${config.port}`);

    let crowdmarkAlive: boolean | undefined;
    let crowdmarkUser: string | null | undefined;
    if (config.crowdmark?.cookie) {
      const cmStatus = await new CrowdmarkClient(config.crowdmark).sessionStatus();
      crowdmarkAlive = cmStatus.alive;
      crowdmarkUser = cmStatus.alive ? cmStatus.user : null;
    }

    const calendarUrl =
      config.authToken
        ? `${base}/calendar.ics?token=${encodeURIComponent(calendarToken(config.authToken))}`
        : `${base}/calendar.ics`;

    return {
      knownUsername: (config.waterloo ?? saved)?.username ?? null,
      loginSaved: saved !== null,
      store: store.kind,
      storeError: store.lastError ?? undefined,
      piazzaConfigured: !!piazza,
      piazzaEmail: piazza?.email,
      crowdmarkConfigured: !!config.crowdmark?.cookie,
      crowdmarkAlive,
      crowdmarkUser,
      serverUrl: `${base}/mcp`,
      authToken: config.authToken ?? undefined,
      calendarUrl,
      keepAliveEnabled: !!record?.keepAlive,
      lastPingAt: record?.lastPingAt,
      lastPingError: record?.lastPingError,
    };
  };

  app.use("/setup", (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    setFrameDenyHeaders(res);
    next();
  });

  /** True when this request comes from a device that has already proven it holds the token. */
  const rememberedDevice = (req: Request): boolean => {
    if (!config.authToken) return false;
    const presented = readCookie(req.headers.cookie, SETUP_COOKIE);
    return !!presented && tokenMatches(presented, setupCookieValue(config.authToken));
  };

  const rememberDevice = (req: Request, res: Response): void => {
    if (!config.authToken) return;
    res.cookie(SETUP_COOKIE, setupCookieValue(config.authToken), {
      httpOnly: true,
      // Lax rather than Strict: the usual way here is tapping a link in a chat app, which is a
      // cross-site navigation that Strict would arrive at without the cookie.
      sameSite: "lax",
      secure: req.secure,
      path: "/",
      maxAge: SETUP_COOKIE_MAX_AGE_SECONDS * 1000,
    });
  };

  /** A live probe, not a cached guess — and the probe itself resets the idle window it reports. */
  const describeSession = async (): Promise<SessionSnapshot> => {
    await syncSession(config, true);
    await ensureKeepAliveOnRequest(config);
    if (!config.d2l) {
      return { alive: false, reason: "No session has been established on this server yet." };
    }
    const status = await new D2LClient(config.d2l).sessionStatus();
    return status.alive
      ? {
          alive: true,
          who: `${status.user.FirstName} ${status.user.LastName}`,
          idleExpiresAt: new Date(Date.now() + D2L_IDLE_WINDOW_MS).toISOString(),
        }
      : { alive: false, reason: status.reason };
  };

  /**
   * Adopts a cookie only after Brightspace confirms it, so a bad paste cannot break a good
   * session — then writes it to the store, so every instance picks it up.
   */
  const adopt = async (
    cookie: string,
    extra: Parameters<typeof store.update>[0] = {},
  ): Promise<{ ok: true; who: string; saved: boolean } | { ok: false; error: string }> => {
    const credentials = { host: config.d2lHost, cookie, csrfToken: undefined };
    const status = await new D2LClient(credentials).sessionStatus();
    if (!status.alive) {
      return {
        ok: false,
        error:
          "Brightspace rejected that session. It may have already expired. The server's " +
          "existing session was left alone.",
      };
    }
    config.d2l = credentials;
    process.env.D2L_COOKIE = cookie;

    let saved = false;
    try {
      const existing = await store.current();
      await store.update({
        cookie,
        keepAlive: existing?.duoSmsCappedDay ? true : (existing?.keepAlive ?? true),
        duoSmsCappedDay: undefined,
        lastPingAt: Date.now(),
        lastAttemptAt: Date.now(),
        consecutiveFailures: 0,
        lastPingError: undefined,
        ...extra,
      });
      saved = store.persistent;
    } catch (error) {
      console.error("[setup] could not save the session", {
        store: store.kind,
        error: error instanceof Error ? error.message : String(error),
      });
    }
    return { ok: true, who: `${status.user.FirstName} ${status.user.LastName}`, saved };
  };

  const signedInMessage = (who: string, saved: boolean): string =>
    `Signed in to UWaterloo Learn as ${who}. Learn tools work now — go back to your assistant ` +
    "and ask again." +
    (saved
      ? ""
      : " This server could not save the session, so it will be forgotten when this instance stops.");

  app.get("/setup", async (req, res) => {
    const authed =
      config.authToken === null ||
      rememberedDevice(req) ||
      bearerMatches(req, config.authToken);
    if (!authed) {
      res.type("html").send(setupPage({ ...(await setupState(req, false)), authenticated: false }));
      return;
    }
    res.type("html").send(
      setupPage({
        ...(await setupState(req, true)),
        authenticated: true,
        session: await describeSession(),
      }),
    );
  });

  app.post("/setup/duo-passcode", (req, res) => {
    const body = (req.body ?? {}) as { loginId?: unknown; passcode?: unknown; token?: unknown };
    const tokenArg = typeof body.token === "string" ? body.token.trim() : "";
    const authed =
      config.authToken === null ||
      rememberedDevice(req) ||
      bearerMatches(req, config.authToken) ||
      (!!config.authToken && !!tokenArg && tokenMatches(tokenArg, config.authToken));
    if (!authed) {
      res.status(401).json({ ok: false, error: "Unauthorized" });
      return;
    }

    const loginId = typeof body.loginId === "string" ? body.loginId.trim() : "";
    const passcode = typeof body.passcode === "string" ? body.passcode : "";
    if (!loginId || !sanitizePasscode(passcode)) {
      res.status(400).json({ ok: false, error: "Invalid loginId or passcode." });
      return;
    }
    const accepted = manualPasscodes.submit(loginId, passcode);
    if (!accepted) {
      res.status(404).json({ ok: false, error: "No pending Duo passcode prompt matches this loginId." });
      return;
    }
    res.json({ ok: true });
  });

  app.post("/setup", form, async (req, res) => {
    const body = (req.body ?? {}) as Record<string, string | undefined>;
    const provided = (body["token"] ?? "").trim();
    const viaToken = !!config.authToken && tokenMatches(provided, config.authToken);

    if (
      config.authToken &&
      !viaToken &&
      !rememberedDevice(req) &&
      !bearerMatches(req, config.authToken)
    ) {
      res.status(401).type("html").send(
        setupPage({
          ...(await setupState(req, false)),
          authenticated: false,
          message: { kind: "error", text: "That token is not correct." },
        }),
      );
      return;
    }
    if (viaToken) rememberDevice(req, res);
    const tokenEcho = viaToken ? provided : undefined;

    const action = body["action"];
    // First POST proves identity; the session forms are only shown afterwards. "check" lands
    // here too — re-probing and re-rendering is exactly what it does.
    if (action === undefined || action === "check") {
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "forget") {
      await store.update({ waterloo: undefined });
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: { kind: "success", text: "The saved WatIAM login was removed from this server." },
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "piazza") {
      const email = (body["email"] ?? "").trim();
      const password = body["password"] ?? "";

      if (!email || !password) {
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "error", text: "Enter your Piazza email and password." },
            session: await describeSession(),
          }),
        );
        return;
      }

      try {
        const client = new PiazzaClient();
        await client.login(email, password);
        config.piazza = { email, password };
        await store.update({ piazza: { email, password } });

        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "success", text: `Connected Piazza account (${email}). Piazza tools are now active.` },
            session: await describeSession(),
          }),
        );
      } catch (err) {
        const errorText = err instanceof Error ? err.message : String(err);
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "error", text: `Piazza login failed: ${errorText}` },
            session: await describeSession(),
          }),
        );
      }
      return;
    }

    if (action === "piazza_disconnect") {
      delete process.env.PIAZZA_EMAIL;
      delete process.env.PIAZZA_PASSWORD;
      config.piazza = null;
      await store.update({ piazza: undefined });
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: { kind: "success", text: "Piazza account disconnected." },
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "crowdmark_cookie") {
      const rawCookie = (body["cookie"] ?? "").trim();
      if (!rawCookie || /[\r\n\0]/.test(rawCookie)) {
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "error", text: "Paste a valid single-line Crowdmark Cookie header." },
            session: await describeSession(),
          }),
        );
        return;
      }

      const status = await new CrowdmarkClient({
        host: config.crowdmarkHost,
        cookie: rawCookie,
      }).sessionStatus();
      if (!status.alive) {
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: {
              kind: "error",
              text: `Crowdmark rejected that cookie (${status.reason}). Existing configuration was kept.`,
            },
            session: await describeSession(),
          }),
        );
        return;
      }

      config.crowdmark = { host: config.crowdmarkHost, cookie: rawCookie };
      process.env.CROWDMARK_COOKIE = rawCookie;
      await store.update({ crowdmarkCookie: rawCookie });
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: {
            kind: "success",
            text: `Connected Crowdmark${status.user ? ` as ${status.user}` : ""}. Read-only Crowdmark tools are active.`,
          },
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "crowdmark_disconnect") {
      delete process.env.CROWDMARK_COOKIE;
      config.crowdmark = null;
      await store.update({ crowdmarkCookie: undefined });
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: { kind: "success", text: "Crowdmark disconnected." },
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "toggle_keep_alive") {
      const enabled = body["enabled"] === "1";
      if (enabled) {
        await store.update({
          keepAlive: true,
          duoSmsCappedDay: undefined,
          consecutiveFailures: 0,
          lastPingError: undefined,
        });
        const ping = await pingLearnSession(config);
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: ping.ok
              ? { kind: "success", text: "Keep Signed In enabled! Auto-ping will refresh your session every 45 minutes." }
              : { kind: "error", text: `Keep Signed In enabled, but initial ping failed: ${ping.message}` },
            session: await describeSession(),
          }),
        );
      } else {
        await store.update({ keepAlive: false, duoSmsCappedDay: undefined });
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "success", text: "Keep Signed In disabled. Session will expire after 3 hours of inactivity." },
            session: await describeSession(),
          }),
        );
      }
      return;
    }

    if (action === "ping_now") {
      const ping = await pingLearnSession(config);
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: ping.ok
            ? { kind: "success", text: ping.message }
            : { kind: "error", text: `Ping failed: ${ping.message}` },
          session: await describeSession(),
        }),
      );
      return;
    }

    if (action === "waterloo") {
      const typedUsername = (body["username"] ?? "").trim();
      const typedPassword = body["password"] ?? "";
      const typed = typedUsername && typedPassword
        ? { username: typedUsername, password: typedPassword }
        : null;
      const credentials = typed ?? (await storedWaterlooCredentials(config));

      if (!credentials) {
        res.type("html").send(
          setupPage({
            ...(await setupState(req, true)),
            authenticated: true,
            tokenEcho,
            message: { kind: "error", text: "Enter your WatIAM username and password." },
          }),
        );
        return;
      }

      beginWaterlooSetupProgress(res);
      let activeLoginId: string | null = null;
      const onClose = () => {
        if (activeLoginId) manualPasscodes.cancel(activeLoginId);
      };
      req.on("close", onClose);

      let inlinePasscodeUsed = false;
      const inlinePasscode = sanitizePasscode(body["passcode"]);
      const providers: DuoPasscodeProvider[] = [];
      if (inlinePasscode) {
        providers.push({
          kind: "form",
          async getPasscode() {
            if (inlinePasscodeUsed) return null;
            inlinePasscodeUsed = true;
            return inlinePasscode;
          },
        });
      }
      providers.push(
        ...createConfiguredPasscodeProviders(process.env, {
          consumedIds: setupConsumedSpekoIds,
        }),
      );
      providers.push(
        manualPasscodes.createProvider((loginId, ctx) => {
          activeLoginId = loginId;
          writeWaterlooSetupCode(res, {
            type: "duo_passcode_required",
            loginId,
            hint: ctx.hint,
          });
        }),
      );
      const passcodeProvider = new CompositeDuoPasscodeProvider(providers);
      const maxSmsPerDay = getDuoSmsMaxAttemptsPerDay();

      let login: Awaited<ReturnType<typeof signInUWaterloo>>;
      try {
        login = await signInUWaterloo(credentials, config.d2lHost, {
          mode: "interactive",
          passcodeProvider,
          phoneLast4: getDuoPhoneLast4(),
          onBeforeSmsRequest: async () => {
            const latest = await store.current(true);
            return canRequestDuoSms(latest, maxSmsPerDay);
          },
          onSmsRequested: async (requestedAt) => {
            const latest = await store.current(true);
            await store.update({
              duoSmsAttempts: nextDailySmsAttempts(latest?.duoSmsAttempts, requestedAt),
            });
          },
          onEvent: (event) => writeWaterlooSetupCode(res, event),
          browserCookies: (await store.current())?.browserCookies,
        });
      } catch (error) {
        req.off("close", onClose);
        if (activeLoginId) manualPasscodes.cancel(activeLoginId);
        let message =
          error instanceof WaterlooLoginError
            ? error.message
            : "UWaterloo sign-in failed without changing the existing Learn session.";
        if (error instanceof WaterlooLoginError && error.code === "duo_sms_capped") {
          await store
            .update({
              keepAlive: false,
              duoSmsCappedDay: torontoDayKey(),
              lastPingError: message,
            })
            .catch(() => undefined);
        }
        if (
          error instanceof WaterlooLoginError &&
          error.code === "invalid_credentials" &&
          !typed &&
          !config.waterloo
        ) {
          await store.update({ waterloo: undefined }).catch(() => undefined);
          message += " The saved login was removed — enter it again on the setup page.";
        }
        finishWaterlooSetupProgress(res, "error", message);
        return;
      }

      req.off("close", onClose);
      if (activeLoginId) manualPasscodes.cancel(activeLoginId);

      // A typed login is saved only once UWaterloo has accepted it, and only if asked to.
      const remember = typed ? body["remember"] === "1" : undefined;
      const adopted = await adopt(login.cookie, {
        browserCookies: login.browserCookies,
        ...(typed && !config.waterloo ? { waterloo: remember ? typed : undefined } : {}),
      });
      finishWaterlooSetupProgress(
        res,
        adopted.ok ? "success" : "error",
        adopted.ok ? signedInMessage(adopted.who, adopted.saved) : adopted.error,
      );
      return;
    }

    if (action !== "cookie") {
      res.status(400).type("text/plain").send("Unknown setup action.");
      return;
    }

    const validated = validateCookie(body["cookie"] ?? "");
    if (!validated.ok) {
      res.type("html").send(
        setupPage({
          ...(await setupState(req, true)),
          authenticated: true,
          tokenEcho,
          message: { kind: "error", text: validated.error },
        }),
      );
      return;
    }

    const adopted = await adopt(validated.cookie);
    res.type("html").send(
      setupPage({
        ...(await setupState(req, true)),
        authenticated: true,
        tokenEcho,
        message: adopted.ok
          ? { kind: "success", text: signedInMessage(adopted.who, adopted.saved) }
          : { kind: "error", text: adopted.error },
        session: await describeSession(),
      }),
    );
  });

  app.all("/api/keep-alive", async (req, res) => {
    const cronHeader = req.headers["x-cron-secret"];
    const rawCronHeader = Array.isArray(cronHeader) ? cronHeader[0] : cronHeader;
    const cronAuthorized =
      !!config.cronSecret &&
      (bearerMatches(req, config.cronSecret) ||
        (typeof rawCronHeader === "string" && tokenMatches(rawCronHeader.trim(), config.cronSecret)));

    const authorized =
      config.authToken === null ||
      bearerMatches(req, config.authToken) ||
      rememberedDevice(req) ||
      cronAuthorized;

    if (!authorized) {
      res.status(401).json({ error: "Unauthorized" });
      return;
    }

    const result = await pingLearnSession(config);
    res.status(result.ok ? 200 : 502).json(result);
  });
}

/**
 * `/file/:token` — serves one course file over plain HTTP.
 *
 * The fallback for clients that cannot accept an embedded resource. Deliberately unauthenticated
 * in the usual sense: the caller is an AI sandbox running `curl`, which has no bearer token. The
 * signed token in the path is the credential — it names one file, expires in minutes, and cannot
 * be altered without invalidating the signature.
 */
function registerFileDownloadRoute(app: Express, config: Config): void {
  app.get("/file/:token", async (req, res) => {
    await syncSession(config);
    if (!config.d2l || !config.authToken) {
      res.status(503).type("text/plain").send("This server is not configured to serve files.");
      return;
    }

    const grant = verifyFileToken(req.params.token ?? "", config.authToken, config.d2l.host);
    if (!grant) {
      res.status(403).type("text/plain").send("This download link is invalid or has expired.");
      return;
    }

    try {
      // A pass-through: the bytes go from D2L to the caller without being buffered or stored
      // here, so a large file costs no more memory than a small one and nothing is retained
      // after the response ends.
      const client = new D2LClient(config.d2l);
      const file =
        grant.kind === "topic"
          ? await streamTopicFile(client, grant.courseId, grant.topicId)
          : grant.kind === "path"
            ? await streamCourseFile(client, grant.path)
            : await streamSubmissionFile(
                client,
                grant.courseId,
                grant.folderId,
                grant.submissionId,
                grant.fileId,
              );

      // Both filename forms, so a client that understands neither RFC 5987 nor quoting still
      // ends up with a sensible name rather than the token.
      const encoded = encodeURIComponent(file.fileName);
      res.status(200).set({
        "Content-Type": file.mimeType,
        "Content-Disposition": `attachment; filename="${file.fileName.replace(/"/g, "")}"; filename*=UTF-8''${encoded}`,
        // A signed URL is single-purpose and short-lived; caching it anywhere is wrong.
        "Cache-Control": "no-store",
      });

      // Deliberately no Content-Length. Brightspace serves text compressed and `fetch`
      // decompresses it, so the length it reported describes a smaller body than the one being
      // streamed here; forwarding it makes the client stop early and save a file truncated
      // mid-token, with a 200 and no error to show for it. Chunked encoding is correct whatever
      // the upstream did, and the cost is only that a downloader cannot show a progress bar.

      await pipeline(Readable.fromWeb(file.body as Parameters<typeof Readable.fromWeb>[0]), res);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Headers are already sent once streaming has begun; the only honest signal left is to
      // break the connection so the client sees a truncated download rather than a valid file.
      if (res.headersSent) {
        res.destroy();
        return;
      }
      res.status(502).type("text/plain").send(`Could not fetch the file from D2L. ${message}`);
    }
  });
}

function sendAuthorizeResult(res: Response, result: AuthorizeResult): void {
  switch (result.kind) {
    case "redirect":
      res.redirect(302, result.location);
      return;
    case "prompt":
      res.type("html").send(result.html);
      return;
    case "error":
      res.status(result.status).type("text/plain").send(result.message);
      return;
  }
}

export function createApp(config: Config): Express {
  /** Base URL used in discovery documents. Falls back to the local bind for dev. */
  const resourceServerUrl = new URL(config.publicUrl ?? `http://localhost:${config.port}`);

  /**
   * Hostnames the DNS-rebinding check will accept.
   *
   * The SDK defaults to localhost-only, which silently breaks every hosted deployment: behind a
   * tunnel or a real domain the `Host` header is the public name, so *all* routes answer
   * `403 Invalid Host` — including the landing page, with no hint as to why. Trusting the
   * hostname the operator already declared in MCP_PUBLIC_URL removes that trap without widening
   * anything: it is the name this server is meant to be reached by.
   *
   * On a platform that assigns the URL for you (Vercel and friends), `trustPlatformHost` skips
   * the check entirely — the platform terminates TLS and routes by hostname, so a forged Host
   * header cannot reach us, and demanding the user configure a name they were given
   * automatically would break one-click deploys.
   */
  const allowedHosts = [
    "localhost",
    "127.0.0.1",
    "[::1]",
    ...(resourceServerUrl.hostname ? [resourceServerUrl.hostname] : []),
    ...config.allowedHosts,
  ];

  // createMcpExpressApp wires up JSON body parsing plus Host/Origin validation. Origin rules
  // stay narrower: browsers send Origin and MCP clients do not, so we widen that list only when
  // the operator explicitly asks.
  // `host` doubles as a policy switch inside createMcpExpressApp: a localhost value turns on
  // automatic Host/Origin validation. Omitting `allowedHosts` therefore does not disable the
  // check, it just falls back to localhost-only — which rejects the platform's own domain. On a
  // managed platform we pass a non-localhost host so no automatic rules are installed at all.
  const app = createMcpExpressApp({
    host: config.trustPlatformHost ? "0.0.0.0" : config.host,
    jsonLimit: "4mb",
    ...(config.trustPlatformHost ? {} : { allowedHosts }),
    ...(config.allowedOrigins.length > 0 ? { allowedOrigins: config.allowedOrigins } : {}),
  });
  app.disable("x-powered-by");
  // Behind a platform proxy, req.protocol must reflect X-Forwarded-Proto so the landing page
  // prints an https:// URL rather than http://.
  if (config.trustProxy) app.set("trust proxy", true);

  app.get("/", async (req, res) => {
    await syncSession(config);
    const store = sessionStore(config);
    const base = config.publicUrl ?? `${req.protocol}://${req.headers.host}`;
    const lines = [
      `${SERVER_NAME} MCP server v${VERSION} — running.`,
      "",
      "To connect this to ChatGPT or Claude, paste these two values:",
      "",
      `  Server URL:  ${base}/mcp`,
    ];

    if (config.authToken === null) {
      lines.push("  Token:       (none — this server is running without authentication)");
    } else {
      lines.push("  Token:       the MCP_AUTH_TOKEN you configured (not shown here)");
    }

    lines.push(
      "",
      `  Setup:       ${base}/setup`,
      "",
      "----",
      "Transport: Streamable HTTP (stateless, MCP 2026-07-28)",
      `Storage:   ${store.kind}${store.persistent ? "" : " (ephemeral)"}`,
      `Learn:     ${config.d2l ? "configured" : "not configured"}`,
      `Piazza:    ${config.piazza ? "configured" : "not configured"}`,
      `Crowdmark: ${config.crowdmark ? "configured" : "not configured"}`,
    );

    res.type("text/plain").send(lines.join("\n"));
  });

  app.get("/healthz", async (_req, res) => {
    const store = sessionStore(config);
    await store.current(true);
    res.json({
      status: "ok",
      server: SERVER_NAME,
      version: VERSION,
      store: store.kind,
      persistent: store.persistent,
      storeError: store.lastError,
    });
  });

  registerSetupRoute(app, config);
  registerFileDownloadRoute(app, config);

  app.get("/calendar.ics", async (req, res) => {
    if (config.authToken) {
      const authHeader = req.headers.authorization ?? "";
      const bearer = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
      const queryToken = typeof req.query.token === "string" ? req.query.token : "";
      const bearerOk = !!(bearer && tokenMatches(bearer, config.authToken));
      const calTokenOk = !!queryToken && verifyCalendarToken(queryToken, config.authToken);
      if (!bearerOk && !calTokenOk) {
        res.status(401).type("text/plain").send("Unauthorized");
        return;
      }
    }

    await syncSession(config);
    if (!config.d2l) {
      res.status(503).type("text/plain").send("No Learn session is currently configured.");
      return;
    }

    try {
      const client = new D2LClient(config.d2l);
      const { deadlines } = await getUpcoming(client, {
        withinDays: 90,
        includeSubmitted: true,
        includeOverdue: true,
      });
      const ics = generateDueDatesIcs(deadlines, { d2lHost: config.d2lHost });
      res
        .status(200)
        .set({
          "Content-Type": "text/calendar; charset=utf-8",
          "Content-Disposition": 'inline; filename="uwaterloo-learn-due-dates.ics"',
          "Cache-Control": "private, no-store",
        })
        .send(ics);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      res.status(502).type("text/plain").send(`Could not export calendar: ${message}`);
    }
  });

  /** Origin this request arrived on — the issuer identity for OAuth documents. */
  const originOf = (req: Request): string =>
    config.publicUrl ?? `${req.protocol}://${req.headers.host}`;

  // Discovery documents are fetched cross-origin by MCP clients, and must never be cached.
  const discovery = (_req: Request, res: Response, next: NextFunction): void => {
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Cache-Control", "no-store");
    next();
  };

  // RFC 9728 Protected Resource Metadata. Clients probe both the bare and resource-suffixed
  // forms, so both are served.
  app.get(
    ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"],
    discovery,
    (req, res) => {
      res.json(protectedResourceMetadata(originOf(req)));
    },
  );

  // RFC 8414 Authorization Server Metadata. Without this, ChatGPT reports that the server
  // "does not implement OAuth" and refuses to add the connector.
  app.get(
    [
      "/.well-known/oauth-authorization-server",
      "/.well-known/oauth-authorization-server/mcp",
      "/.well-known/openid-configuration",
    ],
    discovery,
    (req, res) => {
      res.json(authorizationServerMetadata(originOf(req)));
    },
  );

  if (config.authToken) {
    const staticToken = config.authToken;

    // RFC 7591 dynamic client registration. Deprecated in 2026-07-28 in favour of Client ID
    // Metadata Documents (also supported, in resolveClient) but kept because deployed clients
    // still use it.
    app.post("/register", express.json({ limit: "64kb" }), discovery, (req, res) => {
      const { status, payload } = registerClient(req.body ?? {}, staticToken);
      res.status(status).json(payload);
    });

    app.use("/authorize", (_req, res, next) => {
      res.set("Cache-Control", "no-store");
      setFrameDenyHeaders(res);
      next();
    });

    app.get("/authorize", async (req, res) => {
      const params = authorizeParams(req.query as Record<string, string | undefined>);
      const result = await beginAuthorize(params, staticToken, originOf(req));
      sendAuthorizeResult(res, result);
    });

    app.post("/authorize", express.urlencoded({ extended: false }), async (req, res) => {
      const body = (req.body ?? {}) as Record<string, string | undefined>;
      const params = authorizeParams(body);
      // The deployment token plays two roles here: the value the operator must enter to
      // approve (`expectedToken`), and the HMAC key everything is signed with (`secret`).
      const result = await completeAuthorize(
        params,
        body["token"] ?? "",
        /* expectedToken */ staticToken,
        /* secret */ staticToken,
        originOf(req),
        new URL("/mcp", originOf(req)).href,
      );
      sendAuthorizeResult(res, result);
    });

    app.post("/token", express.urlencoded({ extended: false }), discovery, async (req, res) => {
      const form = new URLSearchParams(req.body as Record<string, string>);
      const result = await exchangeToken(form, staticToken, new URL("/mcp", originOf(req)).href);
      if (result.ok) {
        res.json(result.payload);
      } else {
        res.status(result.status).json({ error: result.error, error_description: result.description });
      }
    });
  }

  /** Handles one MCP request with its own server + transport, then disposes of both. */
  async function handleMcp(req: Request, res: Response): Promise<void> {
    // A session signed in on another instance, or before a restart, is picked up here.
    await syncSession(config);
    await ensureKeepAliveOnRequest(config);
    const server = createServer(config);
    const transport = new NodeStreamableHTTPServerTransport({
      sessionIdGenerator: undefined, // stateless: never mint or require a session id
      // No tool streams progress any more — signing in happens at /setup, in a browser. SSE
      // stays on regardless: it is the transport the 2026-07-28 revision expects, and turning it
      // off would silently drop any notification a future tool wants to send.
      enableJsonResponse: false,
      supportedProtocolVersions: SUPPORTED_PROTOCOL_VERSIONS,
    });

    res.on("close", () => {
      void transport.close();
      void server.close();
    });

    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error(`[${SERVER_NAME}] request failed:`, err);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: "2.0",
          error: { code: -32603, message: "Internal server error." },
          id: null,
        });
      }
    }
  }

  // Header/body cross-validation runs after auth (so unauthenticated callers learn nothing
  // about request shape) but before the transport, which does not enforce it in SDK v2.0.0.
  //
  // A dead Learn session is deliberately NOT surfaced as a 401 here. That challenge makes a
  // client re-run this connector's own OAuth, which cannot establish a Brightspace session and
  // leaves the user in a loop. The tools report it instead, naming the /setup URL that can.
  const mcpMiddleware = config.authToken
    ? [
        requireBearerAuth({
          verifier: combinedVerifier(config.authToken, SERVER_NAME, [
            new URL("/mcp", resourceServerUrl).href,
            // The loopback aliases a local deployment is reached by interchangeably.
            ...(config.publicUrl
              ? []
              : [`http://127.0.0.1:${config.port}/mcp`, `http://[::1]:${config.port}/mcp`]),
          ]),
          resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resourceServerUrl),
          requiredScopes: [],
        }),
        validateMirroredHeaders(CURRENT_PROTOCOL_VERSION),
      ]
    : [validateMirroredHeaders(CURRENT_PROTOCOL_VERSION)];

  app.post("/mcp", ...mcpMiddleware, handleMcp);

  // 2026-07-28 removed the GET stream and session teardown. 405 is the documented answer for
  // clients still speaking an older revision.
  for (const method of ["get", "delete"] as const) {
    app[method]("/mcp", (_req, res) => {
      res.status(405).set("Allow", "POST").json({
        jsonrpc: "2.0",
        error: {
          code: -32000,
          message: "This server is stateless (MCP 2026-07-28); use POST.",
        },
        id: null,
      });
    });
  }

  return app;
}
