/**
 * Optional UWaterloo WatIAM + Duo sign-in.
 *
 * Brightspace itself delegates to UWaterloo ADFS and Duo, so reproducing the exchange with raw
 * HTTP would mean reimplementing a JavaScript SAML client. A short-lived headless browser is
 * both less brittle and closer to what the user already does. The browser is closed after every
 * attempt; only the final learn.uwaterloo.ca cookies leave this module.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import chromium from "@sparticuz/chromium";
import puppeteer, { type Browser, type Frame, type Page } from "puppeteer-core";
import type { WaterlooCredentials } from "./config.js";
import { type DuoPasscodeProvider, getDuoPhoneLast4 } from "./duoPasscode.js";
import { validateCookie } from "./setup.js";
import type { StoredBrowserCookie } from "./sessionStore.js";

const WATERLOO_LEARN_HOST = "learn.uwaterloo.ca";
/**
 * The whole sign-in, Duo included. This is a human-paced wait: someone has to notice the
 * code, unlock a phone and type it, so it is generous. It stays under the 300s function
 * ceiling in vercel.json with room for the session check that follows.
 */
const DEFAULT_TIMEOUT_MS = 240_000;

/** How often to re-announce a pending Duo approval. Comfortably inside a 60s client idle window. */
const HEARTBEAT_INTERVAL_MS = 20_000;

export type WaterlooLoginFailure =
  | "invalid_credentials"
  | "duo_required"
  | "duo_sms_capped"
  | "duo_denied"
  | "duo_timeout"
  | "login_timeout"
  | "browser_unavailable"
  | "session_rejected";

export type WaterlooLoginMode = "silent" | "interactive" | "automatic";

export class WaterlooLoginError extends Error {
  constructor(
    readonly code: WaterlooLoginFailure,
    message: string,
  ) {
    super(message);
    this.name = "WaterlooLoginError";
  }
}

export interface WaterlooLoginResult {
  cookie: string;
  duoPrompted: boolean;
  /**
   * The UWaterloo, ADFS and Duo cookies the browser ended with. Handing them back to the next
   * sign-in carries Duo's "trust this browser" decision forward, so that one can often finish
   * without a phone.
   */
  browserCookies: StoredBrowserCookie[];
}

export interface WaterlooLoginOptions {
  timeoutMs?: number | undefined;
  mode?: WaterlooLoginMode | undefined;
  passcodeProvider?: DuoPasscodeProvider | undefined;
  phoneLast4?: string | undefined;
  /** Called immediately before clicking a Duo SMS button; returning false aborts with `duo_sms_capped`. */
  onBeforeSmsRequest?: (() => Promise<boolean> | boolean) | undefined;
  /** Called when a Duo SMS button is actually clicked, with the request epoch timestamp. */
  onSmsRequested?: ((requestedAt: number) => Promise<void> | void) | undefined;
  onEvent?: WaterlooLoginEventHandler | undefined;
  /** Cookies from a previous successful sign-in, restored before anything is opened. */
  browserCookies?: StoredBrowserCookie[] | undefined;
}

export type WaterlooLoginEvent =
  | { type: "duo_verification_code"; code: string }
  | { type: "duo_passcode_required"; loginId: string; hint?: string | undefined }
  /**
   * Emitted every HEARTBEAT_INTERVAL_MS while the Duo push is outstanding.
   *
   * Not cosmetic. MCP clients abort a tool call that goes quiet, and each progress
   * notification resets that idle clock — so without these the call is killed long before a
   * human finds their phone, however generous DEFAULT_TIMEOUT_MS is.
   */
  | { type: "duo_waiting"; code: string; secondsWaiting: number };

export type WaterlooLoginEventHandler = (
  event: WaterlooLoginEvent,
) => void | Promise<void>;

export type DuoPageAction =
  | "select_sms_passcode"
  | "select_passcode"
  | "enter_passcode"
  | "other_options"
  | "decline_trust"
  | "complete_trust"
  | "continue_after_approval";

interface FrameState {
  url: string;
  text: string;
  controls: string[];
  hasPasscodeInput?: boolean | undefined;
}

export interface DuoActionDecision {
  action: DuoPageAction;
  label: string;
}

/** Keep simultaneous calls on one warm instance from sending duplicate Duo pushes. */
let inFlight: Promise<WaterlooLoginResult> | null = null;
let lastClickDiagnostic = "";

export function signInUWaterloo(
  credentials: WaterlooCredentials,
  host: string,
  options: WaterlooLoginOptions = {},
): Promise<WaterlooLoginResult> {
  if (!inFlight) {
    inFlight = performSignIn(credentials, host, options).finally(() => {
      inFlight = null;
    });
  }
  return inFlight;
}

async function performSignIn(
  credentials: WaterlooCredentials,
  host: string,
  {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    mode = "interactive",
    passcodeProvider,
    phoneLast4,
    onBeforeSmsRequest,
    onSmsRequested,
    onEvent,
    browserCookies,
  }: WaterlooLoginOptions,
): Promise<WaterlooLoginResult> {
  const hostname = new URL(host).hostname.toLowerCase();
  if (hostname !== WATERLOO_LEARN_HOST) {
    throw new WaterlooLoginError(
      "browser_unavailable",
      `Automatic sign-in currently supports https://${WATERLOO_LEARN_HOST} only. ` +
        "The existing D2L_COOKIE setup still works for every institution.",
    );
  }

  let browser: Browser | undefined;
  let page: Page | undefined;
  let stage = "launch_browser";
  try {
    browser = await launchBrowser();
    page = await browser.newPage();
    page.setDefaultNavigationTimeout(30_000);
    page.setDefaultTimeout(30_000);

    if (browserCookies?.length) {
      stage = "restore_browser_cookies";
      await restoreCookies(browser, browserCookies);
    }

    stage = "open_learn_login";
    await page.goto(`${host}/d2l/login`, { waitUntil: "domcontentloaded" });
    stage = "wait_for_username";
    // Restored cookies can carry a live UWaterloo sign-in, in which case there is no form to
    // fill: the redirects land straight back in Learn.
    const remembered = await waitForUsernameOrSession(page, host);
    if (remembered) {
      console.info("[waterloo-login] Learn session received without a password", {
        duoPrompted: false,
      });
      return { cookie: remembered, duoPrompted: false, browserCookies: await keptCookies(browser) };
    }

    const username = credentials.username.includes("@")
      ? credentials.username
      : `${credentials.username}@uwaterloo.ca`;
    stage = "enter_username";
    await replaceInput(page, "#userNameInput", username);

    const passwordVisible = await page
      .$eval("#passwordInput", (element) => {
        const input = element as HTMLInputElement;
        const style = getComputedStyle(input);
        return style.display !== "none" && style.visibility !== "hidden" && input.offsetParent !== null;
      })
      .catch(() => false);
    if (!passwordVisible) {
      stage = "advance_to_password";
      await page.click("#nextButton");
      await page.waitForSelector("#passwordInput", { visible: true });
    }

    stage = "submit_credentials";
    await replaceInput(page, "#passwordInput", credentials.password);
    await page.click("#submitButton");

    stage = "wait_for_duo_or_learn";
    const session = await waitForSession(
      page,
      host,
      timeoutMs,
      mode,
      username,
      passcodeProvider,
      (nextStage) => {
        stage = nextStage;
      },
      {
        phoneLast4,
        onBeforeSmsRequest,
        onSmsRequested,
        onEvent,
      },
    );
    return { ...session, browserCookies: await keptCookies(browser) };
  } catch (error) {
    const location = page ? safePageLocation(page) : "browser-not-open";
    if (error instanceof WaterlooLoginError) {
      console.warn("[waterloo-login] sign-in stopped", {
        code: error.code,
        stage,
        location,
      });
      throw error;
    }
    const message = error instanceof Error ? error.message : String(error);
    console.error("[waterloo-login] browser failure", {
      stage,
      location,
      error: message,
    });
    const unavailable = /executable|browser process|failed to launch|could not find chrome/i.test(message);
    throw new WaterlooLoginError(
      unavailable ? "browser_unavailable" : "login_timeout",
      unavailable
        ? "The server could not start its private sign-in browser. Manual D2L_COOKIE setup is still available."
        : "UWaterloo sign-in did not finish. No existing D2L session was changed.",
    );
  } finally {
    await browser?.close().catch(() => undefined);
  }
}

async function launchBrowser(): Promise<Browser> {
  const systemChrome = findSystemChrome();
  const useServerlessChromium = process.platform === "linux" && !systemChrome;
  const executablePath = useServerlessChromium
    ? await chromium.executablePath()
    : systemChrome;

  if (!executablePath) {
    throw new WaterlooLoginError(
      "browser_unavailable",
      "No Chrome/Chromium executable is available on this host. Manual D2L_COOKIE setup is unchanged.",
    );
  }

  const headless = useServerlessChromium ? "shell" : true;
  const args = useServerlessChromium
    ? await puppeteer.defaultArgs({ args: chromium.args, headless })
    : ["--disable-dev-shm-usage", "--no-sandbox", "--disable-setuid-sandbox"];

  return puppeteer.launch({
    args,
    executablePath,
    headless,
    defaultViewport: { width: 1280, height: 900, deviceScaleFactor: 1 },
  });
}

function findSystemChrome(): string | undefined {
  const configured = process.env.PUPPETEER_EXECUTABLE_PATH?.trim();
  const candidates = [
    configured,
    process.platform === "win32"
      ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      : undefined,
    process.platform === "win32"
      ? "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
      : undefined,
    process.platform === "win32" && process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, "Google", "Chrome", "Application", "chrome.exe")
      : undefined,
    process.platform === "darwin"
      ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
      : undefined,
    process.platform === "linux" ? "/usr/bin/google-chrome" : undefined,
    process.platform === "linux" ? "/usr/bin/google-chrome-stable" : undefined,
    process.platform === "linux" ? "/usr/bin/chromium" : undefined,
    process.platform === "linux" ? "/usr/bin/chromium-browser" : undefined,
  ];
  return candidates.find((candidate): candidate is string => !!candidate && existsSync(candidate));
}

/** Puppeteer's cookie objects, narrowed to what survives a round trip through storage. */
async function restoreCookies(browser: Browser, cookies: StoredBrowserCookie[]): Promise<void> {
  const now = Date.now() / 1000;
  const live = cookies.filter((cookie) => cookie.expires <= 0 || cookie.expires > now);
  if (live.length === 0) return;
  await browser.setCookie(
    ...live.map((cookie) => ({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      ...(cookie.expires > 0 ? { expires: cookie.expires } : {}),
      ...(cookie.sameSite ? { sameSite: cookie.sameSite } : {}),
    })),
  );
}

/**
 * The cookies worth carrying into the next sign-in: those that UWaterloo or Duo set to outlive
 * the browser. Session cookies (no expiry) are deliberately dropped — a real browser forgets
 * them on close too, and replaying them would make this one behave unlike any browser Duo knows.
 * Learn's own cookies are dropped as well; they travel separately as the session itself.
 */
async function keptCookies(browser: Browser): Promise<StoredBrowserCookie[]> {
  const cookies = await browser.cookies().catch(() => []);
  return cookies
    .filter((cookie) => cookie.expires > 0)
    .filter((cookie) => !cookie.domain.replace(/^\./, "").endsWith(WATERLOO_LEARN_HOST))
    .map((cookie) => ({
      name: cookie.name,
      value: cookie.value,
      domain: cookie.domain,
      path: cookie.path,
      expires: cookie.expires,
      httpOnly: cookie.httpOnly ?? false,
      secure: cookie.secure,
      ...(cookie.sameSite && cookie.sameSite !== "Default" ? { sameSite: cookie.sameSite } : {}),
    }));
}

/** Resolves to a Learn cookie if the sign-in finished on its own, or null once the form shows. */
async function waitForUsernameOrSession(page: Page, host: string): Promise<string | null> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const cookie = await learnCookie(page, host);
    if (cookie) return cookie;
    const visible = await page
      .$eval("#userNameInput", (element) => (element as HTMLElement).offsetParent !== null)
      .catch(() => false);
    if (visible) return null;
    await delay(250);
  }
  throw new Error("UWaterloo's sign-in form did not appear.");
}

async function replaceInput(page: Page, selector: string, value: string): Promise<void> {
  await page.$eval(selector, (element) => {
    const input = element as HTMLInputElement;
    input.value = "";
  });
  await page.type(selector, value);
}

async function waitForSession(
  page: Page,
  host: string,
  timeoutMs: number,
  mode: WaterlooLoginMode,
  username: string,
  passcodeProvider: DuoPasscodeProvider | undefined,
  setStage: (stage: string) => void,
  hooks: Pick<
    WaterlooLoginOptions,
    "phoneLast4" | "onBeforeSmsRequest" | "onSmsRequested" | "onEvent"
  > = {},
): Promise<Omit<WaterlooLoginResult, "browserCookies">> {
  const { phoneLast4, onBeforeSmsRequest, onSmsRequested, onEvent } = hooks;
  const resolvedPhoneLast4 = phoneLast4 ?? getDuoPhoneLast4();
  const deadline = Date.now() + timeoutMs;
  const completedActions = new Set<string>();
  let duoPrompted = false;
  let emittedVerificationCode: string | undefined;
  let codeEmittedAt = 0;
  let lastHeartbeatAt = 0;
  let lastDebugState = "";
  let lastLocation = "";
  let passcodeAttempts = 0;
  let lastPasscodeAt = 0;
  let smsRequestedAt: number | undefined;

  while (Date.now() < deadline) {
    const location = safePageLocation(page);
    if (location !== lastLocation) {
      lastLocation = location;
      console.info("[waterloo-login] navigation", { location });
    }

    const cookie = await learnCookie(page, host);
    if (cookie) {
      setStage("learn_session_received");
      console.info("[waterloo-login] Learn session received", { duoPrompted });
      return { cookie, duoPrompted };
    }

    const frames = page.frames();
    const states = await Promise.all(frames.map((frame) => frameState(frame)));
    const combined = states.map((state) => state.text).join("\n").toLowerCase();

    const verificationCode = states
      .map((state) => extractDuoVerificationCode(state))
      .find((code): code is string => !!code);
    // Duo animates/re-renders this screen and can leave other three-digit values in its
    // accessibility text. The first complete verification code belongs to this push; never
    // replace it during the same attempt.
    if (verificationCode && !emittedVerificationCode) {
      emittedVerificationCode = verificationCode;
      codeEmittedAt = Date.now();
      lastHeartbeatAt = Date.now();
      duoPrompted = true;
      setStage("wait_for_duo_code_entry");
      console.info("[waterloo-login] Duo verification code received (not logged)");
      if (onEvent) {
        try {
          await onEvent({ type: "duo_verification_code", code: verificationCode });
        } catch (error) {
          console.warn("[waterloo-login] could not deliver Duo verification code", {
            error: error instanceof Error ? error.message : String(error),
          });
        }
      }
    }

    if (emittedVerificationCode && process.env.UWATERLOO_LOGIN_DEBUG === "1") {
      const debugState = states
        .filter((state) => /duo|duosecurity/i.test(`${state.url}\n${state.text}`))
        .map((state) => ({
          text: state.text
            .replace(/\b\d{3}\b/g, "***")
            .replace(/\s+/g, " ")
            .slice(0, 1_000),
          controls: state.controls,
        }));
      const serialized = JSON.stringify(debugState);
      if (serialized !== lastDebugState) {
        lastDebugState = serialized;
        console.info("[waterloo-login] Duo state", debugState);
      }
    }
    if (
      /incorrect (user id|username|password)|invalid (user id|username|password)|we can't sign you in/.test(
        combined,
      )
    ) {
      throw new WaterlooLoginError(
        "invalid_credentials",
        "UWaterloo rejected that username or password. The existing Learn session was not changed.",
      );
    }

    if (
      /login denied|request (?:was )?denied|you denied|authentication denied|duo push (?:was )?denied|verification (?:was )?denied/.test(
        combined,
      )
    ) {
      throw new WaterlooLoginError(
        "duo_denied",
        "The Duo request was denied. The existing D2L session was not changed.",
      );
    }
    if (/duo push (?:timed out|expired)|request expired|authentication timed out|verification timed out/.test(combined)) {
      throw new WaterlooLoginError(
        "duo_timeout",
        "The Duo request expired before approval. Run sign-in again interactively at /setup.",
      );
    }

    if (states.some(duoPushIsPending)) {
      duoPrompted = true;
      setStage("wait_for_duo_approval");
    }

    if (mode === "silent" && states.some(isInteractiveDuoChallenge)) {
      throw new WaterlooLoginError(
        "duo_required",
        "Silent re-login requires Duo verification. Sign in interactively at /setup (passcode flow).",
      );
    }

    const decisions = states
      .map((state, index) => ({
        state,
        frame: frames[index],
        decision: decideDuoAction(state, mode, { phoneLast4: resolvedPhoneLast4 }),
      }))
      .filter(
        (entry): entry is { state: FrameState; frame: Frame; decision: DuoActionDecision } =>
          !!entry.frame && !!entry.decision,
      )
      .sort((a, b) => actionPriority(a.decision.action) - actionPriority(b.decision.action));

    for (const { state, frame, decision } of decisions) {
      if (decision.action === "enter_passcode") {
        if (Date.now() - lastPasscodeAt < 2_500) continue;
        if (!passcodeProvider) {
          throw new WaterlooLoginError(
            "duo_required",
            "Duo passcode is required. Sign in interactively at /setup or configure a Duo passcode provider.",
          );
        }
        passcodeAttempts += 1;
        if (passcodeAttempts > 3) {
          throw new WaterlooLoginError(
            "duo_timeout",
            "Duo rejected the passcode after multiple attempts. Try signing in again at /setup.",
          );
        }
        setStage("wait_for_duo_passcode");
        const remainingMs = Math.max(1_000, deadline - Date.now());
        const abort = new AbortController();
        const timer = setTimeout(() => abort.abort(), remainingMs);
        let code: string | null = null;
        try {
          code = await passcodeProvider.getPasscode({
            username,
            attempt: passcodeAttempts,
            hint: extractDuoHint(state),
            requestedAt: smsRequestedAt,
            signal: abort.signal,
          });
        } finally {
          clearTimeout(timer);
        }
        if (!code) {
          throw new WaterlooLoginError(
            "duo_timeout",
            "No Duo passcode was provided before the sign-in window ended. Sign in at /setup to enter a passcode.",
          );
        }
        const submitted = await submitPasscodeInFrame(frame, code, decision.label);
        if (submitted) {
          lastPasscodeAt = Date.now();
          duoPrompted = true;
          setStage("enter_passcode");
          console.info("[waterloo-login] submitted Duo passcode");
        }
        break;
      }

      if (mode === "interactive" && emittedVerificationCode && decision.action === "other_options") continue;

      const actionKey = `${decision.action}:${normalizeLabel(decision.label)}`;
      if (completedActions.has(actionKey)) continue;

      if (decision.action === "select_sms_passcode" && onBeforeSmsRequest) {
        const allowed = await onBeforeSmsRequest();
        if (!allowed) {
          throw new WaterlooLoginError(
            "duo_sms_capped",
            "Daily Duo SMS request limit reached. Keep-alive is paused until tomorrow (America/Toronto) or manual sign-in at /setup.",
          );
        }
      }

      if (process.env.UWATERLOO_LOGIN_DEBUG === "1") {
        console.info("[waterloo-login] Duo decision", decision);
      }

      // A remembered passkey/security-key preference can open a native browser prompt. Escape
      // closes it so the Universal Prompt's "Other options" control is usable.
      if (
        decision.action === "other_options" &&
        /passkey|security key|touch id|windows hello/i.test(state.text)
      ) {
        await page.keyboard.press("Escape").catch(() => undefined);
      }

      const candidateSmsRequestedAt =
        decision.action === "select_sms_passcode" ? Date.now() : undefined;
      const clicked = await clickControl(frame, decision.label);
      if (!clicked) continue;

      completedActions.add(actionKey);
      setStage(decision.action);
      console.info("[waterloo-login] handled Duo page", { action: decision.action });
      if (decision.action === "select_sms_passcode" && candidateSmsRequestedAt !== undefined) {
        smsRequestedAt = candidateSmsRequestedAt;
        duoPrompted = true;
        await onSmsRequested?.(candidateSmsRequestedAt);
      } else if (decision.action === "select_passcode") {
        duoPrompted = true;
      }
      break;
    }

    // Keep the client's idle timer alive for as long as the push is genuinely outstanding.
    if (onEvent && emittedVerificationCode && Date.now() - lastHeartbeatAt >= HEARTBEAT_INTERVAL_MS) {
      lastHeartbeatAt = Date.now();
      try {
        await onEvent({
          type: "duo_waiting",
          code: emittedVerificationCode,
          secondsWaiting: Math.round((Date.now() - codeEmittedAt) / 1000),
        });
      } catch (error) {
        console.warn("[waterloo-login] could not deliver Duo heartbeat", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    await delay(500);
  }

  throw new WaterlooLoginError(
    duoPrompted ? "duo_timeout" : "login_timeout",
    duoPrompted
      ? "Duo verification was not completed before the sign-in window ended. Sign in again at /setup."
      : "UWaterloo sign-in did not reach Duo or Learn before the sign-in window ended.",
  );
}

async function learnCookie(page: Page, host: string): Promise<string | null> {
  const cookies = await page.browserContext().cookies();
  const relevant = cookies
    .filter((cookie) => cookie.domain.replace(/^\./, "").endsWith(WATERLOO_LEARN_HOST))
    .map((cookie) => `${cookie.name}=${cookie.value}`)
    .join("; ");
  const validated = validateCookie(relevant);
  return validated.ok ? validated.cookie : null;
}

async function frameState(frame: Frame): Promise<FrameState> {
  const url = frame.url();
  return frame
    .evaluate(() => {
      const passcodeSelector =
        "input[name='passcode'], input[name*='passcode' i], input[aria-label*='passcode' i], input[placeholder*='passcode' i], input[inputmode='numeric']";
      const hasPasscodeInput = Array.from(document.querySelectorAll<HTMLElement>(passcodeSelector)).some(
        (el) => el.offsetParent !== null && !(el as HTMLInputElement).disabled,
      );
      return {
        text: (document.body?.innerText ?? "").slice(0, 20_000),
        hasPasscodeInput,
        controls: Array.from(
          document.querySelectorAll<HTMLElement>(
            "button, input[type='button'], input[type='submit'], [role='button'], a",
          ),
        )
          .filter(
            (element) =>
              element.offsetParent !== null && element.getAttribute("aria-disabled") !== "true",
          )
          .map(
            (element) =>
              element.innerText ||
              (element as HTMLInputElement).value ||
              element.getAttribute("aria-label") ||
              "",
          ),
      };
    })
    .then((state) => ({ url, ...state }))
    .catch(() => ({ url, text: "", controls: [], hasPasscodeInput: false }));
}

function isTrustScreenText(text: string): boolean {
  return /trust (?:this|the) browser|remember (?:this|the) (?:browser|device)|is this your device|remember it for future logins/i.test(
    text,
  );
}

function isApprovedScreenText(text: string): boolean {
  return /\b(?:approved|success|verified|authentication complete|verification complete)\b/i.test(text);
}

function isDuoPage(state: Pick<FrameState, "url" | "text">): boolean {
  return /duo|duosecurity/i.test(`${state.url}\n${state.text}`);
}

/** True when a Duo frame requires human MFA interaction rather than silent trusted-browser flow. */
export function isInteractiveDuoChallenge(state: FrameState): boolean {
  if (!isDuoPage(state)) return false;
  if (isTrustScreenText(state.text) || isApprovedScreenText(state.text)) return false;
  if (state.hasPasscodeInput || duoPushIsPending(state)) return true;
  return state.controls.length > 0 || /passcode|duo push|verify|other options|security key|passkey/i.test(state.text);
}

function extractDuoHint(state: FrameState): string | undefined {
  const match = /\(([^)]*\d{4}[^)]*)\)|ending in (\d{4})/i.exec(state.text);
  return match?.[0];
}

function isSmsOptionLabel(normalized: string): boolean {
  if (/\bpush\b/.test(normalized)) return false;
  if (/\b(?:help|learn more|support|privacy|terms)\b/.test(normalized)) return false;
  if (/\b(?:text message|sms)\b/.test(normalized)) {
    return (
      /\b(?:passcode|code|send|text|me|to|\d{4})\b/.test(normalized) ||
      /^(?:text message|sms)$/.test(normalized)
    );
  }
  return /^(?:text me|send (?:a )?text|send sms|sms passcode|text message passcode|text passcode)\b/.test(
    normalized,
  );
}

function selectSmsControl(
  controls: ReadonlyArray<{ label: string; normalized: string }>,
  phoneLast4: string,
): { label: string; normalized: string } | undefined {
  const smsMatches = controls.filter(({ normalized }) => isSmsOptionLabel(normalized));
  if (smsMatches.length === 0) return undefined;
  if (smsMatches.length === 1) return smsMatches[0];

  const digits = phoneLast4.replace(/\D/g, "").slice(-4);
  if (digits.length === 4) {
    const last4Re = new RegExp(`\\b${digits}\\b`);
    const preferred = smsMatches.find(({ normalized }) => last4Re.test(normalized));
    if (preferred) return preferred;
  }

  const anyHaveDigits = smsMatches.some(({ normalized }) => /\b\d{4}\b/.test(normalized));
  return anyHaveDigits ? undefined : smsMatches[0];
}

/**
 * Chooses one safe transition from a Duo page snapshot.
 *
 * Never auto-clicks Duo Push. In `silent` mode, only trust-device and post-approval continue
 * actions are allowed; any MFA challenge returns null so the caller aborts without pushing.
 * In `automatic` mode, navigates via "Other options" to SMS text-message passcode (never Duo
 * Mobile passcode or Duo Push) and submits the provider code.
 * In `interactive` mode, prefers SMS text-message passcode, then Duo Mobile / bypass passcode,
 * then "Other options" to escape remembered push/passkey defaults.
 */
export function decideDuoAction(
  state: FrameState,
  mode: WaterlooLoginMode = "interactive",
  options: { phoneLast4?: string | undefined } = {},
): DuoActionDecision | null {
  if (!isDuoPage(state)) return null;

  const controls = state.controls.map((label) => ({ label, normalized: normalizeLabel(label) }));
  if (isTrustScreenText(state.text)) {
    const primary = controls.find(({ normalized }) => normalized === "yes this is my device");
    if (primary) return { action: "complete_trust", label: primary.label };

    const decline = controls.find(({ normalized }) =>
      /^(?:no )?(?:(?:do not|dont) trust(?: this| the)? browser|other people use this device|skip)$/.test(
        normalized,
      ),
    );
    if (decline) return { action: "decline_trust", label: decline.label };
  }

  if (isApprovedScreenText(state.text)) {
    const continueControl = controls.find(({ normalized }) =>
      /^(?:continue|continue to (?:login|sign in)|finish|done)$/.test(normalized),
    );
    if (continueControl) {
      return { action: "continue_after_approval", label: continueControl.label };
    }
  }

  // Silent mode never interacts with Duo MFA challenges or prompts for passcodes.
  if (mode === "silent") return null;

  if (state.hasPasscodeInput) {
    const verifyControl = controls.find(({ normalized }) =>
      /^(?:verify|log in|login|submit|continue)$/.test(normalized),
    );
    return { action: "enter_passcode", label: verifyControl?.label ?? "Verify" };
  }

  const smsPasscode = selectSmsControl(controls, options.phoneLast4 ?? "9915");
  if (smsPasscode) return { action: "select_sms_passcode", label: smsPasscode.label };

  if (mode === "interactive") {
    const passcode = controls.find(
      ({ normalized }) =>
        /\b(?:duo mobile passcode|bypass code|passcode)\b/.test(normalized) &&
        !/\bpush\b/.test(normalized),
    );
    if (passcode) return { action: "select_passcode", label: passcode.label };
  }

  const otherOptions = controls.find(({ normalized }) =>
    /^(?:other options|try another method|try another way|choose another option|use a different method)$/.test(
      normalized,
    ),
  );
  return otherOptions ? { action: "other_options", label: otherOptions.label } : null;
}

export function duoPushIsPending(state: Pick<FrameState, "url" | "text">): boolean {
  if (!isDuoPage(state)) return false;
  if (extractDuoVerificationCode(state)) return true;
  return /check (?:for )?a duo push|push (?:notification )?(?:has been |was )?sent|approve (?:the )?(?:login|notification|request)|waiting for (?:a )?(?:duo )?push|enter (?:the )?(?:verification )?code.*duo mobile|duo push sent/is.test(
    state.text,
  );
}

/** Extracts the short-lived Verified Duo Push code without matching unrelated page numbers. */
export function extractDuoVerificationCode(
  state: Pick<FrameState, "url" | "text">,
): string | null {
  if (!isDuoPage(state)) return null;

  const text = state.text.replace(/[\u00a0\s]+/g, " ").trim();
  const patterns = [
    /(?:verification|security|duo) code\D{0,80}(?<!\d)(\d(?:\s*\d){2})(?!\d)/i,
    /enter\D{0,80}(?<!\d)(\d(?:\s*\d){2})(?!\d)\D{0,80}(?:duo mobile|phone|app)/i,
    /(?<!\d)(\d(?:\s*\d){2})(?!\d)\D{0,80}(?:verification|duo mobile|phone|app)/i,
  ];
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (!match?.[1]) continue;
    const code = match[1].replace(/\s/g, "");
    if (/^\d{3}$/.test(code)) return code;
  }
  return null;
}

function actionPriority(action: DuoPageAction): number {
  if (action === "decline_trust" || action === "complete_trust") return 0;
  if (action === "continue_after_approval") return 1;
  if (action === "enter_passcode") return 2;
  if (action === "select_sms_passcode") return 3;
  if (action === "select_passcode") return 4;
  return 5;
}

async function submitPasscodeInFrame(
  frame: Frame,
  code: string,
  verifyButtonLabel: string,
): Promise<boolean> {
  const selector =
    "input[name='passcode'], input[name*='passcode' i], input[aria-label*='passcode' i], input[placeholder*='passcode' i], input[inputmode='numeric']";
  const input = await frame.$(selector).catch(() => null);
  if (!input) return false;
  await frame
    .$eval(selector, (el) => {
      const inp = el as HTMLInputElement;
      inp.value = "";
      inp.focus();
    })
    .catch(() => undefined);
  await input.type(code).catch(() => undefined);
  const clicked = await clickControl(frame, verifyButtonLabel);
  if (clicked) return true;
  await input.press("Enter").catch(() => undefined);
  return true;
}

function normalizeLabel(value: string): string {
  return value
    .normalize("NFKC")
    .replace(/[\u2018\u2019']/g, "")
    .replace(/[^a-zA-Z0-9]+/g, " ")
    .trim()
    .toLowerCase();
}

async function clickControl(frame: Frame, wantedLabel: string): Promise<boolean> {
  const result = await frame
    .evaluate(
      (wanted) => {
        const candidates = Array.from(
          document.querySelectorAll<HTMLElement>(
            "button, input[type='button'], input[type='submit'], [role='button'], a",
          ),
        );
        for (const candidate of candidates) {
          const label = (
            candidate.innerText ||
              (candidate as HTMLInputElement).value ||
              candidate.getAttribute("aria-label") ||
              ""
          )
            .normalize("NFKC")
            .replace(/[\u2018\u2019']/g, "")
            .replace(/[^a-zA-Z0-9]+/g, " ")
            .trim()
            .toLowerCase();
          if (label !== wanted) continue;
          if (
            candidate.offsetParent === null ||
            candidate.getAttribute("aria-disabled") === "true"
          ) {
            continue;
          }

          // Return the evaluation result before Duo replaces this frame. A synchronous click can
          // navigate quickly enough to reject the evaluate call even though the control worked.
          setTimeout(() => candidate.click(), 0);
          return { clicked: true, candidates: [] };
        }
        return {
          clicked: false,
          candidates: candidates.map((candidate) => ({
            tag: candidate.tagName.toLowerCase(),
            label: (
              candidate.innerText ||
                (candidate as HTMLInputElement).value ||
                candidate.getAttribute("aria-label") ||
                ""
            )
              .normalize("NFKC")
              .replace(/[\u2018\u2019']/g, "")
              .replace(/[^a-zA-Z0-9]+/g, " ")
              .trim()
              .toLowerCase(),
            visible: candidate.offsetParent !== null,
            disabled: candidate.getAttribute("aria-disabled"),
          })),
        };
      },
      normalizeLabel(wantedLabel),
    )
    .catch((error) => ({
      clicked: false,
      candidates: [],
      error: error instanceof Error ? error.message : String(error),
    }));

  if (!result.clicked && process.env.UWATERLOO_LOGIN_DEBUG === "1") {
    const diagnostic = JSON.stringify({ wanted: normalizeLabel(wantedLabel), ...result });
    if (diagnostic !== lastClickDiagnostic) {
      lastClickDiagnostic = diagnostic;
      console.info("[waterloo-login] Duo click diagnostic", JSON.parse(diagnostic));
    }
  }
  return result.clicked;
}

function safePageLocation(page: Page): string {
  try {
    const url = new URL(page.url());
    return `${url.hostname}${url.pathname}`;
  } catch {
    return "unknown";
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
