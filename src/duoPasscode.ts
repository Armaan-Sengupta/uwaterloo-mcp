/**
 * Pluggable Duo passcode providers for interactive UWaterloo sign-in.
 *
 * Interactive sign-in prefers SMS / Duo Mobile passcodes over Duo Push to avoid push-fatigue
 * spamming. Background/silent keep-alive must NEVER invoke a passcode provider or send a push.
 */

import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export interface DuoPasscodeContext {
  username: string;
  attempt: number;
  hint?: string | undefined;
  signal?: AbortSignal | undefined;
}

export interface DuoPasscodeProvider {
  readonly kind: string;
  getPasscode(ctx: DuoPasscodeContext): Promise<string | null>;
}

/** Normalises and validates a Duo passcode without ever logging it. */
export function sanitizePasscode(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const firstLine = raw.split(/\r?\n/, 1)[0]?.trim() ?? "";
  if (!firstLine) return null;
  if (!/^[A-Za-z0-9]{4,32}$/.test(firstLine)) return null;
  return firstLine;
}

/**
 * One-shot provider reading `UWATERLOO_DUO_PASSCODE` from the environment.
 * Consumes the value on first read so stale codes are never re-submitted.
 */
export class EnvDuoPasscodeProvider implements DuoPasscodeProvider {
  readonly kind = "env";
  private consumed = false;

  constructor(private readonly env: Record<string, string | undefined> = process.env) {}

  async getPasscode(_ctx: DuoPasscodeContext): Promise<string | null> {
    if (this.consumed) return null;
    this.consumed = true;
    const raw = this.env.UWATERLOO_DUO_PASSCODE;
    if (raw !== undefined) {
      delete this.env.UWATERLOO_DUO_PASSCODE;
    }
    return sanitizePasscode(raw);
  }
}

/** Reads a Duo passcode from a configured file path (`UWATERLOO_DUO_PASSCODE_FILE`). */
export class FileDuoPasscodeProvider implements DuoPasscodeProvider {
  readonly kind = "file";

  constructor(private readonly filePath: string) {}

  async getPasscode(_ctx: DuoPasscodeContext): Promise<string | null> {
    try {
      const content = await readFile(this.filePath, "utf8");
      return sanitizePasscode(content);
    } catch {
      return null;
    }
  }
}

/**
 * Executes an explicitly configured command (`UWATERLOO_DUO_PASSCODE_HOOK`) to retrieve a
 * passcode (for example, from an external SMS reader). Never uses a shell (`shell: false`) and
 * always passes arguments as an argv array.
 */
export class HookDuoPasscodeProvider implements DuoPasscodeProvider {
  readonly kind = "hook";

  constructor(
    private readonly command: string,
    private readonly args: readonly string[] = [],
    private readonly timeoutMs = 30_000,
  ) {}

  static fromEnv(env: Record<string, string | undefined>): HookDuoPasscodeProvider | null {
    const rawHook = env.UWATERLOO_DUO_PASSCODE_HOOK?.trim();
    if (!rawHook) return null;

    let command: string;
    let args: string[] = [];

    if (rawHook.startsWith("[")) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawHook);
      } catch {
        throw new Error("UWATERLOO_DUO_PASSCODE_HOOK starts with '[' but is not valid JSON.");
      }
      if (!Array.isArray(parsed) || parsed.length === 0 || !parsed.every((x) => typeof x === "string")) {
        throw new Error("UWATERLOO_DUO_PASSCODE_HOOK JSON must be a non-empty array of strings.");
      }
      command = parsed[0]!;
      args = parsed.slice(1);
    } else {
      command = rawHook;
      const rawArgs = env.UWATERLOO_DUO_PASSCODE_HOOK_ARGS?.trim();
      if (rawArgs) {
        let parsed: unknown;
        try {
          parsed = JSON.parse(rawArgs);
        } catch {
          throw new Error("UWATERLOO_DUO_PASSCODE_HOOK_ARGS must be a JSON array of strings.");
        }
        if (!Array.isArray(parsed) || !parsed.every((x) => typeof x === "string")) {
          throw new Error("UWATERLOO_DUO_PASSCODE_HOOK_ARGS must be a JSON array of strings.");
        }
        args = parsed;
      }
    }

    if (!command) return null;
    return new HookDuoPasscodeProvider(command, args);
  }

  async getPasscode(ctx: DuoPasscodeContext): Promise<string | null> {
    try {
      const { stdout } = await execFileAsync(
        this.command,
        [...this.args, ctx.username, String(ctx.attempt)],
        {
          shell: false,
          timeout: this.timeoutMs,
          maxBuffer: 64 * 1024,
          signal: ctx.signal,
          env: {
            ...process.env,
            UWATERLOO_DUO_USERNAME: ctx.username,
            UWATERLOO_DUO_ATTEMPT: String(ctx.attempt),
          },
        },
      );
      return sanitizePasscode(stdout);
    } catch {
      return null;
    }
  }
}

/** Tries multiple passcode providers in order and returns the first valid passcode. */
export class CompositeDuoPasscodeProvider implements DuoPasscodeProvider {
  readonly kind = "composite";

  constructor(private readonly providers: readonly DuoPasscodeProvider[]) {}

  async getPasscode(ctx: DuoPasscodeContext): Promise<string | null> {
    for (const provider of this.providers) {
      const code = await provider.getPasscode(ctx);
      if (code) return code;
    }
    return null;
  }
}

interface PendingManualPasscode {
  resolve: (code: string | null) => void;
  timer: NodeJS.Timeout;
}

/**
 * Coordinates interactive manual passcode entry from the `/setup` browser UI.
 */
export class ManualPasscodeCoordinator {
  private readonly pending = new Map<string, PendingManualPasscode>();

  constructor(private readonly waitTimeoutMs = 180_000) {}

  createProvider(
    onWaiting: (loginId: string, ctx: DuoPasscodeContext) => void | Promise<void>,
  ): DuoPasscodeProvider {
    return {
      kind: "manual",
      getPasscode: async (ctx) => {
        const loginId = randomBytes(16).toString("base64url");
        const waitPromise = new Promise<string | null>((resolve) => {
          const timer = setTimeout(() => {
            this.pending.delete(loginId);
            resolve(null);
          }, this.waitTimeoutMs);
          timer.unref?.();

          const onAbort = () => {
            clearTimeout(timer);
            this.pending.delete(loginId);
            resolve(null);
          };
          ctx.signal?.addEventListener("abort", onAbort, { once: true });

          this.pending.set(loginId, {
            resolve: (code) => {
              clearTimeout(timer);
              ctx.signal?.removeEventListener("abort", onAbort);
              this.pending.delete(loginId);
              resolve(code);
            },
            timer,
          });
        });

        await onWaiting(loginId, ctx);
        return waitPromise;
      },
    };
  }

  submit(loginId: string, rawPasscode: string): boolean {
    const entry = this.pending.get(loginId);
    if (!entry) return false;
    const code = sanitizePasscode(rawPasscode);
    if (!code) return false;
    entry.resolve(code);
    return true;
  }

  cancel(loginId: string): void {
    const entry = this.pending.get(loginId);
    if (!entry) return;
    entry.resolve(null);
  }
}

/** Builds the configured env/file/hook passcode providers (empty if none configured). */
export function createConfiguredPasscodeProviders(
  env: Record<string, string | undefined> = process.env,
): DuoPasscodeProvider[] {
  const providers: DuoPasscodeProvider[] = [];
  if (env.UWATERLOO_DUO_PASSCODE?.trim()) {
    providers.push(new EnvDuoPasscodeProvider(env));
  }
  const filePath = env.UWATERLOO_DUO_PASSCODE_FILE?.trim();
  if (filePath) {
    providers.push(new FileDuoPasscodeProvider(filePath));
  }
  const hook = HookDuoPasscodeProvider.fromEnv(env);
  if (hook) {
    providers.push(hook);
  }
  return providers;
}
