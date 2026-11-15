/**
 * Environment file loading and safe token persistence for local/Docker runs.
 */

import { appendFileSync, chmodSync, existsSync, mkdirSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { loadEnvFile } from "node:process";
import { SERVER_NAME } from "./config.js";

/** Resolves a `.env` path under the persistent data directory when `LEARN_SESSION_FILE` is set. */
export function persistentEnvPath(env: Record<string, string | undefined> = process.env): string | null {
  const sessionFile = env.LEARN_SESSION_FILE?.trim();
  if (!sessionFile) return null;
  const dataDir = path.dirname(path.resolve(sessionFile));
  if (dataDir === path.resolve(".")) return null;
  return path.join(dataDir, ".env");
}

/** Loads `.env.local`, `.env`, and any persistent data-dir `.env` without overwriting existing vars. */
export function loadEnvFiles(): void {
  for (const envFile of [".env.local", ".env"]) {
    if (existsSync(envFile)) loadEnvFile(envFile);
  }
  const dataEnv = persistentEnvPath(process.env);
  if (dataEnv && existsSync(dataEnv)) {
    loadEnvFile(dataEnv);
  }
}

/**
 * Generates `MCP_AUTH_TOKEN` on first run when neither it nor `MCP_ALLOW_UNAUTHENTICATED=true`
 * is set, writing it to `.env` (preferring the persistent data directory) with mode `0o600`
 * and never printing the secret value to logs.
 */
export function ensureAuthToken(): void {
  if (process.env.MCP_AUTH_TOKEN || process.env.MCP_ALLOW_UNAUTHENTICATED === "true") return;

  const generated = randomBytes(32).toString("base64url");
  process.env.MCP_AUTH_TOKEN = generated;

  const candidates = [persistentEnvPath(process.env), path.resolve(".env")].filter(
    (p): p is string => Boolean(p),
  );

  for (const target of candidates) {
    try {
      mkdirSync(path.dirname(target), { recursive: true });
      appendFileSync(target, `\nMCP_AUTH_TOKEN="${generated}"\n`, { encoding: "utf8", mode: 0o600 });
      chmodSync(target, 0o600);
      console.log(
        `[${SERVER_NAME}] generated MCP_AUTH_TOKEN and saved it to ${target} (mode 0600; token value not logged).`,
      );
      return;
    } catch {
      // Try next candidate
    }
  }

  console.warn(
    `[${SERVER_NAME}] generated in-memory MCP_AUTH_TOKEN, but could not write .env. ` +
      "Set MCP_AUTH_TOKEN explicitly in your environment or .env to persist across restarts (token value not logged).",
  );
}
