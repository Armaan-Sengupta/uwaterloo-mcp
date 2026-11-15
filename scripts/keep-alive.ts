#!/usr/bin/env node
/**
 * Standalone LEARN session keep-alive runner (for systemd timers or cron).
 *
 * Strictly silent: verifies the current session cookie and, if expired, attempts a silent
 * trusted-browser re-login only. Never starts an LLM and never triggers a Duo Push.
 *
 * Usage:
 *   npx tsx scripts/keep-alive.ts
 *   node dist/scripts/keep-alive.js
 */

import { loadConfig } from "../src/config.js";
import { loadEnvFiles } from "../src/env.js";
import { pingLearnSession } from "../src/keepAlive.js";

async function main(): Promise<void> {
  loadEnvFiles();
  const loaded = loadConfig(process.env);
  if (!loaded.ok) {
    console.error("[keep-alive] Configuration error:", loaded.problems.join("; "));
    process.exitCode = 1;
    return;
  }
  const result = await pingLearnSession(loaded.config);
  const prefix = result.ok ? "[keep-alive] OK:" : "[keep-alive] FAIL:";
  console.log(`${prefix} ${result.message}`);
  process.exitCode = result.ok ? 0 : 1;
}

main().catch((err) => {
  console.error("[keep-alive] Unexpected error:", err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
});
