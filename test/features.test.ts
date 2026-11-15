import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { CrowdmarkClient, CrowdmarkError } from "../src/crowdmark/client.js";
import { diffDueDateSnapshots } from "../src/d2l/dueDateDiff.js";
import { calendarToken, generateDueDatesIcs, verifyCalendarToken } from "../src/d2l/ics.js";
import { computeLateStatus } from "../src/d2l/submissions.js";
import {
  EnvDuoPasscodeProvider,
  FileDuoPasscodeProvider,
  HookDuoPasscodeProvider,
  ManualPasscodeCoordinator,
} from "../src/duoPasscode.js";

test("generateDueDatesIcs emits valid CRLF RFC 5545 calendar with deterministic UIDs and escaped text", () => {
  const ics = generateDueDatesIcs(
    [
      {
        courseId: 101,
        courseName: "CS 240, Sec 001",
        kind: "assignment",
        id: 55,
        name: "Assignment 1; Trees & Heaps",
        dueDate: "2026-03-10T23:59:00.000Z",
        submitted: false,
        outOf: 100,
      },
    ],
    { now: new Date("2026-03-01T12:00:00.000Z"), d2lHost: "https://learn.uwaterloo.ca" },
  );

  assert.equal(ics.includes("\r\n"), true);
  assert.match(ics, /^BEGIN:VCALENDAR\r\n/);
  assert.match(ics, /\r\nUID:uwaterloo-mcp-101-assignment-55@learn\.uwaterloo\.ca\r\n/);
  assert.match(ics, /\r\nDTSTAMP:20260301T120000Z\r\n/);
  assert.match(ics, /\r\nDTSTART:20260310T235900Z\r\n/);
  assert.match(ics, /CS 240\\, Sec 001.*Assignment 1\\; Trees & Heaps/);
  assert.match(ics, /\r\nEND:VCALENDAR\r\n$/);

  // Every unfolded CRLF line is <= 75 UTF-8 bytes
  for (const line of ics.split("\r\n")) {
    assert.ok(Buffer.byteLength(line, "utf8") <= 75, `Line exceeded 75 bytes: ${line}`);
  }

  // Purpose-bound calendar token verification
  const secret = "test-secret-0123456789abcdef";
  const token = calendarToken(secret);
  assert.equal(verifyCalendarToken(token, secret), true);
  assert.equal(verifyCalendarToken(token, "different-secret-0123456789"), false);
});

test("diffDueDateSnapshots initializes and detects added, changed, and removed due dates", () => {
  const day1 = diffDueDateSnapshots(
    null,
    [
      {
        courseId: 1,
        courseName: "MATH 239",
        kind: "assignment",
        id: 10,
        name: "A1",
        dueDate: "2026-02-01T23:59:00Z",
        submitted: false,
        outOf: 50,
      },
      {
        courseId: 1,
        courseName: "MATH 239",
        kind: "quiz",
        id: 20,
        name: "Quiz 1",
        dueDate: "2026-02-05T17:00:00Z",
        submitted: null,
        outOf: null,
      },
    ],
    new Date("2026-01-20T10:00:00Z"),
  );

  assert.equal(day1.result.initialized, true);
  assert.equal(day1.result.changes.length, 0);
  assert.equal(day1.nextSnapshot.items.length, 2);

  const day2 = diffDueDateSnapshots(
    day1.nextSnapshot,
    [
      {
        courseId: 1,
        courseName: "MATH 239",
        kind: "assignment",
        id: 10,
        name: "A1",
        dueDate: "2026-02-03T23:59:00Z", // moved back
        submitted: false,
        outOf: 50,
      },
      {
        courseId: 1,
        courseName: "MATH 239",
        kind: "assignment",
        id: 11,
        name: "A2",
        dueDate: "2026-02-12T23:59:00Z", // added
        submitted: false,
        outOf: 50,
      },
    ],
    new Date("2026-01-21T10:00:00Z"),
  );

  assert.equal(day2.result.initialized, false);
  assert.deepEqual(
    day2.result.changes.map((c) => [c.changeType, c.name, c.previousDueDate, c.newDueDate]),
    [
      ["changed", "A1", "2026-02-01T23:59:00Z", "2026-02-03T23:59:00Z"],
      ["added", "A2", null, "2026-02-12T23:59:00Z"],
      ["removed", "Quiz 1", "2026-02-05T17:00:00Z", null],
    ],
  );
});

test("computeLateStatus accurately computes on-time, late minutes, and missing due dates", () => {
  assert.deepEqual(computeLateStatus("2026-02-01T23:59:00Z", "2026-02-01T23:59:00Z"), {
    isLate: false,
    lateByMinutes: 0,
  });
  assert.deepEqual(computeLateStatus("2026-02-02T00:04:01Z", "2026-02-01T23:59:00Z"), {
    isLate: true,
    lateByMinutes: 6,
  });
  assert.deepEqual(computeLateStatus("2026-02-01T23:59:00Z", null), {
    isLate: null,
    lateByMinutes: null,
  });
});

test("Duo passcode providers (env, file, hook argv, manual coordinator)", async () => {
  // Env one-shot consumes on first read
  const env: Record<string, string | undefined> = { UWATERLOO_DUO_PASSCODE: "654321" };
  const envProvider = new EnvDuoPasscodeProvider(env);
  assert.equal(await envProvider.getPasscode({ username: "jdoe", attempt: 1 }), "654321");
  assert.equal(await envProvider.getPasscode({ username: "jdoe", attempt: 2 }), null);

  // Manual coordinator receives passcode asynchronously
  const coordinator = new ManualPasscodeCoordinator(5000);
  let capturedId = "";
  const manual = coordinator.createProvider((loginId) => {
    capturedId = loginId;
  });
  const waiting = manual.getPasscode({ username: "jdoe", attempt: 1 });
  // Triggered synchronously before waitPromise settles once microtask runs
  await Promise.resolve();
  assert.ok(capturedId);
  assert.equal(coordinator.submit(capturedId, " 789012 "), true);
  assert.equal(await waiting, "789012");

  // File & hook providers
  const dir = await mkdtemp(path.join(tmpdir(), "uwmcp-duo-"));
  try {
    const codeFile = path.join(dir, "code.txt");
    await writeFile(codeFile, "112233\nextra", "utf8");
    const fileProvider = new FileDuoPasscodeProvider(codeFile);
    assert.equal(await fileProvider.getPasscode({ username: "jdoe", attempt: 1 }), "112233");

    const scriptPath = path.join(dir, "hook.mjs");
    await writeFile(scriptPath, "#!/usr/bin/env node\nconsole.log('445566');\n", "utf8");
    await chmod(scriptPath, 0o755);
    const hook = HookDuoPasscodeProvider.fromEnv({
      UWATERLOO_DUO_PASSCODE_HOOK: JSON.stringify([process.execPath, scriptPath]),
    });
    assert.ok(hook);
    assert.equal(await hook.getPasscode({ username: "jdoe", attempt: 1 }), "445566");
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test("CrowdmarkClient enforces host allowlist, read-only GET, and parses JSON:API courses/grades/groups", async () => {
  assert.throws(
    () => new CrowdmarkClient({ host: "https://evil.example", cookie: "c=1" }),
    CrowdmarkError,
  );

  const client = new CrowdmarkClient(
    { host: "https://app.crowdmark.com", cookie: "_crowdmark_session=abc" },
    (async (url) => {
      const target = String(url);
      if (target.endsWith("/api/v2/courses")) {
        return new Response(
          JSON.stringify({
            data: [
              { id: "42", type: "courses", attributes: { name: "MATH 135", code: "MATH 135", term: "F26" } },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/vnd.api+json" } },
        );
      }
      if (target.endsWith("/api/v2/courses/42/assessments")) {
        return new Response(
          JSON.stringify({
            data: [
              { id: "900", type: "assessments", attributes: { title: "Midterm", "total-points": 60 } },
            ],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (target.includes("/api/v2/assessments/900")) {
        return new Response(
          JSON.stringify({
            data: { id: "900", type: "assessments", attributes: { title: "Midterm", "total-points": 60 } },
            included: [{ id: "1", type: "evaluations", attributes: { score: 54, status: "graded" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (target.endsWith("/api/v2/groups")) {
        return new Response(
          JSON.stringify({
            data: [{ id: "7", type: "groups", attributes: { name: "Team A" }, relationships: { members: { data: [{ id: "u1", type: "users" }] } } }],
            included: [{ id: "u1", type: "users", attributes: { name: "Jane Doe" } }],
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("Not Found", { status: 404 });
    }) as typeof fetch,
  );

  await assert.rejects(() => client.getJson("//evil.example/api/v2/me"), CrowdmarkError);
  const courses = await client.listCourses();
  assert.deepEqual(courses, [{ id: "42", name: "MATH 135", code: "MATH 135", term: "F26" }]);

  const grades = await client.getGrades();
  assert.equal(grades[0]?.score, 54);
  assert.equal(grades[0]?.outOf, 60);
  assert.equal(grades[0]?.percentage, 90);

  const groups = await client.listGroups();
  assert.deepEqual(groups[0]?.members, ["Jane Doe"]);
});
