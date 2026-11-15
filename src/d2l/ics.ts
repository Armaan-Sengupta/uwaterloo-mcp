/**
 * RFC 5545 iCalendar (ICS) generator and calendar feed token helpers for LEARN due dates.
 *
 * Emits standard CRLF-delimited VCALENDAR / VEVENT text that can be imported into or subscribed
 * to by Google Calendar, Apple Calendar, or Outlook without requiring any Google API key.
 */

import { createHmac, timingSafeEqual } from "node:crypto";
import type { Deadline } from "./upcoming.js";

const CRLF = "\r\n";

/** Derives a purpose-bound calendar feed token from `MCP_AUTH_TOKEN`. */
export function calendarToken(authToken: string): string {
  return createHmac("sha256", authToken)
    .update("uwaterloo-mcp:calendar-ics:v1")
    .digest("base64url");
}

/** Constant-time verification for a `?token=` calendar subscription query parameter. */
export function verifyCalendarToken(provided: string, expectedAuthToken: string): boolean {
  const expected = calendarToken(expectedAuthToken);
  const a = Buffer.from(provided.trim(), "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Escapes text values per RFC 5545 Section 3.3.11. */
export function escapeIcsText(value: string): string {
  return value
    .replace(/\\/g, "\\\\")
    .replace(/\r\n|\r|\n/g, "\\n")
    .replace(/,/g, "\\,")
    .replace(/;/g, "\\;");
}

/** Formats an ISO/Date timestamp as UTC `YYYYMMDDTHHMMSSZ`. */
export function formatIcsUtc(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}` +
    `${pad(date.getUTCMonth() + 1)}` +
    `${pad(date.getUTCDate())}T` +
    `${pad(date.getUTCHours())}` +
    `${pad(date.getUTCMinutes())}` +
    `${pad(date.getUTCSeconds())}Z`
  );
}

/** Folds a single ICS content line at <= 75 UTF-8 octets per RFC 5545 Section 3.1. */
export function foldIcsLine(line: string): string {
  const bytes = Buffer.from(line, "utf8");
  if (bytes.length <= 75) return line;

  const parts: string[] = [];
  let current = "";
  let currentBytes = 0;
  let limit = 75;

  for (const ch of line) {
    const chBytes = Buffer.byteLength(ch, "utf8");
    if (currentBytes + chBytes > limit && current.length > 0) {
      parts.push(current);
      current = " " + ch;
      currentBytes = 1 + chBytes;
      limit = 75;
    } else {
      current += ch;
      currentBytes += chBytes;
    }
  }
  if (current.length > 0) parts.push(current);
  return parts.join(CRLF);
}

export interface GenerateIcsOptions {
  calendarName?: string;
  prodId?: string;
  now?: Date;
  d2lHost?: string;
}

/** Converts LEARN deadlines into an RFC 5545 VCALENDAR string. */
export function generateDueDatesIcs(
  deadlines: Deadline[],
  options: GenerateIcsOptions = {},
): string {
  const prodId = options.prodId ?? "-//uwaterloo-mcp//LEARN Due Dates//EN";
  const calName = options.calendarName ?? "UWaterloo LEARN Due Dates";
  const stamp = formatIcsUtc(options.now ?? new Date());
  let uidDomain = "learn.uwaterloo.ca";
  if (options.d2lHost) {
    try {
      uidDomain = new URL(options.d2lHost).hostname;
    } catch {
      // Keep default UID domain if custom host wasn't a full URL
    }
  }

  const lines: string[] = [
    "BEGIN:VCALENDAR",
    "VERSION:2.0",
    `PRODID:${escapeIcsText(prodId)}`,
    "CALSCALE:GREGORIAN",
    "METHOD:PUBLISH",
    `X-WR-CALNAME:${escapeIcsText(calName)}`,
  ];

  const sorted = [...deadlines]
    .filter((d) => !Number.isNaN(Date.parse(d.dueDate)))
    .sort((a, b) => Date.parse(a.dueDate) - Date.parse(b.dueDate) || a.id - b.id);

  for (const item of sorted) {
    const due = new Date(item.dueDate);
    const dueUtc = formatIcsUtc(due);
    const kindLabel = item.kind === "quiz" ? "Quiz" : "Assignment";
    const summary = `[${item.courseName}] ${item.name} (${kindLabel} Due)`;
    const descriptionParts = [
      `Course: ${item.courseName} (ID ${item.courseId})`,
      `Type: ${kindLabel}`,
      item.submitted === true
        ? "Status: Submitted"
        : item.submitted === false
          ? "Status: Not yet submitted"
          : "Status: Check Brightspace",
    ];
    if (item.outOf !== null) {
      descriptionParts.push(`Points: ${item.outOf}`);
    }

    lines.push(
      "BEGIN:VEVENT",
      `UID:uwaterloo-mcp-${item.courseId}-${item.kind}-${item.id}@${uidDomain}`,
      `DTSTAMP:${stamp}`,
      `DTSTART:${dueUtc}`,
      `DTEND:${dueUtc}`,
      `SUMMARY:${escapeIcsText(summary)}`,
      `DESCRIPTION:${escapeIcsText(descriptionParts.join("\n"))}`,
      "STATUS:CONFIRMED",
      "TRANSP:TRANSPARENT",
      "BEGIN:VALARM",
      "ACTION:DISPLAY",
      `DESCRIPTION:${escapeIcsText(`Reminder: ${item.name} due in 24 hours`)}`,
      "TRIGGER:-PT24H",
      "END:VALARM",
      "END:VEVENT",
    );
  }

  lines.push("END:VCALENDAR");
  return lines.map(foldIcsLine).join(CRLF) + CRLF;
}
