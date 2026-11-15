/**
 * Quicklinks — the `quickLink.d2l?...&rcode=...` URLs Brightspace puts in course pages.
 *
 * A course page almost never links a topic by id. It links a quicklink, whose `rcode` is an
 * opaque handle that resolves server-side to whatever it points at. Reading a page therefore
 * leaves a caller holding links it cannot use: the ids every other tool wants are on the far
 * side of a redirect.
 *
 * Following that redirect is the whole job. The landing URL says what the link was — a content
 * topic, a rubric, an assignment folder, a file in the course directory — and carries the id,
 * which is then usable with `get_file`, `get_rubric_definition`, `get_submissions`, and the
 * rest.
 *
 * Quizzes are the deliberate exception: a quiz quicklink is reported, never followed. This
 * server reads; it does not open quizzes, and a quiz is the one place where fetching a page
 * could plausibly be mistaken for starting something.
 */

import { type D2LClient, D2LError, resolveSameOriginUrl } from "./client.js";

const QUICKLINK_PATH = "/d2l/common/dialogs/quickLink/quickLink.d2l";

export type QuickLinkKind =
  | "topic"
  | "file"
  | "rubric"
  | "dropbox"
  | "quiz"
  | "discussion"
  | "other";

export interface ResolvedLink {
  kind: QuickLinkKind;
  /** Where the link landed, host-relative. Null for a link that was deliberately not followed. */
  path: string | null;
  /** The id the landing page names, when its kind has one. */
  id: number | null;
  /** Set for a file: the course path `get_file` takes. */
  filePath: string | null;
  /** Why a link was not followed, when it was not. */
  note: string | null;
}

/** Quiz quicklinks are recognised by their own query string before anything is fetched. */
function isQuizLink(url: string): boolean {
  return /[?&]type=quiz(&|$)/i.test(url);
}

/**
 * Follows a quicklink and reports what it points at.
 *
 * `link` is a quicklink URL as it appears in a page, or a bare `rcode` — the second is what a
 * reader usually has after scraping, and it is meaningless without the course, so the course
 * id is what turns it back into a URL.
 */
export async function resolveQuickLink(
  client: D2LClient,
  courseId: number,
  link: string,
): Promise<ResolvedLink> {
  const url = toQuickLinkUrl(courseId, link.trim(), client.host);

  if (isQuizLink(url)) {
    return {
      kind: "quiz",
      path: null,
      id: null,
      filePath: null,
      note:
        "Quiz quicklink, not followed. This server does not open quizzes. Use list_assignments " +
        "to see the quiz, and take it in Brightspace.",
    };
  }

  // Resolve same-origin redirects only so third-party origins never receive cookies or requests.
  const landedUrl = await client.resolveRedirectTarget(url);
  const landed = new URL(landedUrl);
  if (landed.origin !== new URL(client.host).origin) {
    return {
      kind: "other",
      path: landedUrl,
      id: null,
      filePath: null,
      note: "Resolved to an external URL; not followed.",
    };
  }

  return describe(landed.pathname + landed.search);
}

/** Classifies a landing path. Exported for callers that already have one. */
export function describe(path: string): ResolvedLink {
  const base = { path, filePath: null as string | null, note: null as string | null };

  if (path.startsWith("/content/enforced/")) {
    return { ...base, kind: "file", id: null, filePath: path.split(/[?#]/)[0] ?? path };
  }

  const topic = /\/d2l\/le\/content\/\d+\/viewContent\/(\d+)/.exec(path)?.[1];
  if (topic) return { ...base, kind: "topic", id: Number(topic) };

  const rubric = /[?&]rubricId=(\d+)/i.exec(path)?.[1];
  if (rubric) return { ...base, kind: "rubric", id: Number(rubric) };

  const dropbox = /[?&]db=(\d+)/i.exec(path)?.[1];
  if (dropbox) return { ...base, kind: "dropbox", id: Number(dropbox) };

  const discussion = /\/d2l\/le\/\d+\/discussions\/topics\/(\d+)/.exec(path)?.[1];
  if (discussion) return { ...base, kind: "discussion", id: Number(discussion) };

  return { ...base, kind: "other", id: null };
}

/**
 * Accepts only a bare `rcode` or a `/d2l/common/dialogs/quickLink/quickLink.d2l` path/URL
 * on the configured D2L host.
 */
export function toQuickLinkUrl(courseId: number, link: string, host: string): string {
  if (!link) throw new Error("No link was given.");

  if (link.startsWith("/") || /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(link)) {
    const resolved = resolveSameOriginUrl(host, link);
    const parsed = new URL(resolved);
    if (parsed.pathname !== QUICKLINK_PATH) {
      throw new D2LError(
        `Only ${QUICKLINK_PATH} URLs or bare rcodes are allowed in resolve_link.`,
        400,
        resolved,
      );
    }
    return parsed.pathname + parsed.search;
  }

  if (/[:/\\?#\s]/.test(link)) {
    throw new D2LError("Invalid quicklink rcode.", 400, link);
  }

  // A bare code, e.g. "uWaterloo-594354". Type is left out on purpose: Brightspace resolves the
  // code without it, and guessing a wrong type is worse than omitting it.
  return `${QUICKLINK_PATH}?ou=${courseId}&rcode=${encodeURIComponent(link)}`;
}
