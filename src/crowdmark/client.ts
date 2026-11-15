/**
 * Read-only HTTP client and JSON:API normalizer for Crowdmark (app.crowdmark.com).
 *
 * Strictly restricted to `GET` requests against hosts in `CROWDMARK_ALLOWED_HOSTS` so
 * Crowdmark session cookies are never transmitted to arbitrary domains.
 */

import { CROWDMARK_ALLOWED_HOSTS } from "../config.js";

export interface CrowdmarkConfig {
  host: string;
  cookie: string;
  setupUrl?: string | undefined;
}

export interface CrowdmarkCourse {
  id: string;
  name: string;
  code: string | null;
  term: string | null;
}

export interface CrowdmarkAssessment {
  id: string;
  courseId: string | null;
  title: string;
  dueAt: string | null;
  totalPoints: number | null;
  status: string | null;
  submittedAt: string | null;
  isGroup: boolean;
}

export interface CrowdmarkGrade {
  assessmentId: string;
  courseId: string | null;
  title: string;
  score: number | null;
  outOf: number | null;
  percentage: number | null;
  status: string | null;
  gradedAt: string | null;
}

export interface CrowdmarkGroup {
  id: string;
  assessmentId: string | null;
  courseId: string | null;
  name: string | null;
  members: string[];
}

export class CrowdmarkError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly url?: string,
  ) {
    super(message);
    this.name = "CrowdmarkError";
  }
}

export class CrowdmarkSignedOutError extends CrowdmarkError {
  constructor(setupUrl?: string) {
    super(
      [
        "No Crowdmark session cookie is configured on this server.",
        `Add your Crowdmark Cookie header in ${setupUrl ?? "/setup"} (or set CROWDMARK_COOKIE) and try again.`,
      ].join(" "),
      401,
    );
    this.name = "CrowdmarkSignedOutError";
  }
}

export class CrowdmarkAuthError extends CrowdmarkError {
  constructor(status: number, setupUrl?: string, url?: string) {
    super(
      `Crowdmark rejected the session cookie (HTTP ${status}). Update your cookie in ${setupUrl ?? "/setup"} and try again.`,
      status,
      url,
    );
    this.name = "CrowdmarkAuthError";
  }
}

/** Validates that a base URL is HTTPS and on the Crowdmark host allowlist. */
export function validateCrowdmarkHost(rawHost: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(rawHost);
  } catch {
    throw new CrowdmarkError(`Invalid Crowdmark host URL: ${rawHost}`, 400, rawHost);
  }
  if (parsed.protocol !== "https:") {
    throw new CrowdmarkError("Crowdmark host must use https.", 400, rawHost);
  }
  if (parsed.username || parsed.password) {
    throw new CrowdmarkError("Crowdmark host must not contain embedded credentials.", 400, rawHost);
  }
  const hostname = parsed.hostname.toLowerCase();
  if (!CROWDMARK_ALLOWED_HOSTS.has(hostname)) {
    throw new CrowdmarkError(
      `Refusing disallowed Crowdmark host '${hostname}'; allowed: ${[...CROWDMARK_ALLOWED_HOSTS].join(", ")}.`,
      400,
      rawHost,
    );
  }
  return parsed;
}

/** Resolves a path strictly against the allowlisted Crowdmark host origin. */
export function resolveCrowdmarkUrl(host: string, path: string): string {
  const base = validateCrowdmarkHost(host);
  const trimmed = path.trim();
  if (
    !trimmed ||
    /[\r\n\0]/.test(trimmed) ||
    trimmed.startsWith("//") ||
    trimmed.startsWith("\\\\") ||
    trimmed.startsWith("/\\")
  ) {
    throw new CrowdmarkError("Refusing ambiguous Crowdmark request path.", 400, path);
  }
  let target: URL;
  try {
    target = /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)
      ? new URL(trimmed)
      : new URL(trimmed.startsWith("/") ? trimmed : `/${trimmed}`, base);
  } catch {
    throw new CrowdmarkError("Invalid Crowdmark request URL.", 400, path);
  }
  if (target.username || target.password || target.origin !== base.origin) {
    throw new CrowdmarkError(
      `Refusing cross-origin Crowdmark request to ${target.origin}; only ${base.origin} is allowed.`,
      400,
      target.toString(),
    );
  }
  return target.toString();
}

interface JsonApiResource {
  id?: string | number;
  type?: string;
  attributes?: Record<string, unknown>;
  relationships?: Record<
    string,
    { data?: { id?: string | number; type?: string } | Array<{ id?: string | number; type?: string }> | null }
  >;
}

interface JsonApiDocument {
  data?: JsonApiResource | JsonApiResource[] | null;
  included?: JsonApiResource[];
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asBoolean(value: unknown): boolean {
  return value === true;
}

function attr(res: JsonApiResource | Record<string, unknown>, ...keys: string[]): unknown {
  const source =
    "attributes" in res && res.attributes && typeof res.attributes === "object"
      ? (res.attributes as Record<string, unknown>)
      : (res as Record<string, unknown>);
  for (const key of keys) {
    if (key in source && source[key] !== undefined && source[key] !== null) {
      return source[key];
    }
  }
  return undefined;
}

function relId(res: JsonApiResource, ...keys: string[]): string | null {
  const rels = res.relationships;
  if (!rels) return null;
  for (const key of keys) {
    const data = rels[key]?.data;
    if (data && !Array.isArray(data) && data.id !== undefined) {
      return String(data.id);
    }
  }
  return null;
}

function extractResources(payload: unknown): { items: Array<JsonApiResource | Record<string, unknown>>; included: JsonApiResource[] } {
  if (Array.isArray(payload)) {
    return {
      items: payload.filter((x): x is Record<string, unknown> => Boolean(x && typeof x === "object")),
      included: [],
    };
  }
  if (payload && typeof payload === "object" && "data" in payload) {
    const doc = payload as JsonApiDocument;
    const items = Array.isArray(doc.data)
      ? doc.data
      : doc.data
        ? [doc.data]
        : [];
    return {
      items,
      included: Array.isArray(doc.included) ? doc.included : [],
    };
  }
  return { items: [], included: [] };
}

export class CrowdmarkClient {
  private readonly baseUrl: URL;
  private readonly fetchImpl: typeof fetch;

  constructor(
    private readonly config: CrowdmarkConfig,
    fetchFn: typeof fetch = fetch,
  ) {
    this.baseUrl = validateCrowdmarkHost(config.host);
    this.fetchImpl = fetchFn;
  }

  get host(): string {
    return this.baseUrl.origin;
  }

  /** Issues a read-only GET request strictly against the allowlisted Crowdmark host. */
  async getJson<T = unknown>(path: string): Promise<T> {
    if (!this.config.cookie.trim()) {
      throw new CrowdmarkSignedOutError(this.config.setupUrl);
    }

    let currentUrl = resolveCrowdmarkUrl(this.host, path);
    let response: Response | undefined;

    for (let hops = 0; hops < 4; hops++) {
      response = await this.fetchImpl(currentUrl, {
        method: "GET",
        headers: {
          Cookie: this.config.cookie,
          Accept: "application/vnd.api+json, application/json",
        },
        redirect: "manual",
        signal: AbortSignal.timeout(20_000),
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location") ?? "";
        await response.body?.cancel().catch(() => {});
        if (/sign[-_]?in|login/i.test(location)) {
          throw new CrowdmarkAuthError(response.status, this.config.setupUrl, currentUrl);
        }
        if (!location) {
          throw new CrowdmarkError("Crowdmark returned an empty redirect.", response.status, currentUrl);
        }
        currentUrl = resolveCrowdmarkUrl(this.host, new URL(location, currentUrl).toString());
        continue;
      }
      break;
    }

    if (!response || (response.status >= 300 && response.status < 400)) {
      throw new CrowdmarkError("Too many redirects from Crowdmark.", 502, currentUrl);
    }
    if (response.status === 401 || response.status === 403) {
      throw new CrowdmarkAuthError(response.status, this.config.setupUrl, currentUrl);
    }
    if (response.status === 404) {
      throw new CrowdmarkError("Crowdmark resource was not found.", 404, currentUrl);
    }
    if (!response.ok) {
      throw new CrowdmarkError(`Crowdmark returned HTTP ${response.status}.`, response.status, currentUrl);
    }

    const contentType = (response.headers.get("content-type") ?? "").toLowerCase();
    if (!contentType.includes("json")) {
      const snippet = (await response.text().catch(() => "")).slice(0, 400);
      if (/sign\s*in|log\s*in|users\/sign_in/i.test(snippet)) {
        throw new CrowdmarkAuthError(response.status, this.config.setupUrl, currentUrl);
      }
      throw new CrowdmarkError(
        "Crowdmark returned non-JSON content instead of API data.",
        response.status,
        currentUrl,
      );
    }

    return (await response.json()) as T;
  }

  /** Lightweight read-only session check for `/setup`. */
  async sessionStatus(): Promise<{ alive: true; user: string | null } | { alive: false; reason: string }> {
    if (!this.config.cookie.trim()) {
      return { alive: false, reason: "No Crowdmark cookie configured." };
    }
    try {
      const me = await this.getJson<JsonApiDocument | Record<string, unknown>>("/api/v2/me");
      const { items } = extractResources(me);
      const first = items[0] ?? (me as Record<string, unknown>);
      const user =
        asString(attr(first, "name", "full-name", "full_name", "email")) ?? null;
      return { alive: true, user };
    } catch (err) {
      if (err instanceof CrowdmarkError && err.status === 404) {
        try {
          await this.getJson("/api/v2/courses?page%5Bsize%5D=1");
          return { alive: true, user: null };
        } catch (fallbackErr) {
          return {
            alive: false,
            reason: fallbackErr instanceof Error ? fallbackErr.message : String(fallbackErr),
          };
        }
      }
      return { alive: false, reason: err instanceof Error ? err.message : String(err) };
    }
  }

  async listCourses(): Promise<CrowdmarkCourse[]> {
    let payload: unknown;
    try {
      payload = await this.getJson("/api/v2/courses");
    } catch (err) {
      if (err instanceof CrowdmarkError && err.status === 404) {
        payload = await this.getJson("/api/v2/enrollments?include=course");
      } else {
        throw err;
      }
    }

    const { items, included } = extractResources(payload);
    const byKey = new Map(included.map((r) => [`${r.type ?? ""}:${String(r.id ?? "")}`, r]));
    const courses: CrowdmarkCourse[] = [];
    const seen = new Set<string>();

    for (const item of items) {
      const res = item as JsonApiResource;
      let target: JsonApiResource | Record<string, unknown> = item;
      if (res.type === "enrollments" || res.type === "enrollment") {
        const courseId = relId(res, "course");
        const matched = courseId ? byKey.get(`courses:${courseId}`) ?? byKey.get(`course:${courseId}`) : undefined;
        if (matched) target = matched;
      }
      const id = String((target as JsonApiResource).id ?? attr(target, "id") ?? "").trim();
      if (!id || seen.has(id)) continue;
      seen.add(id);

      const name =
        asString(attr(target, "name", "title", "course-name", "course_name")) ?? `Course ${id}`;
      const code = asString(attr(target, "code", "course-code", "course_code", "short-name"));
      const term = asString(attr(target, "term", "semester", "term-name", "term_name"));
      courses.push({ id, name, code, term });
    }

    return courses;
  }

  async listAssessments(courseId?: string): Promise<CrowdmarkAssessment[]> {
    const courseIds = courseId ? [courseId] : (await this.listCourses()).map((c) => c.id);
    const perCourse = await Promise.all(
      courseIds.map(async (cid): Promise<CrowdmarkAssessment[]> => {
        let payload: unknown;
        try {
          payload = await this.getJson(`/api/v2/courses/${encodeURIComponent(cid)}/assessments`);
        } catch (err) {
          if (err instanceof CrowdmarkError && err.status === 404) {
            return [];
          }
          throw err;
        }
        const { items } = extractResources(payload);
        return items.map((raw) => {
          const res = raw as JsonApiResource;
          const id = String(res.id ?? attr(raw, "id") ?? "");
          return {
            id,
            courseId: relId(res, "course") ?? asString(attr(raw, "course_id", "course-id")) ?? cid,
            title: asString(attr(raw, "title", "name")) ?? `Assessment ${id}`,
            dueAt: asString(attr(raw, "due-at", "due_at", "due-date", "due_date")),
            totalPoints: asNumber(attr(raw, "total-points", "total_points", "points-possible", "max_points")),
            status: asString(attr(raw, "status", "submission-status", "submission_status")),
            submittedAt: asString(attr(raw, "submitted-at", "submitted_at")),
            isGroup: asBoolean(attr(raw, "is-group", "is_group", "group-assessment")),
          };
        });
      }),
    );
    return perCourse.flat();
  }

  async getGrades(options: { courseId?: string; assessmentId?: string } = {}): Promise<CrowdmarkGrade[]> {
    if (options.assessmentId) {
      const payload = await this.getJson(
        `/api/v2/assessments/${encodeURIComponent(options.assessmentId)}?include=submissions,evaluations`,
      );
      const { items, included } = extractResources(payload);
      return items.map((raw) => toGrade(raw, included, options.courseId ?? null));
    }

    const assessments = await this.listAssessments(options.courseId);
    const grades = await Promise.all(
      assessments.map(async (a): Promise<CrowdmarkGrade> => {
        try {
          const detail = await this.getJson(
            `/api/v2/assessments/${encodeURIComponent(a.id)}?include=submissions,evaluations`,
          );
          const { items, included } = extractResources(detail);
          if (items[0]) {
            return toGrade(items[0], included, a.courseId);
          }
        } catch (err) {
          if (!(err instanceof CrowdmarkError) || (err.status !== 404 && err.status !== 403)) {
            throw err;
          }
        }
        return {
          assessmentId: a.id,
          courseId: a.courseId,
          title: a.title,
          score: null,
          outOf: a.totalPoints,
          percentage: null,
          status: a.status,
          gradedAt: null,
        };
      }),
    );
    return grades;
  }

  async listGroups(courseId?: string): Promise<CrowdmarkGroup[]> {
    const paths = courseId
      ? [`/api/v2/courses/${encodeURIComponent(courseId)}/groups`, `/api/v2/groups?filter%5Bcourse%5D=${encodeURIComponent(courseId)}`]
      : ["/api/v2/groups"];

    let payload: unknown = null;
    for (let i = 0; i < paths.length; i++) {
      try {
        payload = await this.getJson(paths[i]!);
        break;
      } catch (err) {
        if (err instanceof CrowdmarkError && err.status === 404 && i < paths.length - 1) {
          continue;
        }
        if (err instanceof CrowdmarkError && err.status === 404) {
          return [];
        }
        throw err;
      }
    }

    const { items, included } = extractResources(payload);
    const includedMap = new Map(included.map((r) => [`${r.type ?? ""}:${String(r.id ?? "")}`, r]));
    return items.map((raw) => {
      const res = raw as JsonApiResource;
      const memberRefs = res.relationships?.members?.data;
      const memberNamesFromRel = Array.isArray(memberRefs)
        ? memberRefs.map((ref) => {
            const found = includedMap.get(`${ref.type ?? ""}:${String(ref.id ?? "")}`);
            return (
              (found && asString(attr(found, "name", "email"))) ||
              `Member ${String(ref.id ?? "")}`
            );
          })
        : [];
      const inlineMembers = Array.isArray((raw as Record<string, unknown>).members)
        ? ((raw as Record<string, unknown>).members as unknown[])
            .map((m) => (typeof m === "string" ? m : null))
            .filter((m): m is string => m !== null)
        : [];
      return {
        id: String(res.id ?? attr(raw, "id") ?? ""),
        assessmentId: relId(res, "assessment") ?? asString(attr(raw, "assessment_id", "assessment-id")),
        courseId: relId(res, "course") ?? asString(attr(raw, "course_id", "course-id")) ?? courseId ?? null,
        name: asString(attr(raw, "name", "title")),
        members: memberNamesFromRel.length > 0 ? memberNamesFromRel : inlineMembers,
      };
    });
  }
}

function toGrade(
  raw: JsonApiResource | Record<string, unknown>,
  included: JsonApiResource[],
  fallbackCourseId: string | null,
): CrowdmarkGrade {
  const res = raw as JsonApiResource;
  const evalResource = included.find(
    (inc) => inc.type === "evaluations" || inc.type === "evaluation" || inc.type === "submissions",
  );
  const score =
    asNumber(attr(raw, "score", "points", "grade", "earned-points", "earned_points")) ??
    (evalResource ? asNumber(attr(evalResource, "score", "points", "total-score", "total_score")) : null);
  const outOf =
    asNumber(attr(raw, "total-points", "total_points", "out-of", "out_of", "points-possible")) ??
    (evalResource ? asNumber(attr(evalResource, "total-points", "total_points")) : null);
  const percentage =
    score !== null && outOf !== null && outOf > 0 ? Math.round((score / outOf) * 10_000) / 100 : null;

  return {
    assessmentId: String(res.id ?? attr(raw, "id") ?? ""),
    courseId: relId(res, "course") ?? asString(attr(raw, "course_id", "course-id")) ?? fallbackCourseId,
    title: asString(attr(raw, "title", "name")) ?? `Assessment ${String(res.id ?? "")}`,
    score,
    outOf,
    percentage,
    status:
      asString(attr(raw, "grading-status", "grading_status", "status")) ??
      (evalResource ? asString(attr(evalResource, "status")) : null),
    gradedAt:
      asString(attr(raw, "graded-at", "graded_at")) ??
      (evalResource ? asString(attr(evalResource, "graded-at", "graded_at")) : null),
  };
}
