/**
 * Read-only Crowdmark MCP tools (`crowdmark_list_courses`, `crowdmark_list_assessments`,
 * `crowdmark_get_grades`, `crowdmark_list_groups`).
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { setupUrl, type Config } from "./config.js";
import { CrowdmarkClient, CrowdmarkError, CrowdmarkSignedOutError } from "./crowdmark/client.js";
import { syncSession } from "./sessionStore.js";

export const CROWDMARK_TOOL_NAMES = [
  "crowdmark_list_courses",
  "crowdmark_list_assessments",
  "crowdmark_get_grades",
  "crowdmark_list_groups",
] as const;

const readOnly = {
  readOnlyHint: true,
  destructiveHint: false,
  idempotentHint: true,
  openWorldHint: false,
} as const;

type ToolResult = {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
};

async function withCrowdmark(
  config: Config,
  fn: (client: CrowdmarkClient) => Promise<ToolResult>,
): Promise<ToolResult> {
  try {
    await syncSession(config);
    if (!config.crowdmark?.cookie) {
      throw new CrowdmarkSignedOutError(setupUrl(config));
    }
    const client = new CrowdmarkClient({ ...config.crowdmark, setupUrl: setupUrl(config) });
    return await fn(client);
  } catch (err) {
    const message =
      err instanceof CrowdmarkError
        ? err.message
        : err instanceof Error
          ? err.message
          : String(err);
    return {
      isError: true,
      content: [{ type: "text", text: message }],
    };
  }
}

export function registerCrowdmarkTools(server: McpServer, config: Config): void {
  server.registerTool(
    "crowdmark_list_courses",
    {
      title: "List Crowdmark courses",
      description:
        "List the student's enrolled courses on Crowdmark (read-only). Requires a Crowdmark session cookie configured in /setup or CROWDMARK_COOKIE.",
      annotations: readOnly,
    },
    async () =>
      withCrowdmark(config, async (client) => {
        const courses = await client.listCourses();
        if (courses.length === 0) {
          return {
            content: [{ type: "text", text: "No Crowdmark courses found." }],
            structuredContent: { courses },
          };
        }
        const lines = courses.map(
          (c) =>
            `${c.id}  ${c.name}${c.code ? ` (${c.code})` : ""}${c.term ? ` — ${c.term}` : ""}`,
        );
        return {
          content: [{ type: "text", text: lines.join("\n") }],
          structuredContent: { courses },
        };
      }),
  );

  server.registerTool(
    "crowdmark_list_assessments",
    {
      title: "List Crowdmark assessments",
      description:
        "List Crowdmark assessments across all enrolled courses or for a single Crowdmark course ID (read-only).",
      inputSchema: {
        courseId: z
          .string()
          .trim()
          .min(1)
          .optional()
          .describe("Optional Crowdmark course ID from crowdmark_list_courses"),
      },
      annotations: readOnly,
    },
    async ({ courseId }) =>
      withCrowdmark(config, async (client) => {
        const assessments = await client.listAssessments(courseId);
        if (assessments.length === 0) {
          return {
            content: [{ type: "text", text: "No Crowdmark assessments found." }],
            structuredContent: { assessments },
          };
        }
        const lines = assessments.map((a) => {
          const pts = a.totalPoints !== null ? ` (${a.totalPoints} pts)` : "";
          const due = a.dueAt ? ` due ${a.dueAt}` : "";
          const status = a.status ? ` [${a.status}]` : "";
          return `${a.id}  ${a.title}${pts}${due}${status}`;
        });
        return {
          content: [{ type: "text", text: lines.join("\n") }],
          structuredContent: { assessments },
        };
      }),
  );

  server.registerTool(
    "crowdmark_get_grades",
    {
      title: "Get Crowdmark grades",
      description:
        "Read graded Crowdmark scores for a course or a specific assessment (read-only).",
      inputSchema: {
        courseId: z.string().trim().min(1).optional().describe("Optional Crowdmark course ID"),
        assessmentId: z.string().trim().min(1).optional().describe("Optional Crowdmark assessment ID"),
      },
      annotations: readOnly,
    },
    async ({ courseId, assessmentId }) =>
      withCrowdmark(config, async (client) => {
        const grades = await client.getGrades({ courseId, assessmentId });
        if (grades.length === 0) {
          return {
            content: [{ type: "text", text: "No Crowdmark grades found." }],
            structuredContent: { grades },
          };
        }
        const lines = grades.map((g) => {
          const scoreStr =
            g.score !== null && g.outOf !== null
              ? `${g.score}/${g.outOf}${g.percentage !== null ? ` (${g.percentage}%)` : ""}`
              : g.score !== null
                ? `${g.score}`
                : "not yet graded";
          return `${g.assessmentId}  ${g.title}: ${scoreStr}${g.status ? ` [${g.status}]` : ""}`;
        });
        return {
          content: [{ type: "text", text: lines.join("\n") }],
          structuredContent: { grades },
        };
      }),
  );

  server.registerTool(
    "crowdmark_list_groups",
    {
      title: "List Crowdmark groups",
      description:
        "List group memberships on Crowdmark assessments or courses (read-only).",
      inputSchema: {
        courseId: z.string().trim().min(1).optional().describe("Optional Crowdmark course ID"),
      },
      annotations: readOnly,
    },
    async ({ courseId }) =>
      withCrowdmark(config, async (client) => {
        const groups = await client.listGroups(courseId);
        if (groups.length === 0) {
          return {
            content: [{ type: "text", text: "No Crowdmark groups found." }],
            structuredContent: { groups },
          };
        }
        const lines = groups.map(
          (g) =>
            `${g.id}  ${g.name ?? "Group"}${g.assessmentId ? ` (assessment ${g.assessmentId})` : ""}: ${g.members.join(", ") || "no members listed"}`,
        );
        return {
          content: [{ type: "text", text: lines.join("\n") }],
          structuredContent: { groups },
        };
      }),
  );
}
