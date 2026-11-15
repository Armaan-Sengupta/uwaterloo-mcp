# UWaterloo MCP (Hardened Fork)

Connect your **UWaterloo Learn**, **Piazza**, and **Crowdmark** accounts to **Claude**, **ChatGPT**, and **Claude Code**.

Strictly **read-only**: reads course materials, announcements, grades, assignments, dropbox receipts, due-date changes, quizzes, Crowdmark assessments/grades/groups, and Piazza discussions. Never submits coursework, posts discussions, edits grades, or sends email.

Originally created by [Zayd Syed (`syed-zayd/uwaterloo-mcp`)](https://github.com/syed-zayd/uwaterloo-mcp) under the MIT License.

---

## Security & Safe Self-Hosting

This hardened fork is designed for private single-tenant self-hosting:

- **Loopback bind by default**: `docker-compose.yml` publishes `127.0.0.1:8787:8787` (never `0.0.0.0:8787` on the host) and the server defaults `HOST=127.0.0.1`. Expose externally only through TLS-terminating tunnels/reverse proxies (`cloudflared`, Tailscale Serve, Caddy, nginx) with `MCP_PUBLIC_URL` configured.
- **No localhost auth bypass**: Every management and keep-alive route (`/setup`, `/setup/duo-passcode`, `/api/keep-alive`, `/calendar.ics`, `/mcp`) requires your `MCP_AUTH_TOKEN` (or its signed `uwmcp_setup` device cookie, or `CRON_SECRET` for `/api/keep-alive`) unless you explicitly opt out with `MCP_ALLOW_UNAUTHENTICATED=true`.
- **Encrypted local session storage by default**: `.session.enc` is encrypted with AES-256-GCM and `0600` file permissions using `SESSION_ENCRYPTION_KEY` (when set, recommended) or `MCP_AUTH_TOKEN`. Vercel Blob is optional and only used when explicitly configured (fail-closed `private` access only).
- **Minimal credential retention**: "Remember credentials" on `/setup` is unchecked by default. WatIAM credentials are dropped immediately if rejected (`invalid_credentials`).
- **Strict host allowlists & SSRF guards**: D2L requests, redirects, QuickLinks, page links, Brightspace Rubric Siren bearer tokens, Crowdmark requests, and OAuth CIMD metadata fetches validate origins and block internal/private/metadata IPs.

### Setup Steps

1. Copy `.env.example` to `.env` and set a strong `MCP_AUTH_TOKEN` and separate `SESSION_ENCRYPTION_KEY`:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
   ```
   *(If you run Node directly without `MCP_AUTH_TOKEN`, a random token is generated once and written to `.env` with `0600` permissions — never printed to logs.)*
2. Start locally or with Docker:
   ```bash
   docker compose up -d
   # or without Docker (Node 22+ and Chrome/Chromium):
   npm ci && npm run build && npm start
   ```
3. Open **[http://127.0.0.1:8787/setup](http://127.0.0.1:8787/setup)** in your browser, paste your `MCP_AUTH_TOKEN`, and sign in to Learn (and optionally Piazza / Crowdmark).

---

## Duo MFA (SMS / Passcode First, Never Auto-Push)

- Interactive sign-in (`/setup`) prefers **Text message / SMS** and **Duo Mobile Passcode** options and **never automatically triggers Duo Push** notifications.
- You can enter a Duo passcode directly in `/setup`, OR configure a pluggable provider:
  - `UWATERLOO_DUO_PASSCODE` — one-shot passcode consumed on first read.
  - `UWATERLOO_DUO_PASSCODE_FILE` — path to a file whose first line is a passcode.
  - `UWATERLOO_DUO_PASSCODE_HOOK` (plus optional JSON `UWATERLOO_DUO_PASSCODE_HOOK_ARGS`) — executable invoked via `execFile` with `shell: false` (passcode read from stdout; `UWATERLOO_DUO_USERNAME` and `UWATERLOO_DUO_ATTEMPT` passed via environment and argv). Example JSON array:
    ```env
    UWATERLOO_DUO_PASSCODE_HOOK=["/usr/local/bin/read-duo-sms.sh","--recent"]
    ```
- Background / silent keep-alive runs in `mode: "silent"` and **never triggers a Duo Push or prompts for a passcode**. After failures (`invalid_credentials`, `duo_required`, or 3 consecutive failures with exponential backoff), keep-alive automatically disables itself until you sign in again at `/setup`.

---

## Keep-Alive Timer (`systemd` / `cron`, No LLM)

Keep Brightspace's 180-minute sliding session alive every 45 minutes using the standalone silent script:

```bash
npm run build
node dist/scripts/keep-alive.js
# or in dev:
npx tsx scripts/keep-alive.ts
```

- **systemd**: copy `deploy/uwaterloo-mcp-keepalive.service` and `deploy/uwaterloo-mcp-keepalive.timer` to `/etc/systemd/system/`, update paths, and run `systemctl enable --now uwaterloo-mcp-keepalive.timer`.
- **cron**: see `deploy/crontab.example` for both local script invocation and `/api/keep-alive` with `CRON_SECRET`.

---

## Calendar Export (ICS / Google Calendar)

Export upcoming LEARN deadlines in standard RFC 5545 iCalendar format (no Google API key required):

- **MCP tool**: ask your assistant to call `export_due_dates_ics` and save the `.ics` output, then import it in Google Calendar (**Settings → Import & export → Import**).
- **Live subscription URL**: `GET /calendar.ics?token=<derived-token>` (visible when logged in to `/setup` or returned by `export_due_dates_ics` when `MCP_PUBLIC_URL` is configured). In Google Calendar, choose **Other calendars (+) → From URL** and paste the subscription URL. You can also fetch `/calendar.ics` directly with `Authorization: Bearer <MCP_AUTH_TOKEN>`.

---

## Crowdmark Setup (Read-Only)

Crowdmark support is strictly read-only (`crowdmark_list_courses`, `crowdmark_list_assessments`, `crowdmark_get_grades`, `crowdmark_list_groups`) and restricted to `app.crowdmark.com` / `crowdmark.com`:

1. Sign in to `https://app.crowdmark.com` in your browser.
2. Copy the `Cookie` request header from DevTools and paste it into the **Crowdmark (Read-Only)** card on `/setup` (or set `CROWDMARK_COOKIE` in `.env`).

---

## Connect Your AI Assistant

### Claude Desktop
Add to `claude_desktop_config.json`:
```json
{
  "mcpServers": {
    "uwaterloo": {
      "url": "http://127.0.0.1:8787/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_MCP_AUTH_TOKEN"
      }
    }
  }
}
```

### Claude Code CLI
```bash
claude mcp add uwaterloo http://127.0.0.1:8787/mcp --header "Authorization: Bearer YOUR_MCP_AUTH_TOKEN"
```

---

## Available Tools

### Learn
- **Courses & Upcoming**: `list_courses`, `get_upcoming`, `get_due_date_changes`, `export_due_dates_ics`, `get_announcements`, `get_classlist`, `list_groups`
- **Grades & Rubrics**: `get_grades`, `get_rubric`, `get_rubric_definition`
- **Assignments & Receipts**: `list_assignments`, `get_submissions`, `get_dropbox_receipts`, `get_submission_file`, `get_submission_file_url`
- **Course Content & Files**: `get_course_content`, `get_file`, `get_file_url`, `list_page_links`, `resolve_link`
- **Discussions & Quizzes**: `list_discussions`, `list_discussion_posts`, `get_discussion_thread`, `get_quiz_attempts`

### Piazza
- `piazza_list_courses`, `piazza_list_folders`, `piazza_search_posts`, `piazza_get_posts`

### Crowdmark (Read-Only)
- `crowdmark_list_courses`, `crowdmark_list_assessments`, `crowdmark_get_grades`, `crowdmark_list_groups`

---

## Development & Tests

```bash
npm ci
npx tsc --noEmit
npm test
```

---

## License

MIT — see [LICENSE](LICENSE). Original work copyright (c) 2026 Zayd Syed (`syed-zayd/uwaterloo-mcp`).
