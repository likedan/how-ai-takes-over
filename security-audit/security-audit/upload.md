---
description: Upload a completed audit report to the platform and notify the user
argument-hint: <domain>
allowed-tools: [Bash, Read, Glob, Grep]
---

# Upload Security Audit Report

Upload a completed audit report for the given domain to the Prowl platform.

**Domain:** $ARGUMENTS

If no domain is provided, ask the user for the target domain.

## Steps

1. **Find the audit ID.** Query the platform for pending/in-progress audits matching this domain:
   ```bash
   cd ~/Documents/Github/security-audit
   source landing/.env.local
   curl -s "${API_BASE_URL:-http://localhost:3000}/api/admin/pending" \
     -H "Authorization: Bearer $REPORT_UPLOAD_API_KEY" | jq '.audits[] | select(.domain == "DOMAIN")'
   ```
   Replace `DOMAIN` with the actual domain. If multiple audits exist, pick the most recent pending one. If no pending audit exists, tell the user.

2. **Find the report files.** Look in the audit directory:
   ```
   audits/{domain-slug}/
   ```
   where `{domain-slug}` is the domain with dots replaced by hyphens (e.g., `platonagent.ai` → `platonagent-ai`).

   Expected files:
   - `report.md` — full report (required)
   - `executive-summary.md` — standalone exec summary (auto-sent if present)
   - `stats.json` — severity counts as `{"critical":N,"high":N,"medium":N,"low":N,"info":N}` (auto-sent if present)

   If `report.md` doesn't exist, check for any `.md` file in that directory and use it.

   **If `stats.json` is missing**, warn the user — the dashboard severity badges will show all zeros unless the report contains a parseable severity table as a fallback.

3. **Upload the report.** Run:
   ```bash
   cd ~/Documents/Github/security-audit
   ./scripts/upload-report.sh <auditId> <path-to-report.md>
   ```
   The script automatically picks up `executive-summary.md` and `stats.json` from the same directory.

4. **Report the result.** Show the user:
   - Domain uploaded
   - Severity counts (from stats.json or parsed)
   - Whether the "report ready" email was sent
   - Link to view: `/dashboard/<auditId>`
