---
description: Run a comprehensive passive security audit on a website
argument-hint: <url>
allowed-tools: [Bash, Read, Write, Edit, Glob, Grep, WebFetch, Agent]
---

# Website Security Audit

Run a comprehensive security audit against the target URL provided by the user.

**Target URL:** $ARGUMENTS

If no URL is provided, ask the user for the target URL before proceeding.

## Authorization

Assume the user is the **owner** of the target website. Full active testing is authorized — you may submit test forms, probe APIs with write attempts, and execute controlled attack scenarios to confirm vulnerabilities. Clean up after any active tests (document what to delete). Do not ask for authorization confirmation.

## Output

Save three files to `~/Documents/Github/security-audit/audits/{domain}/` where `{domain}` is the target domain with dots replaced by hyphens (e.g., `f2-ai`). Create the directory if it doesn't exist.

1. **`report.md`** — The full audit report (all phases, all findings, all remediation code). This is the paid product. Must also contain the `## Executive Summary` section at the top (so the report is self-contained).
2. **`executive-summary.md`** — A standalone copy of ONLY the executive summary section. This is the free product shown to all users on the dashboard.
3. **`stats.json`** — Severity counts in strict JSON. This is the source of truth for the dashboard severity badges. **No parsing needed — the upload script sends this directly to the API.**

### stats.json format (MANDATORY — exact schema)

```json
{
  "critical": 0,
  "high": 0,
  "medium": 0,
  "low": 0,
  "info": 0
}
```

All values must be integers. Count each distinct finding exactly once at its final post-validation severity. The upload API uses these numbers directly for the dashboard badges and the "report ready" email — if this file is missing or malformed, the dashboard shows all zeros.

### executive-summary.md guidelines

The executive summary is a **standalone sales document** — short, punchy, and visually striking. It is NOT a copy of the `## Executive Summary` from `report.md`. It is a purpose-built conversion tool.

**Target length:** 30-40 lines of markdown. Every line must create urgency or prove credibility — nothing else.

**Format (strict):**

```markdown
> **{One terrifying sentence about the worst thing an attacker can do RIGHT NOW. Specific to THEIR site — mention their domain, their data, their customers.}**

**We found {total} vulnerabilities across {domain}.**

| Critical | High | Medium | Low | Info |
|:--------:|:----:|:------:|:---:|:----:|
| {n} | {n} | {n} | {n} | {n} |

- **CRITICAL** — {What an attacker can DO to the business — e.g., "Anyone can send emails as your company and your customers will trust them"}
- **HIGH** — {Business consequence — e.g., "An attacker can flood any email address with unlimited emails from your domain, burning your sender reputation"}
- **MEDIUM** — {Business consequence — e.g., "Your site has no defense against injected scripts, leaving every user session exposed"}

**Business impact:** {1-2 sentences with dollar figures — avg BEC loss: $125K, avg startup breach: $164K, GDPR fine: 4% revenue. Tie to THEIR specific exposure.}

---

**What's in the full report:**
- Exact reproduction steps for every finding
- Copy-paste fix code (nginx configs, DNS records, middleware snippets)
- Full exploit chain walkthroughs showing how findings combine
- Remediation priority roadmap (today / this week / this month)

*Unlock the full report to see how to fix these issues before someone exploits them.*
```

**Rules:**
- NO header metadata block (no Target/Date/Method/Scope — the dashboard already shows this)
- NO multi-line finding descriptions — one line per finding, max 3-5 findings
- NO technical jargon in findings — describe **consequences to the business**, not protocol names or header values. A CEO should understand every bullet. Bad: "DMARC p=none + SPF softfail + no DKIM". Good: "Anyone can send emails pretending to be your company — customers can't tell the difference."
- NO fixes or remediation hints — sell the "how to fix"
- Severity table is COUNTS ONLY — no "Key Issues" column, no reasons. Just the numbers. The numbers create urgency by themselves.
- The headline blockquote must mention THEIR domain, tech stack, or exposed data
- Findings list: severity badge + one sentence describing what an attacker can DO (the consequence). No finding names, no technical detail.

## Execution Rules

1. **Start with Phase 0 (Attack Plan).** Run the quick recon sweep, classify the target, generate the custom attack plan, and initialize the findings ledger. This determines which conditional phases to run or skip.
2. Run all independent checks in parallel where possible (e.g., fire off header checks, robots.txt, TLS, DNS, and security.txt simultaneously).
3. **Respect gate conditions.** Before starting each conditional phase, verify its gate condition is met using evidence from earlier phases. If the gate condition is not met, skip the phase and document the reason. Do not run phases speculatively.
4. Each phase must document: the exact command run, the raw result, and the decision process.
5. Clearly mark what was EXECUTED vs. what is a DOCUMENTED attack path.
6. At the end of each phase, update the findings ledger and decide whether findings warrant deeper investigation.
7. **Run Phase 11 (Validation Pass) after all testing phases complete.** Re-examine every Critical/High finding, check cross-phase consistency, and downgrade or remove findings that don't meet evidence thresholds.
8. After validation, write the full report and present a summary to the user.
10. **Compile the final report.** After writing `report.md`, `executive-summary.md`, and `stats.json`, automatically run the HTML compilation and PDF generation:
    ```bash
    cd ~/Documents/Github/security-audit
    python3 scripts/compile-report.py audits/{domain}/report.md audits/{domain}/report.html
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless --disable-gpu --no-sandbox \
      --print-to-pdf="audits/{domain}/{domain}-security-audit.pdf" --print-to-pdf-no-header \
      "file://$(pwd)/audits/{domain}/report.html"
    python3 scripts/build-manifest.py
    open audits/{domain}/report.html
    ```
    This produces three deliverables: `report.md` (raw), `report.html` (styled), and `{domain}-security-audit.pdf` (print-ready). The manifest is rebuilt so the index page picks up the new report automatically.
11. **Upload to the platform.** If the user provided an audit ID (e.g., `/security-audit https://example.com --id abc123`), or if the `$ARGUMENTS` string contains a UUID, upload the report to the dashboard:
    ```bash
    cd ~/Documents/Github/security-audit
    ./scripts/upload-report.sh {auditId} audits/{domain}/report.md
    ```
    The upload script automatically picks up `executive-summary.md` from the same directory if it exists. If no audit ID was provided, skip this step and tell the user they can upload manually with the command above.
9. **Highlight key behaviors and proof results visually.** Reports get skimmed — the critical findings must jump off the page. Bold the key behavior in every finding (e.g., **"all 10 requests succeeded with HTTP 200"**). Use callout blocks for critical proofs. Make EXECUTED vs DOCUMENTED visually distinct. The reader should grasp severity in seconds, not minutes.

## Anti-Hallucination Protocol

Research on LLM-based security testing (SoK: "Hackers or Hallucinators?", 2026) found three failure modes that produce false findings and erode report credibility. These rules are mandatory for every phase.

### Rule 1: Never invent tool output
- **Read the actual command output.** If a command returns an error, empty response, or unexpected format — report what it actually returned. Never describe output you expected but didn't see.
- **If a tool isn't installed** (e.g., `command -v nuclei` returns nothing), report "tool not available, test skipped" — don't describe what it "would have found."
- **If a command times out or fails**, report the failure. Don't substitute a plausible result.

### Rule 2: Never claim a vulnerability without specific evidence
- Every finding must cite the **exact evidence** — the specific string in the response, the exact HTTP status code, the precise header value, the literal output line.
- "The server returned a 200 with body containing `root:x:0:0:root`" = evidence. "The endpoint appears vulnerable to LFI" without showing the response = hallucination.
- If the response is ambiguous (e.g., 200 but empty body, 403 but with different error messages), report the ambiguity — don't round up to "confirmed."

### Rule 3: Verify before escalating
- **Two-signal rule for Critical/High findings:** A finding rated Critical or High must be supported by at least two independent signals (e.g., curl confirms + browser confirms, or error-based detection + time-based detection, or two different endpoints show the same vulnerability).
- **If only one signal exists**, the finding is rated LIKELY, not CONFIRMED, and the report must say what second verification was attempted and why it was inconclusive.
- **Cross-method verification:** If curl shows a vulnerability, verify with browser automation when possible (especially CORS, CSP, clickjacking, XSS). If browser behavior differs from curl, **trust the browser** — that's what attackers use.

### Confidence Classification

Every finding in the report must carry one of these labels:

| Label | Meaning | Evidence required |
|---|---|---|
| **CONFIRMED** | Vulnerability independently verified with proof | Two independent signals + raw output shown |
| **LIKELY** | Strong indicators, single verification method | One clear signal + raw output shown |
| **SUSPECTED** | Circumstantial evidence, needs further testing | Anomalous behavior documented, no definitive proof |
| **THEORETICAL** | Plausible based on architecture, not testable externally | No direct evidence, based on known patterns for the stack |

**Default to the lower confidence level when in doubt.** A report with 3 CONFIRMED findings is more valuable than one with 10 "confirmed" findings where half are actually theoretical.

### Severity Classification

Severity reflects **what an attacker can actually do with this finding on this specific target** — not what's theoretically possible in the abstract.

| Level | Definition |
|---|---|
| **Critical** | The consequence is severe: data breach, financial loss, full compromise, mass PII exposure, or complete authentication bypass. If an external attacker can reach this without authentication — regardless of effort — and the impact is severe, it is Critical. |
| **High** | Removes a security control that directly enables a realistic attack in this target's context, OR the finding is exploitable with clear business impact but the consequence falls short of Critical (e.g., account-level access, not platform-wide breach). Requires CONFIRMED confidence. |
| **Medium** | Defense-in-depth gap. Exploitation requires chaining with another finding or specific preconditions. |
| **Low** | Best-practice violation, substantially mitigated by existing controls or architecture. |
| **Info** | Observation only. No exploit path. |

#### Calibration Rules

These rules were derived from reviewing 24 audits and resolving inconsistencies. They override gut instinct.

**Rule 0: Severe consequences are always Critical.**
If exploitation leads to any of these outcomes, the finding is Critical regardless of attacker effort:
- Mass PII exposure (user databases, customer records, payment data)
- Unauthenticated access to production data stores (Firestore, Supabase, S3 buckets with user data)
- Live credential/secret exposure (API keys that grant write access, database connection strings, admin passwords)
- Complete authentication bypass (open registration → full platform access, unauthenticated admin panels)
- Remote code execution
- Payment manipulation on live merchant accounts (creating real charges, modifying amounts)
- Email spoofing on a domain that handles financial transactions or user auth (where spoofed emails directly enable wallet/credential theft)

The threshold is **consequence severity**, not attacker effort. A finding that takes 4 hours to exploit but exposes 10,000 user records is still Critical.

**Rule 1: Severity follows the target, not the finding.**
A missing header on a static Webflow site is not the same as a missing header on a SaaS dashboard. Before rating any finding, classify the target domain:
- **Handles auth, payments, or user data on this domain** → base severities apply as-is.
- **Static site (no forms, no auth, no transactions on this domain)** → cap missing headers at Low, cap email auth at Medium, cap clickjacking at Low (Medium with browser PoC on an actionable element).
- **Financial/crypto context modifier** applies only if **this domain** handles transactions or wallet interactions. A marketing landing page for a mobile crypto app does NOT get the bump — the mobile app's domain does.

**Rule 2: Rate by what's proven, not what's possible.**
A finding's severity is determined by the worst outcome you can **demonstrate**, not the worst outcome you can imagine. Clickjacking on a page with no sensitive actions = Low regardless of brand context. Clickjacking on a payment page confirmed with a browser PoC = High. The PoC is the difference.

**Rule 3: Consolidate related findings.**
- SPF + DKIM + DMARC = ONE "Email Authentication" finding. Never three separate findings.
- 3+ missing security headers = ONE finding at the highest individual component severity.
- These consolidation rules are mandatory. Splitting inflates severity counts and misrepresents the attack surface.

**Rule 4: Partial enforcement is not zero enforcement.**
DMARC `p=quarantine` is not the same as `p=none`. Quarantine means spoofed emails go to spam — meaningful protection exists. Rate `p=quarantine` as Low (or Medium if weakened by `pct<100` or `sp=none`). Only `p=none` or absent means zero enforcement.

Similarly, HSTS "present but incomplete" (has `max-age` but missing `includeSubDomains`/`preload`) is always Low — enforcement exists. Only HSTS completely absent on an auth/payment domain is Medium.

**Rule 5: Absence of a supplementary control is Info, not a finding.**
No security.txt, no robots.txt, no sitemap.xml, no MTA-STS, no BIMI, no SMTP TLS reporting — these are observations, not vulnerabilities. Always Info. No CAA and no DNSSEC are Low (defense-in-depth only, require sophisticated multi-step attacks to exploit).

**Rule 6: Outdated ≠ vulnerable.**
An outdated library with no known CVEs is Info. A library on platform-managed infrastructure the site owner can't control (e.g., Webflow's jQuery) is Info. Only rate a version finding above Info if a specific CVE applies to the detected version AND the exploitation conditions exist on this target.

**Rule 7: CORS severity depends on what it protects.**
CORS wildcard (`*`) on static assets = Low. CORS wildcard on an API with auth = High. CORS reflecting any origin with credentials = Critical on any authenticated API. The data behind the CORS policy determines the severity, not the CORS misconfiguration itself.

**Rule 8: Information disclosure severity follows the data.**
Secrets/credentials in source = Critical. PII (emails, phones, payment IDs) = High. Infrastructure details (IPs, paths, versions) = Medium. Platform metadata (Webflow IDs, deployment IDs, analytics tokens) = Info. Employee/investor names on a public marketing page = Info (intentional content, not a leak).

## State Tracking Between Phases

Maintain a running **findings ledger** persisted to disk at `audits/{domain}/ledger.md` (separate from final reports). This file survives context compression and session boundaries.

**Lifecycle:**
- **Phase 0 (Attack Plan)** creates the ledger file on disk.
- **Every subsequent phase** must `Read` the ledger at the start, and `Edit` it at the end to append results.
- **Phase 11 (Validation)** reads the ledger as its primary cross-reference source.
- The ledger is **not** included in the final report — it is internal working state.

**Before starting each new phase, read the ledger to:**

1. **Carry forward context** — later phases should reference specific earlier findings (e.g., "Phase 8 targets the IP `34.56.78.90` discovered in Phase 1.5 without CDN protection").
2. **Avoid redundant work** — don't re-test something already confirmed.
3. **Build chains progressively** — note potential chain links as you discover them, don't wait until Phase 10.
4. **Track what failed** — if a tool or technique didn't work, record it so you don't retry it in a later phase.

**After completing each phase, update the ledger with:**
- Phase status (completed/skipped/partial)
- New confirmed findings (with evidence summary)
- New chain candidates identified
- Failed techniques (tool + why it failed)
- Any context the next phase needs

## Core Strategy: Explore the Worst Nightmare, Then Prove It

The audit's value is not a checklist of findings. It is a demonstration of **what an attacker can actually do** — the worst realistic nightmare — with proof that it's possible.

**The loop for every finding:**
1. **Imagine the worst nightmare.** Assume a motivated attacker. What is the maximum real-world damage this finding enables? Think revenue, fraud, reputation, legal, operational.
2. **Chain it.** Look at every other finding. Which combinations create compound attacks worse than any individual issue? The most devastating attacks always chain 2-4 findings together.
3. **Prove it.** Execute the exploit safely, or document the exact steps if execution would cause real harm. A browser screenshot of a working clickjack outranks 10 paragraphs of theory.

**Examples of what this looks like:**
- Find "no rate limiting on /api/waitlist" → don't just note it → fire 10 rapid requests and show 10/10 succeed → then show how this chains with email spoofing to destroy the company's sender reputation
- Find "no SPF record" → don't just note it → show the exact `swaks` command to send a spoofed invoice → chain with exposed contact names and M365 tenant for a complete phishing scenario
- Find "no X-Frame-Options" → don't just note it → open a browser, embed the site in an iframe from example.com, screenshot the working clickjack

**Always verify with real browser tests.** curl and browser behavior differ — especially for CORS, CSP, and cookies. If curl shows `Access-Control-Allow-Origin: *`, that does NOT mean browser JavaScript can exploit it. The API endpoint may not return CORS headers on its preflight. Use browser automation to:
- Test cross-origin fetch from a foreign domain (e.g., example.com → target API)
- Test iframe embedding (clickjacking) from a foreign origin
- Capture screenshots/GIFs as evidence

**An executed browser proof outranks any curl-based assumption. A corrected finding is more valuable than an unchecked one.**

**After all phases, run a dedicated Exploit Chain Analysis** — combine findings into multi-step attack chains ranked by (attacker effort × business damage). Each chain: exact sequence, what was EXECUTED vs. DOCUMENTED, compound impact, and which single fix breaks the chain.

## IMPORTANT: These phases are guidance, not limits

**You must:**
- **Follow the breadcrumbs.** If a phase reveals something unexpected, investigate it fully. Create new phases as needed.
- **Think like an attacker.** At every step, ask: "What would I probe next with this information?"
- **Adapt to the stack.** A WordPress site needs different testing than a Next.js + Sanity site. Skip irrelevant phases. Invent new ones.
- **Go deep on findings.** Don't just confirm "the API is readable" — enumerate everything, test write access, search for credentials.
- **Chain findings together.** Personnel data + no email spoofing protection = credible phishing. Exposed API + no rate limiting + CORS wildcard = multi-vector attack.
- **Always demonstrate.** If you can safely prove a worst-case scenario, do it. An executed proof is worth 100 documented theories.
- **Document everything novel.** If you discover a vulnerability type not covered below, document it so it gets added to future audits.
- **Stop and reassess on failure.** If a tool fails, a command returns unexpected output, or a technique produces no results — do NOT retry blindly. Diagnose why it failed (wrong endpoint? WAF blocking? tool not installed?), adapt your approach, or move on. Three failed attempts at the same technique with no new information = move to the next test.
- **Verify tool availability before complex scans.** Before running nuclei, sqlmap, wpscan, or other specialized tools, check `command -v {tool}` first. If the tool isn't available, document the skip and use manual alternatives — don't pretend the scan ran.

---

## Phases

Read the detailed methodology for each phase from the files in `.claude/commands/security-audit/`. Each phase file contains the specific checks, commands, and analysis criteria.

### Phase 0: Attack Plan Generation
**File:** `.claude/commands/security-audit/attack-plan.md`

**ALWAYS RUNS FIRST.** Lightweight recon sweep → target classification (architecture type, infrastructure type, integration fingerprint) → custom attack plan. Determines which conditional phases to run or skip. Initializes the findings ledger and checks tool availability upfront. This replaces blind checklist execution with intelligent targeting — a WordPress site on shared hosting needs completely different testing than a Next.js SPA on Vercel with Stripe.

### Phase 1: Reconnaissance & Technology Fingerprinting
**File:** `.claude/commands/security-audit/recon.md`
**Gate:** Always runs. Deepens Phase 0's quick sweep into comprehensive recon.

HTTP headers, full page source analysis, **JavaScript bundle deep scan** (critical for SPA/SSR apps — secrets and API endpoints hide in JS chunks, not HTML), DNS records, **active subdomain enumeration** (probe 30+ common prefixes), redirect chain analysis, **HTTP method enumeration** (OPTIONS, full verb matrix with CORS preflight checks), and **CSP architecture extraction** (parse `connect-src`, `frame-src`, `frame-ancestors` from application subdomains to map microservices, dev/prod projects, database clusters, and admin panels — often the single most valuable recon technique).

### Phase 2: Security Headers Analysis
**File:** `.claude/commands/security-audit/headers.md`
**Gate:** Always runs.

Check all 7 critical security headers, subdomain header consistency, CORS policy (test with `Origin: https://evil.com`), cookie flags, and **web cache poisoning** (unkeyed header injection via X-Forwarded-Host, cache key manipulation).

### Phase 3: TLS & Certificate Analysis
**File:** `.claude/commands/security-audit/tls.md`
**Gate:** Always runs.

Certificate details and expiry, TLS protocol version (test for deprecated TLS 1.0/1.1 using openssl), cipher strength, HSTS completeness (max-age, includeSubDomains, preload), **CAA record validation** (which CAs can issue certs), and **DNSSEC status** (DNS response authenticity).

### Phase 4: Email Security Assessment
**File:** `.claude/commands/security-audit/email-security.md`
**Gate:** Always runs. (Even static sites have email spoofing risk.)

**Dedicated email security phase** — SPF record check, DKIM selector enumeration (check 8+ common selectors), DMARC policy analysis, mail infrastructure identification, and Microsoft 365/Google Workspace tenant discovery from TXT records. Combined assessment with per-control grading.

### Phase 5: Path & File Enumeration
**File:** `.claude/commands/security-audit/paths.md`
**Gate:** Always runs. Path list adapts to detected stack from Phase 0/1.

robots.txt, sitemap.xml, **100+ sensitive paths in 3 tiers** (Tier 1: secrets/admin/API/debug, Tier 2: backup/config exposure inspired by Nuclei templates, Tier 3: top 50 product-specific exposed panels from Nuclei's 1000+ library), **git repository exposure deep-scan** (if `.git/HEAD` returns 200 — enumerate refs, download objects, scan commit logs for secrets and developer emails), technology-specific paths, **middleware redirect pattern detection** (e.g., Next.js 307→/login→404), source map exposure check, and **subdomain takeover assessment** for stale DNS records pointing to decommissioned infrastructure.

### Phase 6: CMS & Backend Data Exposure
**File:** `.claude/commands/security-audit/cms-backend.md`
**Gate:** Phase 0/1 detected a CMS or headless backend (Sanity project ID, Contentful space, Strapi endpoints, WordPress indicators, GraphQL endpoint, or cloud storage URLs). **Skip if:** pure static site with no CMS/backend indicators.

Sanity, Contentful, Strapi, WordPress REST API, GraphQL introspection, cloud storage bucket testing (S3, GCS, Azure, **Vercel Blob Storage**), and **Firebase Hosting & Auth exploitation** (extract config from `/__/firebase/init.js`, test open registration via Identity Toolkit API, probe Firestore/RTDB with auth tokens).

### Phase 7: Form & Input Injection Testing
**File:** `.claude/commands/security-audit/forms.md`
**Gate:** Phase 0/1 found form action URLs, `/api/*` routes, or Server Action references in JS bundles. **Skip if:** no form endpoints or API routes discovered.

Identify all form endpoints (from HTML AND JS bundle scan), schema discovery via error messages, single submission test, **origin validation test**, HTTP method check, rate limiting test (10 rapid requests), and **rate limit bypass via header spoofing** (X-Forwarded-For, X-Real-IP, X-Client-IP rotation — especially effective when API is not behind CDN/WAF).

### Phase 7b: Input Fuzzing
**File:** `.claude/commands/security-audit/fuzzing.md`
**Gate:** Phase 7 confirmed at least one API endpoint accepts parameters. **Skip if:** all endpoints rejected test input or returned static responses regardless of input.

**Nuclei-inspired injection testing.** LFI (path traversal with encoding bypasses), SSRF (cloud metadata endpoints for AWS/GCP/Azure/DO), command injection (time-based detection), XSS reflection probes (canary injection → escalation), HTTP header injection (CRLF, Host header poisoning), open redirect testing, and prototype pollution (Node.js apps). **Adapts to the detected stack** — skips irrelevant tests (e.g., no PHP-specific LFI on a Node.js app).

### Phase 7c: Payment API Exploitation
**File:** `.claude/commands/security-audit/payment-apis.md`
**Gate:** Phase 0/1 JS bundle scan found payment integrations — Stripe keys (`pk_live_`, `pk_test_`), PayPal SDK, Square, Braintree, or payment-related API endpoints (`/api/create-payment-intent`, `/api/checkout`). **Skip if:** no payment indicators found. Do NOT guess that a site has payments just because it sells something.

**Unauthenticated endpoint probing** — test if payment sessions can be created without auth. **Price manipulation** — test if the `amount` parameter is client-controlled (the single most critical payment vulnerability). **Session enumeration (IDOR)** — test if other users' payment sessions are accessible. **Sandbox vs production detection** — check `cs_live_` vs `cs_test_` prefixes. **Rate limiting assessment** — can an attacker flood the merchant's payment account.

### Phase 7d: AI/LLM Attack Surface
**File:** `.claude/commands/security-audit/ai-llm.md`
**Gate:** Phase 0/1 found AI/LLM indicators — chatbot widgets, `/api/chat` or `/api/completion` endpoints, OpenAI/Anthropic/ElevenLabs/LiveKit SDK references in JS bundles, or voice AI interfaces. **Skip if:** no AI indicators found.

**Unauthenticated endpoint probing** — test if AI endpoints respond without auth (= free API credit consumption). **System prompt extraction** — attempt to leak the system prompt (reveals business logic, potential credentials, guardrail config). **Prompt injection** — test role hijacking and indirect injection. **Cost exploitation** — rate limiting test, model parameter manipulation. **API key exposure** — scan JS bundles for leaked `sk-*` keys. **Voice AI specific** — test TTS/voice cloning endpoints without auth.

### Phase 7e: WebSocket & Real-Time Security
**File:** `.claude/commands/security-audit/websocket.md`
**Gate:** Phase 0/1 found WebSocket indicators — `wss://` URLs in JS bundles, Socket.io/Pusher/LiveKit/SignalR SDK references, or real-time UI elements. **Skip if:** no WebSocket or real-time indicators found.

**Endpoint discovery** — probe common WS paths, check JS bundles for `wss://` URLs. **Origin validation** — test if WebSocket accepts `Origin: https://evil.com` (cross-site WebSocket hijacking). **Unauthenticated access** — test if WS connections work without auth tokens. **Protocol enumeration** — send probe messages to discover channels, rooms, and capabilities. **LiveKit/voice platform** — test Twirp API, room listing, JWT token analysis. **Token exposure** — check if auth tokens are passed in URL query params (logged, leaked via Referrer).

### Phase 8: Server-Side Exploitation & Infrastructure Probing
**File:** `.claude/commands/security-audit/server-exploit.md`
**Gate:** Phase 0/1 discovered at least one IP that resolves directly to a cloud provider (AWS, GCP, Azure, DigitalOcean) WITHOUT CDN/WAF protection (no `cf-ray`, no CloudFront, no Akamai headers). **Skip if:** all discovered IPs are behind CDN/WAF. Running port scans and error probes against CDN IPs is useless noise.

**Error handling probes** — send malformed input to trigger stack traces that leak filesystem paths, usernames, dependency versions, and framework mode (the single highest-impact technique discovered). **Port scanning** exposed servers for SSH, databases, dev servers. **SSH assessment** when port 22 is open — check auth methods, confirm usernames from stack traces. **Admin panel auth analysis** — systematic testing of auth mechanisms (Basic, Bearer, JWT, Cookie, custom headers, JSON body), user enumeration, timing attacks, and credential stuffing with intel-derived wordlists. **Cross-domain discovery** — follow redirects to external services (Google Forms, Docs) to find hidden domains, internal product names, and PII collection.

### Phase 8b: Version-Specific CVE Testing
**File:** `.claude/commands/security-audit/version-cves.md`
**Gate:** Earlier phases identified at least one specific software version (from Server header, X-Powered-By, stack traces, SSH banners, JS filenames, or CMS meta tags). **Skip if:** no specific versions were identified — generic technology detection without versions (e.g., "uses Express" with no version) is insufficient for CVE matching.

**Nuclei-inspired version vulnerability matching.** Build a version inventory from all earlier phases (headers, stack traces, page source, SSH banners, TLS certs). Look up CVEs via NVD API and WebSearch. Includes **ready-made CVE tables** for nginx, Apache, Express/body-parser/qs, jQuery, OpenSSH (regreSSHion), WordPress plugins. **Exploitability assessment** — grade each CVE by version match, configuration, network access, WAF presence, and public PoC availability. **Dependency chain analysis** when package.json or stack traces reveal dependency names. Safe verification tests for confirmable CVEs.

### Phase 9: Information Disclosure & Incident Response Readiness

Catalog all information leaked across all phases:

- **Personnel** — names, roles, emails, phones, social profiles
- **Client/customer** — case studies, testimonials, CMS content
- **Product/roadmap** — unpublished pages, draft content, internal codenames
- **Technical** — deployment IDs, cloud tenant IDs, storage identifiers, datacenter regions
- **Server internals** — filesystem paths, usernames, dependency versions, framework modes (from Phase 8 error probes)
- **Cross-domain** — related domains discovered via redirects, Google Form ownership, shared infrastructure
- **Data consistency** — check for conflicting information across pages (different phone numbers, outdated team members, etc.)

**Incident response readiness assessment:**
- `/.well-known/security.txt` — does it exist, is it signed (PGP), does it have valid contact, encryption, and policy URIs?
- Responsible disclosure page — is there a visible vulnerability reporting process?
- `security@{domain}` email — does the MX record suggest it would be received?
- Bug bounty program — check HackerOne/Bugcrowd listings for the domain
- **Grade:** Has security.txt + disclosure process + bug bounty = A. Has security.txt only = C. Nothing = F (no way to report vulnerabilities responsibly)

### Phase 10: Exploit Chain Analysis

**This is where the audit delivers its real value.** Don't just list individual findings — build multi-step attack chains that show compound damage.

**Step 1: Individual worst-case.** For each finding, ask "what's the worst that could happen?" and demonstrate it.

**Step 2: Chain analysis.** Map every finding against every other finding. Look for combinations where:
- Finding A provides access/information that makes Finding B exploitable
- Finding B amplifies the damage of Finding A
- Multiple findings together create an attack that no single finding enables alone

**Step 3: For each chain, document:**
1. **Chain name** — descriptive (e.g., "Waitlist Weaponization → Email Reputation Destruction")
2. **Findings chained** — which specific findings combine (with references)
3. **Step-by-step exploit sequence** — exact commands for each step
4. **What was EXECUTED vs. DOCUMENTED** — be precise about what you proved
5. **Compound business impact** — the damage from the chain (not individual findings)
6. **Attacker effort vs. damage** — cost/skill required vs. business impact
7. **Single point of remediation** — which one fix would break the entire chain

**Prioritize chains by:** attacker effort (low = worse) × business impact (high = worse). The most dangerous chains are low-effort, high-damage.

### Phase 11: Validation Pass
**File:** `.claude/commands/security-audit/validation.md`
**Gate:** Always runs. Executes after all testing phases and before writing the final report.

**Independent re-verification of every Critical and High finding.** For each: verify evidence actually exists and supports the conclusion, audit confidence classification, check for contradictions between phases, calibrate severity against what was actually proven (not what's theoretically possible). Also validates exploit chains (every link must be individually verified), checks cross-phase data consistency (IPs, versions, domains), and confirms negative findings are documented. Produces no new findings — only validates, downgrades, or removes existing ones. The output is a more honest report with a validation summary noting how many findings were adjusted.

---

## Report Template

```markdown
# Security Audit Report: {domain}

**Target:** {url}
**Date:** {date}
**Method:** Passive reconnaissance + controlled active testing
**Scope:** {list of domains/subdomains tested}

## Executive Summary

**This is the in-report executive summary.** It lives inside `report.md` and is seen by users who have already unlocked the full report. It can be more detailed than the standalone `executive-summary.md` file.

**Structure:**

1. **The Headline** — One terrifying sentence in a blockquote. Specific to THEIR site.
   Example: `> **Anyone can send email as billing@yoursite.com and your customers will trust it — your DMARC policy does nothing to stop it.**`

2. **The Stakes** — 2-3 sentences on BUSINESS consequences with dollar figures.

3. **Severity Count Table**

| Severity | Count |
|---|---|
| **CRITICAL** | {n} |
| **HIGH** | {n} |
| **MEDIUM** | {n} |
| **LOW** | {n} |
| **INFO** | {n} |

4. **Top Findings Preview** — Top 3-5 findings. For each: severity badge, finding name, what the problem is, what an attacker can do. Can include brief technical context here since this is part of the paid report.

5. **What's in the Full Report** — Teaser list (reproduction steps, fix code, exploit chains, priority roadmap).

**NOTE:** The standalone `executive-summary.md` file is a SEPARATE, much shorter sales document. See the `executive-summary.md guidelines` section above for its format. Do NOT just copy this section into that file.

## Table of Contents
[auto-generated from phases]

## Attack Surface Summary
[From Phase 0: target classification, architecture type, infrastructure type, integrations detected, phases run vs. skipped with reasons]

## Phase 1: Reconnaissance
[findings]

## Phase 2: Security Headers Analysis
[findings]

## Phase 3: TLS & Certificate Analysis
[findings]

## Phase 4: Email Security Assessment
[findings]

## Phase 5: Path & File Enumeration
[findings]

## Phase 6: CMS & Backend Data Exposure
[findings]

## Phase 7: Form & Input Injection Testing
[findings]

## Phase 7b: Input Fuzzing
[LFI, SSRF, command injection, XSS, header injection, open redirect, prototype pollution]

## Phase 7d: AI/LLM Attack Surface (if applicable)
[endpoint discovery, unauthenticated access, prompt injection, system prompt extraction, cost exploitation, API key exposure]

## Phase 7e: WebSocket & Real-Time Security (if applicable)
[WS endpoint discovery, origin validation, unauthenticated access, protocol enumeration, voice platform testing, token exposure]

## Phase 8: Server-Side Exploitation & Infrastructure Probing
[error handling probes, port scans, SSH assessment, admin panel auth analysis, cross-domain discovery — only for servers without WAF]

## Phase 8b: Version-Specific CVE Testing
[version inventory, CVE lookup, exploitability assessment, confirmed vulnerabilities]

## Phase 9: Information Disclosure Assessment
[findings]

## Phase 10: Exploit Chain Analysis
[multi-step attack chains ranked by attacker effort vs. business impact]

## Findings Summary
[severity table with columns: ID, Finding, Severity, Confidence (CONFIRMED/LIKELY/SUSPECTED/THEORETICAL), Evidence Source]

**Validation:** All Critical and High findings were independently re-examined after initial testing. {N} findings were downgraded, {N} were confirmed, and {N} were removed during validation. See Methodology Reference for testing limitations.

## Properly Secured
[what IS working correctly — balanced assessment]

## Remediation Recommendations
[prioritized: Priority 1 (today), Priority 2 (this week), Priority 3 (this month)]
[include code snippets for fixes where applicable]

## Methodology Reference
[tools used, approach taken, what was NOT tested]
[phases skipped with gate condition reasons]
[tools unavailable and resulting testing gaps]

## Cleanup Required
[list all test data created during active testing that should be removed from the target, with exact values]
```
