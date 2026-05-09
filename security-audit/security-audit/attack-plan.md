---
description: "Phase 0: Attack plan generation — recon-driven test plan adapted to the target's stack"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 0: Attack Plan Generation

**Target:** $ARGUMENTS

**Goal:** Run lightweight reconnaissance, then generate a custom attack plan tailored to this specific target. The plan determines which phases to run, skip, or prioritize — and identifies the target's unique attack surface before deep testing begins.

**This phase replaces blind checklist execution with intelligent targeting.** A WordPress site on shared hosting needs completely different testing than a Next.js SPA on Vercel with Stripe integration.

---

## 0.1 — Quick Recon Sweep

Run these in parallel (30 seconds max per check):

```bash
# HTTP headers — technology fingerprint
curl -sI https://{target} --max-time 10

# Page source — framework, third-party services, inline config
curl -s https://{target} --max-time 15 | head -500

# JS bundle discovery — SPA/SSR detection
curl -s https://{target} --max-time 15 | grep -oE '/_next/static/[^"]+\.js|/static/js/[^"]+\.js|/assets/[^"]+\.js' | head -20

# DNS — hosting, email, CDN
dig +short {target} A
dig +short {target} MX
dig +short {target} TXT

# One JS chunk scan (if SPA detected) — API endpoints, secrets, integrations
# Pick the largest chunk or main bundle
```

---

## 0.2 — Target Profile Classification

Based on the recon sweep, classify the target:

### Architecture Type
| Type | Indicators | Impact on testing |
|---|---|---|
| **Static site** | Webflow, Squarespace, Wix, no JS bundles with API routes | Skip injection testing, focus on headers/email/info disclosure |
| **SPA + API** | Next.js, React, Vue with `/api/*` routes | Deep JS bundle scan, API fuzzing, CORS testing critical |
| **Traditional CMS** | WordPress, Drupal, Joomla | WPScan, plugin vulns, admin panel, SQLi focus |
| **Headless CMS + frontend** | Sanity, Contentful, Strapi + SPA | CMS API exposure, GraphQL introspection, bucket testing |
| **Custom backend** | Express, Django, Rails, Spring behind API | Error probing, injection testing, auth analysis |

### Infrastructure Type
| Type | Indicators | Impact on testing |
|---|---|---|
| **CDN/WAF protected** | Cloudflare, AWS CloudFront, Akamai headers | Skip port scanning on CDN IPs, focus on application-layer |
| **Direct cloud exposure** | Raw AWS/GCP/Azure IP, no CDN headers | Full port scan, SSH assessment, error probing = high priority |
| **Managed hosting** | Vercel, Netlify, Heroku, Railway | Limited server-side testing, focus on app logic and config |
| **Shared hosting** | cPanel indicators, shared IPs | Check for cross-tenant leaks, server info disclosure |

### Integration Fingerprint
From JS bundles and page source, check for:
- [ ] **Payment processing** — Stripe (`pk_live_`, `pk_test_`), PayPal, Square, Braintree
- [ ] **AI/LLM** — OpenAI, Anthropic, ElevenLabs, LiveKit, `/api/chat`, `/api/completion`
- [ ] **Real-time/WebSocket** — Socket.io, Pusher, LiveKit, `wss://` URLs
- [ ] **Auth provider** — Clerk, Auth0, Firebase Auth, Supabase Auth
- [ ] **CMS/headless** — Sanity project ID, Contentful space, Strapi, WordPress
- [ ] **Cloud storage** — S3 buckets, GCS, Azure Blob, Vercel Blob
- [ ] **Email/forms** — HubSpot, Typeform, Formspree, custom `/api/contact`

---

## 0.3 — Generate the Attack Plan

Based on the target profile, generate a concrete plan with three sections:

### Priority Phases (always run)
These phases run on every target. List them with any target-specific adaptations:
- Phase 1: Recon (full) — note specific areas to deep-dive based on quick sweep
- Phase 2: Security Headers
- Phase 3: TLS
- Phase 4: Email Security
- Phase 5: Path Enumeration — note technology-specific paths to add
- Phase 9: Information Disclosure
- Phase 10: Exploit Chain Analysis

### Conditional Phases (run if gate conditions met)
For each, state the gate condition and whether it's met:

| Phase | Gate Condition | Met? | Evidence |
|---|---|---|---|
| Phase 6: CMS/Backend | CMS or headless backend detected | Yes/No/Unknown | {what was detected} |
| Phase 7: Forms | Form endpoints or API routes found | Yes/No/Unknown | {endpoints found} |
| Phase 7b: Fuzzing | API endpoints that accept parameters found | Yes/No/Unknown | {endpoints found} |
| Phase 7c: Payment | Payment integration detected | Yes/No/Unknown | {Stripe keys, PayPal, etc.} |
| Phase 7d: AI/LLM | AI endpoints or SDKs detected | Yes/No/Unknown | {what was detected} |
| Phase 7e: WebSocket | WS URLs or real-time SDKs detected | Yes/No/Unknown | {what was detected} |
| Phase 8: Server Exploit | Direct IP without CDN/WAF found | Yes/No/Unknown | {IP and evidence} |
| Phase 8b: Version CVEs | Specific software versions identified | Yes/No/Unknown | {versions found} |

### Target-Specific Investigations
List anything unusual discovered in the quick sweep that doesn't fit existing phases:
- Unexpected redirects to external domains
- Unusual headers or response patterns
- Dev/staging environments accidentally exposed
- Anything that makes you think "that's interesting, I should dig deeper"

---

## 0.4 — Initialize the Findings Ledger (on disk)

**Write the ledger to disk** at `audits/{domain}/ledger.md` so it persists across context compression and session boundaries. Every subsequent phase will `Read` this file at start and `Edit` it at end.

**Check tool availability first:**
```bash
for tool in nuclei sqlmap wpscan nmap nikto gobuster dirsearch subfinder amass \
           theHarvester wafw00f testssl.sh ssh-audit cewl exiftool hydra; do
  if command -v "$tool" &> /dev/null; then
    echo "AVAILABLE: $tool"
  else
    echo "MISSING: $tool"
  fi
done
```

**Then use the `Write` tool** to create `audits/{domain}/ledger.md` with this structure:

```markdown
# Findings Ledger — {target}

- **Stack:** {architecture type} on {infrastructure type}
- **Integrations:** {detected integrations}
- **CDN/WAF:** {yes/no, which one}
- **Direct IPs:** {if any found}

## Tools Available

| Tool | Status |
|------|--------|
| nuclei | available/missing |
| sqlmap | available/missing |
| ... | ... |

## Phase Results

| Phase | Status | Key Findings |
|-------|--------|-------------|
| 0 — Attack Plan | completed | {1-line summary} |
| 1 — Recon | pending | |
| 2 — Headers | pending | |
| 3 — TLS | pending | |
| 4 — Email | pending | |
| 5 — Paths | pending | |
| 6 — CMS/Backend | pending | |
| 7 — Forms/Injection | pending | |
| 8a — Server Exploit | pending | |
| 8b — Version CVEs | pending | |
| 9 — Post-Auth | pending | |
| 10 — Report | pending | |
| 11 — Validation | pending | |

## Confirmed Findings

(updated after each phase — include severity, evidence summary, and phase where discovered)

*none yet*

## Chain Candidates

(potential multi-finding exploit chains — note links as discovered, don't wait until Phase 10)

*none yet*

## Failed Techniques

(tool + what was attempted + why it failed — so later phases don't retry)

*none yet*
```

---

**Output:** The attack plan is internal working state — it guides execution but doesn't appear as a separate section in the final report. The Methodology Reference section of the report should summarize what was tested and what was skipped (with reasons).
