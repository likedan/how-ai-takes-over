---
description: "Phase 11: Validation pass — independent re-verification of all Critical/High findings before report finalization"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 11: Validation Pass

**Target:** $ARGUMENTS

**Goal:** Before finalizing the report, independently re-examine every Critical and High finding. This phase acts as a **second pair of eyes** — catching hallucinated findings, correcting misclassified severity, and ensuring every claim in the report is backed by evidence that actually exists.

**Why this phase exists:** Research on LLM-based pentesting found that 30-60% of "confirmed" findings in automated reports were actually misclassified — either the evidence didn't support the conclusion, the vulnerability was theoretical rather than confirmed, or the finding contradicted information from another phase. This validation pass catches those errors before they reach the reader.

**When to run:** After all testing phases (1-10) are complete, before writing the final report.

**First action:** `Read` the findings ledger from `audits/{domain}/ledger.md`. This is your primary cross-reference for all checks below. If the ledger file doesn't exist, the audit was run without state tracking — flag this as a limitation and proceed using the report draft as your source.

---

## 11.1 — Finding-by-Finding Re-Examination

For every finding rated **Critical** or **High**, perform this checklist:

### Evidence Exists Check
- [ ] The finding cites specific raw output (not paraphrased, not summarized)
- [ ] The cited output was from a command that was actually executed (check against the findings ledger)
- [ ] The output shown actually demonstrates the claimed vulnerability (re-read it critically — does `HTTP 200` with an empty body really confirm the vulnerability, or just that the endpoint exists?)

### Confidence Level Audit
- [ ] If rated **CONFIRMED**: Are there truly two independent signals? List both.
- [ ] If rated **LIKELY**: Was a second verification attempted? What happened?
- [ ] Should this be downgraded? (When in doubt, downgrade — a conservative report is more credible)

### Contradiction Check
- [ ] Does this finding contradict anything from another phase?
  - Example: Phase 2 says "no CORS headers present" but Phase 7 says "CORS wildcard allows cross-origin access" — which is it?
  - Example: Phase 1 says "Cloudflare WAF detected" but Phase 8 ran port scans against a CDN IP — those results are meaningless
- [ ] Does the finding depend on a condition that was assumed but not verified?
  - Example: "SQLi confirmed" but the only evidence is a generic error message that could come from input validation, not a database

### Severity Calibration
- [ ] Cross-reference the finding against the **Severity Classification** and **Finding-Specific Severity Lookup** tables in the main `security-audit.md` skill file. These tables define the baseline severity for each finding type and the context-aware adjustments (financial/crypto targets bump email auth failures to Critical, static sites cap missing headers at Low, etc.).
- [ ] Is the severity appropriate given what was actually proven (not what's theoretically possible)?
  - Missing `X-Frame-Options` on a login page = Medium (credential theft via clickjacking)
  - Missing `X-Frame-Options` on a static marketing page with no forms = Low (no exploitable action)
  - No DMARC on a crypto/fintech domain = Critical (direct path to financial fraud)
  - No DMARC on a personal blog = Medium (annoying but no financial consequence)
- [ ] Does the severity account for existing mitigations?
  - "No rate limiting" is High when there's also no CAPTCHA. It's Medium if CAPTCHA is present but rate limiting is missing.
- [ ] **Consolidation check:** Are there 3+ missing security headers reported as separate findings? If so, consolidate into one finding at the highest individual severity. Exception: CSP and X-Frame-Options get separate findings if they have distinct exploit implications.

---

## 11.2 — Cross-Phase Consistency Check

Review the findings ledger and check for:

### Data Consistency
- IP addresses referenced in later phases match what Phase 1 discovered
- Software versions cited in Phase 8b match what was detected (not what was assumed)
- Subdomain findings are consistent across phases (same subdomain shouldn't have conflicting results)

### Logic Consistency
- If the target is behind Cloudflare (Phase 1), Phase 8 should only target non-CDN IPs (if any were found)
- If Phase 1 detected a static site (Webflow/Squarespace), Phase 7b injection testing results should reflect that most endpoints are hosted by the platform, not custom code
- If Phase 5 found no API endpoints, Phase 7 shouldn't claim to have tested API form submissions

### Scope Consistency
- Every finding references the correct domain/subdomain
- No findings were generated for targets that weren't actually tested
- Cleanup section lists ALL test data created (cross-reference with Phase 7 submissions, Phase 8 login attempts)

---

## 11.3 — Negative Finding Verification

Check that important negatives are documented:

- [ ] If injection testing (Phase 7b) found nothing — is it documented which endpoints were tested and with which payloads? (not just silence)
- [ ] If no exposed admin panels were found — is this noted as a positive security finding?
- [ ] If tools were unavailable (nuclei, sqlmap, etc.) — is the testing gap documented in Methodology Reference?
- [ ] If phases were skipped due to gate conditions — are the skip reasons documented?

---

## 11.4 — Exploit Chain Validation

For each chain in Phase 10:

- [ ] Every finding in the chain was individually validated above
- [ ] The chain's step-by-step sequence is logically sound (Step 2 actually requires Step 1's output)
- [ ] The "EXECUTED vs DOCUMENTED" labels are accurate — if Step 1 was EXECUTED but Step 2 was DOCUMENTED, the chain is partially proven, not fully proven
- [ ] The compound impact claim is realistic (not "theoretical RCE" from a chain of three SUSPECTED findings)

---

## 11.5 — Final Adjustments

After the validation pass, make these changes to the report:

1. **Downgrade** any findings that don't meet their confidence level's evidence threshold
2. **Remove** any findings that turned out to be hallucinated (no real evidence, contradicted by other phases)
3. **Upgrade** any findings that were under-classified (rare, but possible — e.g., a "Medium" that's actually Critical when combined with a chain)
4. **Add caveats** to findings where the evidence is real but the interpretation is uncertain
5. **Update the Methodology Reference** to honestly document what was tested, what was skipped, what tools were unavailable, and what limitations applied

### Validation Summary (include in report)

Add a brief note at the end of the Findings Summary:

> **Validation:** All Critical and High findings were independently re-examined after initial testing. {N} findings were downgraded, {N} were confirmed, and {N} were removed during validation. See Methodology Reference for testing limitations.

---

**This phase produces no new findings.** It only validates, adjusts, or removes existing ones. The output is a more honest, more credible report.
