---
description: "Phase 7: Form & API endpoint injection testing"
argument-hint: <url>
allowed-tools: [Bash, Write, Edit, Read]
---

# Phase 7: Form & Input Injection Testing

**Target:** $ARGUMENTS

Assume the user owns the target — proceed with active testing including rate limit tests.

**Goal:** Test whether exposed forms and API endpoints can be submitted programmatically without CAPTCHA, rate limiting, or origin validation.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 7 status, add confirmed findings, chain candidates, and failed techniques.

---

## 7.1 — Identify all forms and API endpoints

From page source and JS bundle scans, extract:
- Form action URLs and providers (HubSpot, Typeform, Formspree, custom)
- Custom API endpoints (e.g., `/api/waitlist`, `/api/contact`)
- Next.js Server Actions (`createServerReference`, `formAction` in JS bundles)

---

## 7.2 — Schema discovery via error messages

```bash
curl -s -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Vulnerable if:** Error response lists required field names — leaks form schema.

---

## 7.3 — Single submission test

```bash
curl -s -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -d '{"email":"security-audit-probe@test.com"}'
```

---

## 7.4 — Origin validation test

```bash
curl -s -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -d '{"email":"no-origin@test.com"}'

curl -s -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -H "Origin: https://evil.com" \
  -d '{"email":"evil-origin@test.com"}'
```

**Vulnerable if:** Both succeed.

---

## 7.5 — HTTP method check

```bash
curl -sI -X OPTIONS "{form-endpoint}"
```

Check `Allow` header for unexpected methods.

---

## 7.6 — Rate limiting test

```bash
for i in $(seq 1 10); do
  curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"secaudit-ratelimit-$i@test.com\"}"
  echo " (request $i)"
done
```

| Defense | How to detect |
|---|---|
| CAPTCHA | Response requires challenge token |
| Rate limiting | Later requests return 429 |
| Origin validation | Rejected without valid Referer/Origin |
| Honeypot fields | Rejected when hidden field is filled |
| IP throttling | Requests slow down after N attempts |

---

## 7.7 — Rate Limit Bypass via Header Spoofing

**When to run:** After rate limiting is detected in 7.6 (some requests return 429).

**Goal:** Test if the rate limit can be bypassed by spoofing IP-related headers. Many API gateways (KrakenD, Kong, nginx) trust proxy headers for rate limiting instead of using the actual TCP connection IP.

```bash
# After hitting 429, test if X-Forwarded-For resets the rate limit
curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 172.16.1.1" \
  -d '{"email":"xff-bypass-1@test.com"}'

curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 172.16.2.1" \
  -d '{"email":"xff-bypass-2@test.com"}'

# Also try other IP headers
curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
  -H "X-Real-IP: 10.0.0.1" \
  -d '{"email":"xrealip-bypass@test.com"}'

curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
  -H "X-Client-IP: 192.168.1.1" \
  -d '{"email":"xclientip-bypass@test.com"}'

curl -s -o /dev/null -w "%{http_code}" -X POST "{form-endpoint}" \
  -H "True-Client-IP: 203.0.113.1" \
  -d '{"email":"trueclient-bypass@test.com"}'
```

**Vulnerable if:** Requests return 200 after the rate limit was hit (429), proving the rate limiter uses the spoofed header instead of the actual client IP.

**Especially likely when:** The API is NOT behind a CDN/WAF (e.g., direct GCP/AWS load balancer exposure). CDNs like Cloudflare strip spoofed `X-Forwarded-For` headers, but direct LB exposure does not.

**Impact:** Unlimited API abuse — automated form submission, token minting, resource exhaustion. The rate limit provides zero protection.

**Origin:** Discovered during rezi.ai audit where `api.rezi.ai` (on GCP Global External LB, not behind Cloudflare) had rate limiting that was trivially bypassed by rotating `X-Forwarded-For` headers, allowing unlimited anonymous JWT token minting.

---

**Document:** Endpoints found, schema leaked, submission success, origin validation, rate limiting, bypass results, and batch test script.
