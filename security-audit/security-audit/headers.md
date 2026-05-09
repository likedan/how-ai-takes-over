---
description: "Phase 2: Security headers analysis for a target domain"
argument-hint: <url>
allowed-tools: [Bash, Write, Edit, Read]
---

# Phase 2: Security Headers Analysis

**Target:** $ARGUMENTS

**Goal:** Identify missing or misconfigured HTTP security headers that enable client-side attacks.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 2 status, add confirmed findings, chain candidates, and failed techniques.

---

## 2.1 — Check all security headers on the main domain AND all discovered subdomains

**IMPORTANT:** Check headers on EVERY subdomain discovered in Phase 0/1, not just the main domain. Real audits consistently find different header profiles across subdomains — seel.com had HSTS on CDN subdomains but zero headers on API servers; yummy-future had no X-Frame-Options leading to confirmed clickjacking. Build a header comparison matrix across all subdomains.

```bash
# Check main domain first
curl -sI https://{target} | grep -iE 'x-frame|x-content-type|x-xss|content-security-policy|permissions-policy|referrer-policy|cross-origin|feature-policy|strict-transport'

# Then check every subdomain from Phase 1
for sub in {discovered_subdomains}; do
  echo "=== $sub ==="
  curl -sI "https://$sub" --max-time 5 2>/dev/null | grep -iE 'x-frame|x-content-type|x-xss|content-security-policy|permissions-policy|referrer-policy|cross-origin|feature-policy|strict-transport'
done
```

**Required headers checklist:**

| Header | Purpose | Missing = Risk |
|---|---|---|
| `Content-Security-Policy` | Prevents XSS, injection | Scripts from any origin can execute |
| `X-Frame-Options` | Prevents clickjacking | Site can be embedded in malicious iframes |
| `X-Content-Type-Options` | Prevents MIME sniffing | Browser may execute uploaded files as scripts |
| `Referrer-Policy` | Controls referrer leakage | Full URLs leaked to third parties |
| `Permissions-Policy` | Restricts browser APIs | Camera, mic, geolocation accessible |
| `Strict-Transport-Security` | Forces HTTPS | Downgrade attacks possible |
| `X-XSS-Protection` | Legacy XSS filter | Minor — modern CSP is better |

---

## 2.2 — Check subdomains for header inconsistency

For every known subdomain, check headers. It's common for the main app to have headers but marketing/docs sites to be missing them.

---

## 2.3 — CORS policy check

```bash
curl -sI https://{target} -H "Origin: https://evil.com" | grep -i "access-control"
```

**Vulnerable if:** `Access-Control-Allow-Origin: https://evil.com` or `*` is returned — means any site can make authenticated cross-origin requests. When combined with API endpoints, this enables cross-site form submission and data exfiltration.

---

## 2.4 — Cookie analysis

From the Set-Cookie headers, check each cookie for:
- `Secure` flag (required — prevents transmission over HTTP)
- `HttpOnly` flag (required for session cookies — prevents JS access)
- `SameSite` attribute (Strict or Lax recommended)
- Overly broad `Domain` or `Path` scope

---

## 2.5 — Web Cache Poisoning

**Goal:** Test if an attacker can manipulate cached responses via unkeyed headers, causing other users to receive poisoned content.

**Step 1: Identify caching behavior**
```bash
# Check if responses are cached (look for Age, X-Cache, CF-Cache-Status, x-vercel-cache)
curl -sI https://{target}/ | grep -iE 'age:|x-cache|cf-cache|x-vercel-cache|x-fastly|via:|cache-control'

# Send two requests — if Age increments or X-Cache changes to HIT, caching is active
curl -sI https://{target}/ | grep -iE 'age:|x-cache'
sleep 2
curl -sI https://{target}/ | grep -iE 'age:|x-cache'
```

**Step 2: Test unkeyed header injection**
```bash
# X-Forwarded-Host — most common cache poisoning vector
# If the response reflects this host in links/redirects AND the response is cached, it's exploitable
curl -sI https://{target}/ -H "X-Forwarded-Host: evil.com" | grep -iE 'location:|evil\.com|x-cache'
curl -s https://{target}/ -H "X-Forwarded-Host: evil.com" | grep -o 'evil\.com'

# X-Original-URL / X-Rewrite-URL — path override (common in IIS/nginx)
curl -sI https://{target}/ -H "X-Original-URL: /admin" | head -5
curl -sI https://{target}/ -H "X-Rewrite-URL: /admin" | head -5

# X-Forwarded-Scheme — force HTTP downgrade in cached response
curl -sI https://{target}/ -H "X-Forwarded-Scheme: http" | grep -iE 'location:|x-cache'

# X-Forwarded-Proto — similar downgrade vector
curl -sI https://{target}/ -H "X-Forwarded-Proto: http" | grep -iE 'location:|x-cache'
```

**Step 3: Cache key manipulation**
```bash
# Test if query parameters are excluded from cache key (fat GET)
curl -s "https://{target}/?cachebuster=$(date +%s)&cb=evil" -H "X-Forwarded-Host: evil.com" | grep -o 'evil\.com'

# Test parameter pollution — duplicate params may bypass cache key
curl -s "https://{target}/?utm_content=legit&utm_content=<script>alert(1)</script>" | grep -o 'alert(1)'
```

**Vulnerable if:**
- An unkeyed header value (X-Forwarded-Host, etc.) appears in the **cached** response body or Location header
- A subsequent request **without** the poisoned header returns the poisoned content (cache served it)

**Impact:** Stored XSS-equivalent — every user who hits the cached page gets the attacker's payload. Cache poisoning + reflected XSS = persistent XSS without touching the server.

---

**Document:** Table of all headers present/missing, comparison across subdomains if applicable, cache poisoning test results, and specific risk for each missing header.
