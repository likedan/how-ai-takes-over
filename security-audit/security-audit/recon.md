---
description: "Phase 1: Reconnaissance & technology fingerprinting for a target domain"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 1: Reconnaissance & Technology Fingerprinting

**Target:** $ARGUMENTS

**Goal:** Identify the technology stack, hosting infrastructure, third-party services, and full attack surface.

Run all independent checks in parallel. Document the exact command, raw result, and analysis for each check.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 1 status, add confirmed findings, chain candidates, and failed techniques.

---

## 1.1 — HTTP Response Headers

```bash
curl -sI https://{target}
```

**Look for:**
- `Server` header → web server or CDN identity
- `X-Powered-By` → framework disclosure (e.g., Next.js, Express, PHP)
- `Set-Cookie` → cookie flags (Secure, HttpOnly, SameSite)
- Custom `X-*` headers → hosting platform (Vercel, AWS, Netlify, Heroku)
- `Strict-Transport-Security` → HSTS configuration
- Caching headers → CDN behavior

**Platform-specific headers to look for:**

| Header | Platform/Framework | What it reveals |
|---|---|---|
| `x-vercel-id` | Vercel | Datacenter region (e.g., `pdx1`), deployment routing |
| `x-vercel-cache` | Vercel | Cache behavior (`HIT`, `MISS`, `STALE`) |
| `x-nextjs-prerender` | Next.js | Page is statically prerendered |
| `x-nextjs-stale-time` | Next.js | ISR stale revalidation interval |
| `vary: rsc, next-router-state-tree` | Next.js App Router | React Server Components in use |
| `x-powered-by: Next.js` | Next.js (Pages Router) | Framework version may be appended |
| `x-amzn-requestid` | AWS | API Gateway or ALB |
| `cf-ray` | Cloudflare | Cloudflare datacenter |
| `x-netlify-*` | Netlify | Hosting on Netlify |
| `fly-request-id` | Fly.io | Fly.io deployment |

---

## 1.2 — Full Page Source Analysis

Use WebFetch to retrieve the full page and analyze for:

- **Inline scripts** with API keys, tokens, or secrets
- **Third-party integrations** — analytics (GA, Segment, Mixpanel), CRM (HubSpot, Salesforce), chat (Intercom, Drift)
- **CMS indicators** — Sanity project IDs, Contentful space IDs, Strapi endpoints, WordPress REST API
- **Authentication endpoints** — login URLs, OAuth redirects, SSO providers
- **Form action URLs** — where form data is submitted
- **Structured data** (JSON-LD, Open Graph) — organization details, social profiles, contact info
- **Source maps** — if `.map` files are referenced, the full source code may be downloadable
- **Comments** — developers sometimes leave TODO, FIXME, or credential notes in HTML comments
- **Vercel Live / Preview scripts** — `vercel.live` references indicate preview deployment tooling

---

## 1.3 — JavaScript Bundle Deep Scan

**CRITICAL:** For SPA and SSR frameworks (Next.js, React, Vue, Angular), the HTML source is often just a shell. The real secrets, API endpoints, and configuration are buried in JavaScript bundle files. This step frequently reveals endpoints not visible in the HTML.

```bash
# Extract all JS chunk filenames from the page
curl -s "https://{target}" | grep -oE '/_next/static/chunks/[^"]+\.js' | sort -u

# For each unique chunk, scan for sensitive patterns
curl -s "https://{target}/{chunk-path}" | grep -oiE '(https?://[^"'\''` ]+|/api/[a-zA-Z0-9_/-]+|NEXT_PUBLIC_[A-Z_]+|supabase|sanity|firebase|clerk|auth0|stripe|\.env|apiKey|secret|token|\.blob\.)'
```

**Look for:**
- `/api/*` routes — custom API endpoints (e.g., `/api/waitlist`, `/api/quote`, `/api/auth`)
- Full URLs — CDN hostnames, Blob Storage URLs, third-party API endpoints
- Environment variable names — `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` variables are client-side and may contain project IDs, API URLs, keys
- BaaS configuration — Supabase URLs (`*.supabase.co`), Firebase config objects, Clerk publishable keys
- Auth tokens in JS — Stytch (`public-token-live-*`, `public-token-test-*`), Stripe (`pk_live_*`, `pk_test_*`), Datadog RUM (`pub*`)
- Internal codenames — project names, feature flags, unreleased feature references
- Storage URLs — Vercel Blob (`*.public.blob.vercel-storage.com`), S3 buckets, GCS buckets
- Future/unreleased infrastructure — subdomain references in JS that don't resolve yet (attackers can pre-register or squat)
- Deployment IDs — Vercel (`dpl_*`), build IDs, release versions (`VITE_RELEASE_VERSION`)

### 1.3b — Source Map Harvesting

**CRITICAL:** Source maps are one of the highest-value findings across all audits. They expose complete original source code, API endpoints, auth logic, merchant IDs, and internal architecture.

```bash
# For each JS file discovered in 1.3, check if a .map file exists
# Extract JS file list from page source
JS_FILES=$(curl -s "https://{target}" | grep -oE '"[^"]+\.js"' | tr -d '"' | sort -u)

for js in $JS_FILES; do
  # Make URL absolute
  [[ "$js" != http* ]] && js="https://{target}${js}"
  map_url="${js}.map"
  code=$(curl -sI -o /dev/null -w "%{http_code}" "$map_url" --max-time 5 2>/dev/null)
  content_type=$(curl -sI "$map_url" --max-time 5 2>/dev/null | grep -i "content-type:" | head -1)
  if [ "$code" = "200" ]; then
    # Verify it's a real source map (not SPA fallback HTML)
    if echo "$content_type" | grep -qi "json\|javascript\|octet"; then
      echo "!!! SOURCE MAP EXPOSED: $map_url"
    else
      echo "NOTE: $map_url returns 200 but Content-Type is $content_type (likely SPA fallback)"
    fi
  fi
done
```

**For CRA apps:** Also check `asset-manifest.json` which lists all JS/CSS files:
```bash
curl -s "https://{target}/asset-manifest.json" 2>/dev/null | head -50
```

**If source maps are found, download and analyze for:**
- API base URLs and endpoint paths
- Auth mechanisms (cookie, JWT, API key, signature)
- Environment detection logic (prod/dev/test)
- Merchant/partner IDs hardcoded in constants
- Error codes and internal status enums
- Platform integration lists
- Redux/state management structure

**Impact:** resolve.seel.com source maps exposed 1,228 files including complete API request logic, auth flows, and merchant IDs. partytime.gg had partial source map exposure. This is consistently a HIGH+ finding.

---

### 1.3c — Certificate SAN Analysis for Related Domains

**Why:** TLS certificate Subject Alternative Names (SANs) often reveal related domains, brand relationships, and internal naming conventions that aren't visible anywhere else.

```bash
# Extract SANs from the target's certificate
echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | \
  openssl x509 -noout -ext subjectAltName 2>/dev/null

# Also check discovered subdomains (especially API servers)
for sub in api app admin dashboard; do
  echo "=== $sub.{target} ==="
  echo | openssl s_client -connect $sub.{target}:443 -servername $sub.{target} 2>/dev/null | \
    openssl x509 -noout -ext subjectAltName 2>/dev/null
done
```

**Look for:**
- Domains you haven't seen before (brand relationships, rebrands — seel.com cert revealed `*.kover.ai`)
- Wildcard certs covering test infrastructure (`*.test.{related-domain}`)
- Multiple unrelated domains on one cert (shared hosting / shared infrastructure)
- Cert issued to a different organization than expected

---

## 1.4 — DNS & Infrastructure

```bash
dig +short {target} A
dig +short {target} AAAA
dig +short {target} MX
dig +short {target} TXT
```

**Look for:**
- Cloudflare, AWS, GCP, Azure IP ranges → hosting provider
- SPF/DKIM/DMARC records → email spoofing protection
- Multiple A records → load balancing or CDN
- `*.onmicrosoft.com` in TXT records → Microsoft 365 tenant ID
- `google-site-verification` → Google Search Console verified

---

## 1.5 — Subdomain Enumeration

**Actively probe common subdomain prefixes:**

```bash
for sub in api app staging stg dev test preview beta demo www2 cdn assets static \
           admin portal dashboard platform mail docs wiki shop store order track \
           status monitor grafana sentry internal; do
  result=$(dig +short "$sub.{target}" A 2>/dev/null)
  if [ -n "$result" ]; then
    echo "$sub.{target} -> $result"
  fi
done
```

**For each subdomain found:**
1. Reverse DNS: `dig +short -x {ip}`
2. Port check: 80, 443, 3000, 8080, 8443
3. Fetch headers if accessible
4. Note for subdomain takeover assessment

---

## 1.6 — Redirect Chain Analysis

```bash
curl -sI http://{target} | head -10     # HTTP to HTTPS
curl -sI https://{bare-domain} | head -10  # Bare to www
```

**Check:** HTTP → HTTPS should use 301 or 308 (permanent). Bare domain redirect should also be permanent.

---

## 1.7 — HTTP Method Enumeration

```bash
# OPTIONS request reveals allowed methods directly
curl -sI -X OPTIONS https://{target} | grep -iE 'allow:|access-control-allow-methods'

# Test each method individually
for method in GET POST PUT PATCH DELETE TRACE OPTIONS HEAD CONNECT; do
  code=$(curl -sI -o /dev/null -w "%{http_code}" -X $method https://{target} --max-time 5 2>/dev/null)
  echo "$method -> $code"
done
```

**Check for:**
- **TRACE returns 200** = Cross-Site Tracing (XST) — can steal cookies via XSS even with HttpOnly flag
- **PUT/DELETE return 200** = potentially dangerous write/delete access on the web root
- **PATCH returns 200** = unexpected mutation endpoint
- **OPTIONS reveals `Access-Control-Allow-Methods`** = CORS method whitelist (compare against what's actually enforced)
- **Discrepancy between OPTIONS response and actual enforcement** = CORS misconfiguration

**Also test on discovered API endpoints:**
```bash
# API endpoints often have different method handling than the root
for endpoint in /api /api/v1 /graphql; do
  curl -sI -X OPTIONS "https://{target}${endpoint}" 2>/dev/null | grep -iE 'allow:|access-control-allow-methods'
done
```

---

## 1.8 — CSP Architecture Extraction

**CRITICAL:** When the application subdomain (e.g., `app.{target}`) returns a `Content-Security-Policy` header, the `connect-src`, `frame-src`, `frame-ancestors`, and `script-src` directives are a goldmine of backend architecture intelligence. This frequently reveals more infrastructure than any other recon technique.

```bash
# Fetch CSP from application subdomain (often has richer CSP than marketing site)
curl -sI "https://app.{target}/" 2>/dev/null | grep -i "content-security-policy" | \
  tr ';' '\n' | grep -iE 'connect-src|frame-src|frame-ancestors|script-src'
```

**Parse the CSP for:**

| Directive | What it reveals | Example |
|---|---|---|
| `connect-src` | **All backend APIs, databases, third-party services** the app talks to | Cloud Run URLs, Firebase, Elasticsearch, WebSocket endpoints |
| `frame-src` | Embedded services, OAuth providers, payment iframes | Stripe, Google Auth, dev Firebase projects |
| `frame-ancestors` | White-label partners, staging domains, admin panels | `rezi-admin.netlify.app`, `stage.testnzm1.xyz` |
| `script-src` | CDN sources, analytics, A/B testing | `http://localhost:*` = dev config leaked to prod |

**Look for in parsed CSP:**
- **Cloud Run / Cloud Functions URLs** — pattern `{service}-{projecthash}-uc.a.run.app` reveals microservice names AND GCP project IDs. Two different project hashes = dev + prod.
- **Firebase project IDs** — `{project}.firebaseapp.com`, `{project}.firebaseio.com`, `us-central1-{project}.cloudfunctions.net`
- **Elasticsearch/database cluster IDs** — full cluster URLs with instance IDs
- **WebSocket endpoints** — `wss://*.livekit.cloud`, `wss://api.assemblyai.com` reveal real-time/AI infrastructure
- **`http://localhost:*`** or **`ws://localhost:*`** or **`http://127.0.0.1:*`** — development configuration leaked to production CSP
- **Staging/QA domains** in `frame-ancestors` — `stage.*.xyz`, `qa.*.xyz` may be registerable by attackers
- **Admin panel URLs** — `*-admin.netlify.app` or similar in `frame-ancestors`

**For each Cloud Run URL discovered, probe it:**
```bash
curl -sI "https://{service}-{hash}-uc.a.run.app/" | head -10
```

Look for: authentication status (200 vs 401 vs 404), CORS headers, server identification, debug info.

**Origin:** Discovered during rezi.ai audit where a single CSP header revealed 13 Cloud Run microservices, 2 Firebase projects (prod + dev), an Elasticsearch cluster, LiveKit/AssemblyAI integrations, an admin panel URL, localhost debug references, and 10+ white-label partner domains.

---

---

## 1.9 — WAF Detection (wafw00f)

**Why:** Knowing the WAF type determines which fuzzing payloads will work in later phases. Testing blind wastes time.

```bash
# If wafw00f is installed
if command -v wafw00f &> /dev/null; then
  wafw00f https://{target}
else
  # Manual WAF fingerprinting via response behavior
  # Send a suspicious request and check for WAF signatures
  curl -sI "https://{target}/?id=1' OR 1=1--" | grep -iE 'server:|x-cdn|cf-ray|x-sucuri|x-akamai|x-aws-waf|x-shield|x-firewall'

  # Check for common WAF block pages
  response=$(curl -s -o /dev/null -w "%{http_code}" "https://{target}/<script>alert(1)</script>")
  echo "XSS probe response: $response"
  # 403/406/429 = WAF likely blocking; 200/404 = no WAF or WAF not catching this
fi
```

**Common WAF signatures:**

| WAF | Detection Signal |
|---|---|
| Cloudflare | `cf-ray` header, `Server: cloudflare` |
| AWS WAF | `x-amzn-requestid`, 403 with AWS error page |
| Akamai | `X-Akamai-*` headers, `Server: AkamaiGHost` |
| Sucuri | `X-Sucuri-ID`, `Server: Sucuri/Cloudproxy` |
| ModSecurity | `Server: Apache/2.x (mod_security)`, 403 with ModSec error |
| Imperva/Incapsula | `X-CDN: Incapsula`, `visid_incap_*` cookies |
| F5 BIG-IP | `Server: BigIP`, `BIGipServer*` cookies |

**Impact on later phases:** If a WAF is detected, fuzzing payloads in Phase 7b need WAF-evasion encoding (double URL encoding, case alternation, comment insertion).

---

## 1.10 — Subdomain Discovery (passive sources)

**Why:** Our Phase 1.5 checks ~30 hardcoded prefixes. Passive sources (certificate transparency logs, DNS datasets, web archives) find subdomains we'd never guess.

```bash
# Method 1: subfinder (if installed) — queries CT logs, DNS datasets, web archives
if command -v subfinder &> /dev/null; then
  subfinder -d {target} -silent | sort -u
fi

# Method 2: amass passive mode (if installed) — broadest coverage
if command -v amass &> /dev/null; then
  amass enum -passive -d {target} -silent | sort -u
fi

# Method 3: Certificate Transparency logs (always available, no install needed)
curl -s "https://crt.sh/?q=%25.{target}&output=json" | \
  python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" 2>/dev/null | \
  sort -u | grep -v '^\*'

# Method 4: DNS brute force with extended wordlist (if SecLists available)
if [ -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt ]; then
  while read sub; do
    result=$(dig +short "$sub.{target}" A 2>/dev/null)
    [ -n "$result" ] && echo "$sub.{target} -> $result"
  done < /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
fi
```

**For each new subdomain found:** Run headers check, port probe (80, 443, 8080, 8443), and note for subdomain takeover assessment in Phase 5.

---

## 1.11 — OSINT & Email Harvesting (theHarvester)

**Why:** Harvested email addresses enrich the personnel exposure assessment (Phase 7) and inform phishing risk calculations.

```bash
# theHarvester — queries search engines, Shodan, Censys, etc.
if command -v theHarvester &> /dev/null; then
  theHarvester -d {target} -b all -l 200
fi

# Manual email pattern discovery
# Check common email disclosure points
curl -s "https://{target}/team" "https://{target}/about" "https://{target}/contact" 2>/dev/null | \
  grep -oiE '[a-zA-Z0-9._%+-]+@{target}' | sort -u

# Check for Hunter.io-style email patterns (if the domain uses predictable formats)
# Look for mailto: links
curl -s "https://{target}" | grep -oiE 'mailto:[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+' | sort -u
```

---

## 1.12 — Shodan / Censys Passive Recon

**Why:** These services have already scanned the target's IP. Their data reveals open ports, services, TLS certs, and banners without us sending a single packet.

```bash
# Shodan CLI (if installed and API key configured)
if command -v shodan &> /dev/null; then
  IP=$(dig +short {target} A | head -1)
  shodan host "$IP"
fi

# Censys CLI (if installed)
if command -v censys &> /dev/null; then
  censys search "dns.names: {target}" --index-type hosts
fi

# Manual Shodan check via web (always available)
# Document: search shodan.io for the target IP and note open ports, services, vulns
```

---

## 1.13 — Document Metadata Harvesting (ExifTool)

**Why:** PDFs, images, and documents hosted on the site contain metadata that leaks author names, software versions, internal hostnames, and filesystem paths.

```bash
# Find downloadable documents
curl -s "https://{target}/sitemap.xml" 2>/dev/null | grep -oiE 'https?://[^<]+\.(pdf|doc|docx|xls|xlsx|pptx?)' | head -20

# For each document found, download and extract metadata
if command -v exiftool &> /dev/null; then
  for doc_url in $(curl -s "https://{target}" | grep -oiE 'href="[^"]+\.(pdf|doc|docx)"' | sed 's/href="//;s/"$//' | head -10); do
    # Make URL absolute if relative
    [[ "$doc_url" != http* ]] && doc_url="https://{target}${doc_url}"
    tmpfile=$(mktemp /tmp/meta_XXXXXX)
    curl -s "$doc_url" -o "$tmpfile" --max-time 10
    echo "=== $doc_url ==="
    exiftool "$tmpfile" 2>/dev/null | grep -iE 'author|creator|producer|title|subject|company|manager|last.modified|software'
    rm -f "$tmpfile"
  done
fi
```

**What metadata reveals:**
- **Author/Creator** — employee names (personnel enumeration)
- **Software** — internal software and versions (e.g., "Microsoft Word 16.0", "Adobe InDesign CC 2023")
- **Company** — legal entity name, sometimes different from brand name
- **Last Modified By** — another employee name
- **Producer** — PDF converter, may reveal server-side rendering stack

---

## 1.14 — Cloudflare/CDN Origin IP Discovery

**Why:** If the target is behind Cloudflare or another CDN, the real origin IP may be directly accessible — bypassing all WAF protections.

```bash
# Method 1: Check historical DNS records
# If CloudFail is installed
if command -v cloudfail &> /dev/null; then
  cloudfail -t {target}
fi

# Method 2: Check for origin IP leaks in common places
# Mail headers — MX servers often run on the same IP as the web server
MX_HOST=$(dig +short {target} MX | sort -n | head -1 | awk '{print $2}' | sed 's/\.$//')
if [ -n "$MX_HOST" ]; then
  MX_IP=$(dig +short "$MX_HOST" A)
  echo "MX server $MX_HOST -> $MX_IP"
  # Check if the MX IP hosts the website too
  curl -sI "https://${MX_IP}" -H "Host: {target}" --max-time 5 -k 2>/dev/null | head -5
fi

# Method 3: Check subdomains that might not be proxied
for sub in direct origin backend api mail ftp cpanel webmail; do
  ip=$(dig +short "$sub.{target}" A 2>/dev/null)
  if [ -n "$ip" ]; then
    # Check if this IP is NOT a CDN IP
    echo "$sub.{target} -> $ip"
    curl -sI "https://${ip}" -H "Host: {target}" --max-time 5 -k 2>/dev/null | head -3
  fi
done

# Method 4: Check certificate transparency for non-CDN IPs
# SANs from the certificate may point to the origin
```

**If origin IP is found:** This becomes the primary target for Phase 8a (server-side exploitation) — port scanning, SSH probing, and admin panel attacks all bypass the WAF.

---

**Document:** Complete technology stack table with component, version (if detectable), and source of detection. Include HTTP method enumeration results, CSP architecture mapping, WAF detection, subdomain discovery, and OSINT findings.
