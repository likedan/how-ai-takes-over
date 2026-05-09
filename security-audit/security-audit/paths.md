---
description: "Phase 5: Path & file enumeration + subdomain takeover check"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 5: Path & File Enumeration

**Target:** $ARGUMENTS

**Goal:** Discover exposed admin panels, API endpoints, sensitive files, directories, and subdomain takeover risks.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 5 status, add confirmed findings, chain candidates, and failed techniques.

---

## 5.1 — robots.txt & sitemap.xml

```bash
curl -s https://{target}/robots.txt
curl -s https://{target}/sitemap.xml
```

robots.txt is an attacker's roadmap — Disallow paths reveal what the site considers sensitive. Disallow does NOT prevent access.

---

## 5.2 — Common sensitive paths

**IMPORTANT:** Use `-L` flag to follow redirects and check the final status code. Run in parallel for speed.

**Tier 1 — Critical paths (always check):**
```bash
# Secrets & source code
curl -sI -L https://{target}/.env
curl -sI -L https://{target}/.env.local
curl -sI -L https://{target}/.env.production
curl -sI -L https://{target}/.env.backup
curl -sI -L https://{target}/.git/config
curl -sI -L https://{target}/.git/HEAD
curl -sI -L https://{target}/.git/logs/HEAD
curl -sI -L https://{target}/.git/COMMIT_EDITMSG
curl -sI -L https://{target}/.git/packed-refs
curl -sI -L https://{target}/.svn/entries
curl -sI -L https://{target}/.DS_Store
curl -sI -L https://{target}/.htaccess
curl -sI -L https://{target}/.htpasswd

# Admin panels
curl -sI -L https://{target}/admin
curl -sI -L https://{target}/admin/login
curl -sI -L https://{target}/administrator
curl -sI -L https://{target}/wp-admin
curl -sI -L https://{target}/wp-login.php
curl -sI -L https://{target}/login
curl -sI -L https://{target}/dashboard
curl -sI -L https://{target}/console
curl -sI -L https://{target}/portal
curl -sI -L https://{target}/manager
curl -sI -L https://{target}/cpanel
curl -sI -L https://{target}/_admin

# API & docs
curl -sI -L https://{target}/api
curl -sI -L https://{target}/api/v1
curl -sI -L https://{target}/api/v2
curl -sI -L https://{target}/graphql
curl -sI -L https://{target}/swagger
curl -sI -L https://{target}/swagger-ui.html
curl -sI -L https://{target}/swagger.json
curl -sI -L https://{target}/openapi.json
curl -sI -L https://{target}/api-docs
curl -sI -L https://{target}/redoc
curl -sI -L https://{target}/docs

# Debug & monitoring
curl -sI -L https://{target}/debug
curl -sI -L https://{target}/status
curl -sI -L https://{target}/health
curl -sI -L https://{target}/healthz
curl -sI -L https://{target}/server-status
curl -sI -L https://{target}/server-info
curl -sI -L https://{target}/phpinfo.php
curl -sI -L https://{target}/info.php
curl -sI -L https://{target}/elmah.axd
curl -sI -L https://{target}/trace.axd
curl -sI -L https://{target}/_profiler

# Security & well-known
curl -sI -L https://{target}/.well-known/security.txt
curl -sI -L https://{target}/.well-known/openid-configuration
curl -sI -L https://{target}/.well-known/jwks.json
curl -sI -L https://{target}/.well-known/apple-app-site-association
curl -sI -L https://{target}/.well-known/assetlinks.json
```

**Tier 2 — Backup & config exposure (Nuclei-inspired):**
```bash
# Backup files (common patterns from Nuclei's 'exposures' templates)
curl -sI -L https://{target}/backup.sql
curl -sI -L https://{target}/backup.zip
curl -sI -L https://{target}/backup.tar.gz
curl -sI -L https://{target}/db.sql
curl -sI -L https://{target}/database.sql
curl -sI -L https://{target}/dump.sql
curl -sI -L https://{target}/data.sql
curl -sI -L https://{target}/{domain}.sql
curl -sI -L https://{target}/{domain}.zip
curl -sI -L https://{target}/site.tar.gz
curl -sI -L https://{target}/www.zip
curl -sI -L https://{target}/web.config
curl -sI -L https://{target}/config.json
curl -sI -L https://{target}/config.yml
curl -sI -L https://{target}/config.yaml
curl -sI -L https://{target}/application.yml
curl -sI -L https://{target}/application.properties
curl -sI -L https://{target}/settings.json
curl -sI -L https://{target}/credentials.json

# Config files that commonly leak
curl -sI -L https://{target}/wp-config.php.bak
curl -sI -L https://{target}/wp-config.php.old
curl -sI -L https://{target}/wp-config.php~
curl -sI -L https://{target}/configuration.php.bak
curl -sI -L https://{target}/.npmrc
curl -sI -L https://{target}/.dockerenv
curl -sI -L https://{target}/Dockerfile
curl -sI -L https://{target}/docker-compose.yml
curl -sI -L https://{target}/package.json
curl -sI -L https://{target}/composer.json
curl -sI -L https://{target}/Gemfile
curl -sI -L https://{target}/requirements.txt
```

**Tier 3 — Exposed panels by product (top 50 from Nuclei's 1000+):**
```bash
# DevOps & infrastructure
curl -sI -L https://{target}/jenkins
curl -sI -L https://{target}/grafana
curl -sI -L https://{target}/kibana
curl -sI -L https://{target}/prometheus
curl -sI -L https://{target}/prometheus/targets
curl -sI -L https://{target}/actuator
curl -sI -L https://{target}/actuator/env
curl -sI -L https://{target}/actuator/health
curl -sI -L https://{target}/actuator/configprops
curl -sI -L https://{target}/metrics
curl -sI -L https://{target}/jolokia
curl -sI -L https://{target}/haproxy?stats
curl -sI -L https://{target}/solr/admin
curl -sI -L https://{target}/phpmyadmin
curl -sI -L https://{target}/adminer.php
curl -sI -L https://{target}/mailhog
curl -sI -L https://{target}/flower

# CMS & frameworks
curl -sI -L https://{target}/strapi
curl -sI -L https://{target}/ghost
curl -sI -L https://{target}/keystone
curl -sI -L https://{target}/directus
curl -sI -L https://{target}/studio
curl -sI -L https://{target}/sanity

# Cloud & storage
curl -sI -L https://{target}/.aws/credentials
curl -sI -L https://{target}/.gcloud/credentials.json
curl -sI -L https://{target}/firebase-debug.log
curl -sI -L https://{target}/__firebase/init.json

# API gateway debug/health endpoints (also check on api.{domain})
curl -sI -L https://{target}/__health
curl -sI -L https://{target}/__debug
curl -sI -L https://{target}/__debug/config
curl -sI -L https://{target}/__debug/router
curl -sI -L https://{target}/__stats
curl -sI -L https://{target}/__echo
```

**API gateway endpoints by product:**

| Gateway | Debug Endpoints | What they leak |
|---|---|---|
| KrakenD | `/__health`, `/__debug/config`, `/__debug/router`, `/__stats` | Uptime, routing table, backend config |
| Kong | `/status`, `/{admin-path}/` | Service/route listing, plugin config |
| Traefik | `/api/overview`, `/api/rawdata`, `/dashboard/` | Full routing config, middleware chain |
| Envoy | `/stats`, `/config_dump`, `/clusters` | Full mesh config, upstream endpoints |

**For each path that returns 200 or 301/302:** Investigate further. Follow redirects to see what's actually exposed.

**For paths returning 403:** Note them — a 403 (vs 404) confirms the path exists but is blocked. This leaks information about the server's WAF rules or directory structure.

**Middleware redirect patterns:** Some frameworks (especially Next.js) use middleware to redirect suspicious paths. Look for patterns like `307 → /login → 404` — document the pattern, it confirms middleware exists.

---

## 5.3 — Git Repository Exposure & Secret Scanning

**Trigger:** If `/.git/HEAD` or `/.git/config` returns 200 in the Tier 1 scan.

**Step 1: Confirm exposure depth**
```bash
# If HEAD returns 200, check what's accessible
curl -s https://{target}/.git/HEAD          # Should show "ref: refs/heads/main" or similar
curl -s https://{target}/.git/config        # Reveals remote URLs, author info, branch config
curl -s https://{target}/.git/logs/HEAD     # Full commit log with emails and timestamps
curl -s https://{target}/.git/packed-refs   # All branch/tag refs
curl -s https://{target}/.git/COMMIT_EDITMSG # Last commit message
curl -s https://{target}/.git/description   # Repo description
curl -s https://{target}/.git/info/refs     # Ref listing (if smart HTTP enabled)
```

**Step 2: Attempt object download**
```bash
# From HEAD, get the current commit hash
HEAD_REF=$(curl -s https://{target}/.git/HEAD | awk '{print $2}')
COMMIT_HASH=$(curl -s "https://{target}/.git/$HEAD_REF")

# Try to download the commit object (first 2 chars = dir, rest = filename)
DIR=$(echo $COMMIT_HASH | cut -c1-2)
FILE=$(echo $COMMIT_HASH | cut -c3-)
curl -sI "https://{target}/.git/objects/$DIR/$FILE"

# Try pack index (large repos use packfiles instead of loose objects)
curl -s https://{target}/.git/objects/info/packs
```

**Step 3: Scan for secrets in accessible git data**

If `/.git/config` is readable, look for:
- **Remote URLs** with embedded credentials (`https://user:token@github.com/...`)
- **Deploy keys** or tokens in config
- **Author emails** — personnel intelligence

If `/.git/logs/HEAD` is readable, scan for:
- **Email addresses** of all committers (personnel enumeration)
- **Commit messages** referencing secrets, API keys, internal systems, JIRA tickets
- **Branch names** revealing internal project structure

**Step 4: Check for related source exposure**
```bash
# If .git is exposed, source maps and other dev artifacts are likely too
curl -sI https://{target}/.gitignore          # Reveals what they're hiding
curl -sI https://{target}/.env.example        # Template may contain real service names
curl -sI https://{target}/package-lock.json   # Full dependency tree with versions
curl -sI https://{target}/yarn.lock
```

**Impact:** Full `.git` exposure = complete source code reconstruction. Even partial exposure (just `config` + `logs/HEAD`) leaks developer identities, internal infrastructure URLs, and commit history that may reference secrets.

---

## 5.4 — Technology-specific paths

**Next.js / Vercel:**
```bash
curl -sI https://{target}/_next/data/
curl -sI https://{target}/studio
curl -sI https://{target}/api/revalidate
curl -sI https://{target}/api/health
curl -sI https://{target}/api/auth
curl -sI https://{target}/_next/image   # Image optimization endpoint (test for SSRF)

# Build manifests — reveal route structure and page list
curl -s "https://{target}/_next/static/{buildId}/_buildManifest.js" 2>/dev/null | head -30
curl -s "https://{target}/_next/static/{buildId}/_ssgManifest.js" 2>/dev/null | head -10

# Source maps — check EVERY JS chunk (see Phase 1.3b for methodology)
```

**WordPress:**
```bash
# REST API namespace enumeration — reveals all installed plugins/features
curl -s https://{target}/wp-json/ | head -100
curl -s https://{target}/wp-json/wp/v2/users
curl -sI https://{target}/xmlrpc.php

# User enumeration via author pages (works even when REST API is locked)
for i in 1 2 3 4 5 6 7 8 9 10; do
  curl -sI -L "https://{target}/?author=$i" 2>/dev/null | grep -i "location:"
done

# WooCommerce Store API (unauthenticated by design)
curl -s "https://{target}/wp-json/wc/store/v1/products" | head -50
curl -s "https://{target}/wp-json/wc/store/v1/cart" | head -20

# wp-cron (externally triggerable scheduled tasks)
curl -sI "https://{target}/wp-cron.php"

# wp-config backup files — test 403 vs 404 differentiation
for ext in .bak .old .txt ".php~" ".php.bak" ".php.old"; do
  code=$(curl -sI -o /dev/null -w "%{http_code}" "https://{target}/wp-config${ext}" --max-time 3 2>/dev/null)
  [ "$code" != "404" ] && echo "wp-config${ext} -> $code (403=file likely exists, blocked by WAF)"
done
```

**React CRA / Vite SPAs:**
```bash
# CRA asset manifest — lists all JS/CSS files with hashes
curl -s "https://{target}/asset-manifest.json" | head -50
# CRA manifest — may reveal app name and description
curl -s "https://{target}/manifest.json" | head -20

# Source maps for CRA — check the main bundle
# If asset-manifest.json exists, extract JS paths and check each .js.map
```

**Webflow:**
```bash
# manifest.json — leaks publish version, site IDs, renderer info
curl -s "https://{target}/manifest.json" | head -20
# Cloudflare cdn-cgi endpoint
curl -s "https://{target}/cdn-cgi/trace" | head -20
```

**Mobile app deep-link discovery:**
```bash
# iOS — Apple App Site Association (reveals Team ID, app bundle, deep-link routes, webcredentials)
curl -s "https://{target}/.well-known/apple-app-site-association" | head -50

# Android — Asset Links (reveals package name, signing cert fingerprint)
curl -s "https://{target}/.well-known/assetlinks.json" | head -30
```

**Impact of mobile app links:** AASA/assetlinks reveal the app's URL routing structure (game rooms, payment flows, auth endpoints), iOS Team ID (stable identifier), Android signing cert SHA-256 (cannot be changed without re-signing), and webcredentials associations (passkey/autofill). Found in partytime.gg audit.

Also check any API endpoints discovered in JS bundle scan (Phase 1.3).

---

## 5.5 — Subdomain Takeover Assessment

For each subdomain with a DNS record but closed/unreachable ports:

**Takeover risk is HIGH when:**
- DNS A record points to an IP with all ports closed (instance may be terminated)
- DNS CNAME points to a service returning "not found"
- The underlying cloud resource has been deleted but DNS still points to it

**Common vulnerable patterns:**

| DNS Target | Service | Takeover Method |
|---|---|---|
| `*.amazonaws.com` (EC2) | AWS | Acquire released Elastic IP |
| `*.herokuapp.com` | Heroku | Create app with matching name |
| `*.s3.amazonaws.com` | AWS S3 | Create bucket with matching name |
| `*.azurewebsites.net` | Azure | Create app with matching name |
| `*.netlify.app` | Netlify | Create site with matching name |

---

## 5.6 — Web Server Scanning (Nikto)

**Why:** Nikto checks thousands of server misconfigurations, outdated software, and dangerous files that our manual path list doesn't cover — including server-specific default pages, CGI vulnerabilities, and version-specific exploits.

```bash
if command -v nikto &> /dev/null; then
  nikto -h https://{target} -maxtime 120s -no404 -C all 2>&1 | head -100
fi
```

**What Nikto finds that we don't manually check:**
- Default server pages revealing versions (IIS welcome page, Apache test page)
- CGI scripts with known vulnerabilities
- Dangerous HTTP methods enabled on specific paths
- Server software identified by behavior (not just headers)
- Outdated SSL configurations
- Misconfigured directory indexes on non-root paths

---

## 5.7 — Directory Brute Forcing (gobuster / dirsearch)

**Why:** Our hardcoded path list covers ~100 common paths. Directory brute forcing with a wordlist finds application-specific paths, hidden admin panels, and forgotten endpoints.

**Only run when initial path enumeration suggests there's more to find** (e.g., several 403s indicating directory structure exists, or an app framework known for deep path hierarchies like WordPress, Django, or Spring Boot).

```bash
# gobuster (Go, fast)
if command -v gobuster &> /dev/null; then
  gobuster dir -u https://{target} -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -t 10 -q --no-error -s "200,301,302,403" 2>/dev/null | head -50
fi

# dirsearch (Python, good default wordlists)
if command -v dirsearch &> /dev/null; then
  dirsearch -u https://{target} -e php,html,js,json,txt -t 10 --quiet 2>/dev/null | head -50
fi

# Fallback: minimal brute force with curl and a small wordlist
# Use SecLists if available, otherwise skip
if [ -f /usr/share/seclists/Discovery/Web-Content/common.txt ]; then
  head -200 /usr/share/seclists/Discovery/Web-Content/common.txt | while read path; do
    code=$(curl -sI -o /dev/null -w "%{http_code}" -L "https://{target}/${path}" --max-time 3 2>/dev/null)
    [ "$code" != "404" ] && [ "$code" != "000" ] && echo "$path -> $code"
  done
fi
```

**SecLists wordlists to use (by priority):**
- `Discovery/Web-Content/common.txt` — 4,700 entries, fast baseline
- `Discovery/Web-Content/raft-medium-directories.txt` — 30,000 entries, thorough
- `Discovery/Web-Content/directory-list-2.3-small.txt` — 87,000 entries, comprehensive
- Stack-specific lists: `Discovery/Web-Content/CMS/wordpress.fuzz.txt`, `Discovery/Web-Content/spring-boot.txt`

**Note:** Only use large wordlists with explicit user authorization — they generate significant traffic and may trigger WAF blocks or rate limiting.

---

**Document:** Table of all paths checked, HTTP status codes, redirect chains, subdomain takeover risks, Nikto findings, and directory brute force results.
