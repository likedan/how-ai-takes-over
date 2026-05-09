---
description: "Phase 8b: Version-specific CVE testing for detected software"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 8b: Version-Specific CVE Testing

**Target:** $ARGUMENTS

**Goal:** When specific software versions are identified (from headers, stack traces, or error pages), check for known CVEs and test whether they're exploitable.

**When to run:** After Phase 1 (recon) and Phase 8 (server exploit) have identified specific software versions.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 8b status, add confirmed findings, chain candidates, and failed techniques.

---

## 8b.1 — Version Inventory

**Compile all identified software with versions from earlier phases:**

| Source | Software | Version | How detected |
|---|---|---|---|
| `Server` header | nginx, Apache, IIS | e.g., 1.22.1 | HTTP response headers |
| `X-Powered-By` header | Express, PHP, ASP.NET | e.g., Express | HTTP response headers |
| Stack trace (Phase 8) | Node.js, body-parser, raw-body | inferred from internal paths | Error handling probe |
| Page source | jQuery, React, Vue, Angular | e.g., 3.5.1 | Script tags, bundle filenames |
| TLS certificate | OpenSSL | inferred from cipher support | Cipher enumeration |
| SSH banner | OpenSSH | e.g., 9.2p1 | Port scan |
| CMS detection | WordPress, Drupal, Joomla | from meta tags, paths | Page source / path enum |
| DNS | BIND, PowerDNS | from version.bind query | DNS probing |

---

## 8b.2 — CVE Lookup

**For each identified software + version, search for known CVEs:**

```bash
# Use the NIST NVD API (no auth required, rate limited)
curl -s "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={software}+{version}&resultsPerPage=10" | \
  python3 -c "
import sys, json
data = json.load(sys.stdin)
for vuln in data.get('vulnerabilities', []):
  cve = vuln['cve']
  cve_id = cve['id']
  desc = cve['descriptions'][0]['value'][:120]
  metrics = cve.get('metrics', {})
  score = 'N/A'
  for key in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
    if key in metrics:
      score = metrics[key][0]['cvssData']['baseScore']
      break
  print(f'{cve_id} (CVSS {score}): {desc}')
"
```

**Alternative: WebSearch for recent advisories:**
- Search: `"{software} {version}" CVE site:nvd.nist.gov`
- Search: `"{software} {version}" vulnerability advisory`
- Search: `"{software} {version}" exploit`

---

## 8b.3 — Common High-Impact CVEs by Technology

**Check these first — they're the most commonly exploitable:**

### Web Servers

**nginx:**
| Version Range | CVE | Severity | What it does |
|---|---|---|---|
| < 1.25.5 | CVE-2024-7347 | Medium | mp4 module buffer overread |
| < 1.21.0 | CVE-2021-23017 | Critical | DNS resolver off-by-one (if resolver used) |
| 1.0.x-1.22.x | Various | Medium | HTTP/2 rapid reset, header injection in specific configs |

**Apache:**
| Version Range | CVE | Severity |
|---|---|---|
| 2.4.49-2.4.50 | CVE-2021-41773/42013 | Critical — Path traversal + RCE |
| < 2.4.52 | CVE-2021-44790 | Critical — mod_lua buffer overflow |

### JavaScript / Node.js

**Express.js:**
| Dependency | CVE | Severity |
|---|---|---|
| body-parser < 1.20.3 | CVE-2024-45590 | High — Denial of service via Content-Type |
| qs < 6.13.0 | CVE-2024-48950 | High — Prototype pollution |
| cookie < 0.7.0 | CVE-2024-47764 | Medium — Cookie parsing bypass |

**jQuery:**
| Version Range | CVE | Severity |
|---|---|---|
| < 3.5.0 | CVE-2020-11022/11023 | Medium — XSS via HTML sanitization |
| < 3.0.0 | CVE-2015-9251 | Medium — XSS in $.ajax |

### CMS Platforms

**WordPress:**
```bash
# Check WordPress version
curl -s "https://{target}/wp-includes/version.php" 2>/dev/null
curl -s "https://{target}/feed/" | grep -o 'generator.*wordpress.com/\?v=[0-9.]*'
# Check for known vulnerable plugins
curl -sI "https://{target}/wp-content/plugins/contact-form-7/readme.txt"
curl -sI "https://{target}/wp-content/plugins/elementor/readme.txt"
curl -sI "https://{target}/wp-content/plugins/woocommerce/readme.txt"
```

### Databases (if directly exposed — Phase 8 port scan)

| Database | Default Port | Quick Version Check |
|---|---|---|
| MySQL | 3306 | `mysql -h {ip} -u root --connect-timeout=3 2>&1 | head -1` |
| PostgreSQL | 5432 | `psql -h {ip} -U postgres -c "SELECT version();" --connect-timeout=3 2>&1 | head -1` |
| Redis | 6379 | `redis-cli -h {ip} INFO server 2>&1 | grep redis_version` |
| MongoDB | 27017 | `curl -s http://{ip}:27017` (returns version in error page) |

### SSH

**OpenSSH:**
| Version Range | CVE | Severity |
|---|---|---|
| 8.5p1-9.7p1 | CVE-2024-6387 (regreSSHion) | Critical — Remote unauthenticated RCE (race condition, glibc-based Linux) |
| < 9.3p2 | CVE-2023-38408 | High — Remote code execution via ssh-agent forwarding |

---

## 8b.4 — Exploitability Assessment

**For each CVE found, assess whether it's actually exploitable on this target:**

| Factor | Question | Impact on exploitability |
|---|---|---|
| **Exact version match** | Is the detected version within the vulnerable range? | Required |
| **Configuration** | Does the vuln require a specific config (e.g., nginx mp4 module, Apache mod_lua)? | May not apply |
| **Network access** | Is the vulnerable service reachable from the internet? | Required for remote exploit |
| **WAF/CDN** | Is the service behind a WAF that might block the exploit payload? | May mitigate |
| **OS/arch** | Does the exploit require specific OS (e.g., regreSSHion needs glibc Linux)? | May not apply |
| **Exploit availability** | Is there a public PoC? Metasploit module? | Determines attacker effort |

**Grading:**
- **Confirmed exploitable** — version match + configuration match + network reachable + public PoC exists
- **Likely exploitable** — version match + network reachable, but config/PoC uncertain
- **Unlikely exploitable** — version match but config doesn't apply or WAF blocks
- **Not exploitable** — version outside vulnerable range

### CVE Verification Rules (Anti-Hallucination)

CVE matching is where LLMs most frequently hallucinate — inventing CVE IDs, misattributing version ranges, or describing vulnerabilities that don't exist for the detected software.

1. **Never invent CVE IDs.** Only cite CVEs that appear in the pre-built tables above OR that were returned by the NVD API / WebSearch in this session. If you're unsure of a CVE ID, look it up — don't guess.
2. **Version ranges must be verified.** Don't assume a version is vulnerable because it "seems old." Check the actual affected version range from NVD. A server running nginx 1.24.0 is NOT affected by a CVE that only impacts < 1.21.0.
3. **"Version detected" ≠ "version confirmed."** An `X-Powered-By: Express` header doesn't tell you the Express version. A jQuery filename like `jquery-3.6.0.min.js` DOES. Report the confidence of the version detection alongside the CVE match.
4. **NVD API can return irrelevant results.** Keyword search for "express 4.18" may return CVEs for completely different software. Verify that each returned CVE actually applies to the specific software and version in question by reading the description.
5. **Configuration-dependent CVEs must note the dependency.** If a CVE requires mod_lua (Apache) or resolver directive (nginx) and you have no evidence that module/config is active, the CVE is UNLIKELY, not CONFIRMED.

---

## 8b.5 — Test Specific CVEs (where safe)

**Only test CVEs that are safe to verify without causing damage:**

```bash
# Example: Test for CVE-2021-41773 (Apache path traversal)
curl -s "https://{target}/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

# Example: Test for jQuery XSS (CVE-2020-11022)
# Check if jQuery version is < 3.5.0 from page source
curl -s "https://{target}" | grep -oE 'jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)' | head -3

# Example: Test for OpenSSH regreSSHion (check version only — do NOT exploit)
nmap -sV -p 22 {ip} 2>&1 | grep "OpenSSH"
# If version 8.5p1-9.7p1 on glibc Linux → flag as CRITICAL

# Example: Test for Express body-parser DoS (CVE-2024-45590)
# Check if the stack trace from Phase 8 shows body-parser version
# If body-parser < 1.20.3 → flag as HIGH
```

**NEVER run destructive exploits (DoS, data corruption, RCE payloads) unless the user has explicitly authorized active exploitation beyond standard testing.**

---

## 8b.6 — Dependency Chain Analysis

**When a stack trace (Phase 8) reveals dependency names, check the full dependency tree:**

```bash
# If package.json is accessible (unlikely but check)
curl -s "https://{target}/package.json" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for dep, ver in {**data.get('dependencies',{}), **data.get('devDependencies',{})}.items():
  print(f'{dep}: {ver}')
"

# If specific dependencies are known from stack trace, check npm advisories
# Search: "npm audit {package-name}" or check https://www.npmjs.com/advisories
```

**For WordPress, check plugin vulnerabilities:**
```bash
# WPScan-style plugin version check
for plugin_path in $(curl -s "https://{target}/" | grep -oE '/wp-content/plugins/[^/]+/' | sort -u); do
  readme=$(curl -s "https://{target}${plugin_path}readme.txt" 2>/dev/null)
  version=$(echo "$readme" | grep -i "stable tag:" | head -1)
  echo "${plugin_path} -> $version"
done
```

---

## 8b.7 — Automated Vulnerability Scanning (Nuclei)

**Why:** Nuclei has 8,000+ community-maintained vulnerability templates. One command tests for thousands of known CVEs, misconfigurations, exposed panels, default credentials, and technology-specific vulnerabilities that would take days to check manually.

```bash
if command -v nuclei &> /dev/null; then
  # Full scan — all relevant template categories
  nuclei -u https://{target} \
    -t cves/ \
    -t vulnerabilities/ \
    -t exposures/ \
    -t misconfiguration/ \
    -t default-logins/ \
    -t takeovers/ \
    -severity critical,high,medium \
    -silent -no-color 2>&1 | head -100

  # Technology-specific scan (run after Phase 1 identifies the stack)
  # WordPress
  nuclei -u https://{target} -tags wordpress -silent 2>&1 | head -50

  # Spring Boot / Java
  nuclei -u https://{target} -tags spring,springboot,java -silent 2>&1 | head -50

  # Apache/Nginx
  nuclei -u https://{target} -tags apache,nginx -silent 2>&1 | head -50

  # Cloud/DevOps
  nuclei -u https://{target} -tags aws,azure,gcp,docker,kubernetes -silent 2>&1 | head -50
fi
```

**What Nuclei finds that we can't easily check manually:**
- **CVE-specific exploits** — thousands of version-matched CVE checks with safe payloads
- **Default credentials** — tests hundreds of default username/password combinations for admin panels
- **Exposed panels** — detects admin interfaces by response fingerprints, not just path guessing
- **Subdomain takeover** — checks if CNAME targets are claimable
- **Misconfigurations** — detects .git exposure, debug modes, open redirects, SSRF, etc.
- **Technology fingerprinting** — matches response patterns to identify exact software versions

**Template categories to prioritize:**

| Category | Templates | What it finds |
|---|---|---|
| `cves/` | ~4,000 | Known CVE exploits with version matching |
| `exposures/` | ~500 | Leaked configs, tokens, backups, source code |
| `misconfiguration/` | ~300 | Debug mode, default settings, open services |
| `default-logins/` | ~200 | Default admin credentials |
| `takeovers/` | ~50 | Subdomain takeover opportunities |
| `vulnerabilities/` | ~1,000 | Generic vuln patterns (SSRF, XSS, SQLi, etc.) |

**Note:** Nuclei generates traffic — each template is an HTTP request. A full scan may send thousands of requests. For targets behind strict WAFs, use `-rate-limit 10` to throttle.

---

**Document:** Version inventory table, CVEs found per component, exploitability assessment for each, any confirmed vulnerabilities with reproduction steps, and Nuclei scan results organized by severity.
