---
description: "Phase 3: TLS & certificate analysis for a target domain"
argument-hint: <url>
allowed-tools: [Bash, Write, Edit, Read]
---

# Phase 3: TLS & Certificate Analysis

**Target:** $ARGUMENTS

**Goal:** Assess transport layer security — protocol versions, cipher strength, certificate validity.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 3 status, add confirmed findings, chain candidates, and failed techniques.

---

## 3.1 — Certificate details

```bash
echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | \
  openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

**Check for:**
- Certificate expiry (< 30 days = warning)
- Wildcard coverage (`*.domain.com`)
- Certificate issuer (Let's Encrypt, Cloudflare, DigiCert, etc.)
- Subject Alternative Names — reveals other domains/subdomains

If subdomains were discovered, check their certificates too.

---

## 3.2 — Protocol and cipher check

**Primary method (testssl.sh — comprehensive, 200+ checks):**

```bash
# testssl.sh is the gold standard — tests for every known TLS vulnerability
if command -v testssl &> /dev/null || [ -f ~/testssl.sh/testssl.sh ]; then
  testssl --quiet --color 0 https://{target}
  # Or with specific checks:
  # testssl --protocols --ciphers --vulnerabilities --headers https://{target}
fi
```

**testssl.sh checks for vulnerabilities that openssl alone misses:**

| Vulnerability | What it does | Impact |
|---|---|---|
| Heartbleed (CVE-2014-0160) | Leaks server memory | Critical — can extract private keys, session data |
| ROBOT | RSA padding oracle | High — decrypt TLS sessions |
| CRIME/BREACH | TLS compression attacks | Medium — extract secrets from compressed responses |
| POODLE | SSLv3 padding oracle | High — decrypt session cookies |
| FREAK/Logjam | Export cipher downgrade | High — MITM via weak ciphers |
| Lucky13 | CBC timing attack | Medium — decrypt TLS records |
| Ticketbleed | Session ticket leak | High — extract 31 bytes of server memory |
| CCS Injection | ChangeCipherSpec injection | High — MITM attack |
| Secure Renegotiation | Client-initiated renegotiation | Medium — DoS, injection |
| ROBOT | Bleichenbacher oracle | High — decrypt past sessions |

**Alternative: SSLyze (Python-based, also comprehensive):**

```bash
if command -v sslyze &> /dev/null; then
  sslyze --regular {target}
fi
```

**Fallback (openssl — always available):**

```bash
echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | grep -E "Protocol|Cipher"

# Test for deprecated TLS versions (should fail)
echo | openssl s_client -connect {target}:443 -servername {target} -tls1_1 2>&1 | grep -E "error|Protocol|alert"
echo | openssl s_client -connect {target}:443 -servername {target} -tls1 2>&1 | grep -E "error|Protocol|alert"
```

**Tertiary method (nmap — if available):**

```bash
nmap --script ssl-enum-ciphers -p 443 {target}
```

**Grade:**
- TLS 1.3 only = A (excellent)
- TLS 1.2 + 1.3 with strong ciphers = B (acceptable)
- TLS 1.1 or below supported = F (critical vulnerability)
- Any CBC or RC4 ciphers = D (weak)
- Any of the above named vulnerabilities found = F (critical)

---

## 3.3 — HSTS completeness

Check `Strict-Transport-Security` for:
- `max-age` ≥ 31536000 (1 year minimum)
- `includeSubDomains` present
- `preload` present
- Domain on hstspreload.org list

---

## 3.4 — CAA Records

```bash
dig +short {target} CAA
dig +short {target} TYPE257  # fallback if CAA type not supported
```

**Check for:**
- **No CAA record at all** = any CA can issue certificates for this domain (medium risk — enables mis-issuance attacks)
- `issue` tag — which CAs are authorized (e.g., `0 issue "letsencrypt.org"`)
- `issuewild` tag — which CAs can issue wildcard certs (should be explicitly restricted)
- `iodef` tag — incident reporting URL (where CA sends policy violation alerts)

**Grade:**
- CAA with `issue` + `issuewild` + `iodef` = A (fully configured)
- CAA with `issue` only = B (partial — wildcards unrestricted)
- No CAA record = D (any CA can issue)

---

## 3.5 — DNSSEC Validation

```bash
dig +dnssec +short {target} A
dig {target} DNSKEY +short
dig {target} DS +short
```

**Check for:**
- `RRSIG` records in the `+dnssec` response → DNSSEC is active
- `DNSKEY` records → zone signing keys exist
- `DS` records → parent zone delegation is signed

**If no DNSSEC:**
- DNS responses can be spoofed (cache poisoning, man-in-the-middle on DNS)
- Combined with no CAA → attacker can poison DNS AND get a valid cert from any CA

**Grade:**
- Full DNSSEC chain (DS + DNSKEY + RRSIG) = A
- Partial (DNSKEY but no DS in parent) = C (broken chain)
- No DNSSEC = D (common but noted — most sites don't have it, but it chains with other findings)

---

## 3.6 — Cross-Subdomain TLS Comparison

**Why:** Real audits consistently find TLS config inconsistencies between production and dev/test environments. seel.com's production API (api.seel.com) had weaker TLS than its own dev/test servers.

**For each discovered subdomain (especially API servers):**
- Compare TLS version support (does prod support TLS 1.3 like dev does?)
- Compare cipher suites (does prod accept CBC ciphers that dev rejects?)
- Compare HSTS presence (CDN subdomains may have HSTS but direct API servers don't)
- Check cert SANs for related domain discovery (seel.com cert revealed `*.kover.ai`)

**Build a comparison table** like the seel.com audit produced — this makes configuration drift obvious at a glance.

---

**Document:** TLS grade, cipher list, certificate details, HSTS completeness, CAA configuration, DNSSEC status. Include cross-subdomain comparison table if multiple subdomains were tested.
