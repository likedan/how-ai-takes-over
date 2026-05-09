---
description: "Phase 4: Email security assessment (SPF/DKIM/DMARC) for a domain"
argument-hint: <domain>
allowed-tools: [Bash, Write, Edit, Read]
---

# Phase 4: Email Security Assessment

**Target domain:** $ARGUMENTS

**Goal:** Comprehensively assess email authentication controls. For B2B companies especially, email is the primary attack vector — spoofed invoices, impersonated executives, and phishing campaigns cause direct financial damage.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 4 status, add confirmed findings, chain candidates, and failed techniques.

---

## 4.1 — SPF (Sender Policy Framework)

```bash
dig +short {target} TXT | grep -i spf
```

**Check for:**
- SPF record exists at all
- Authorized senders match the mail infrastructure (e.g., `include:spf.protection.outlook.com` for M365, `include:_spf.google.com` for Google Workspace)
- Enforcement: `~all` (softfail) vs `-all` (hardfail — stronger)
- Not using `+all` (permits everyone — effectively no protection)

**Missing = CRITICAL:** Any mail server can send email claiming to be from `@{target}`.

---

## 4.2 — DKIM (DomainKeys Identified Mail)

Check DKIM selectors — both TXT and CNAME records (some providers use CNAME delegation):

```bash
# Tier 1: High-probability selectors (always check these)
for sel in default google selector1 selector2 k1 k2 s1 s2 dkim mail mandrill mte1 mte2; do
  txt=$(dig +short ${sel}._domainkey.{target} TXT 2>/dev/null)
  cname=$(dig +short ${sel}._domainkey.{target} CNAME 2>/dev/null)
  [ -n "$txt" ] && echo "DKIM TXT: ${sel} -> $txt"
  [ -n "$cname" ] && echo "DKIM CNAME: ${sel} -> $cname"
done

# Tier 2: ESP-specific selectors (check based on SPF includes or known integrations)
for sel in ses ses1 ses2 ses3 amazonses postmark mailgun sendgrid sparkpost brevo \
           zoho protonmail resend cm turbo1 turbo2 sig1 sig2 pm mx1 mx2 m1 \
           mailer everlytic cmail email pic bounces firebase1 hubspot; do
  txt=$(dig +short ${sel}._domainkey.{target} TXT 2>/dev/null)
  cname=$(dig +short ${sel}._domainkey.{target} CNAME 2>/dev/null)
  [ -n "$txt" ] && echo "DKIM TXT: ${sel} -> $txt"
  [ -n "$cname" ] && echo "DKIM CNAME: ${sel} -> $cname"
done
```

**Common selectors by provider:**
- Microsoft 365: `selector1`, `selector2`
- Google Workspace: `google`
- Mailchimp/Mandrill: `mandrill`, `k1`, `mte1`, `mte2` (mte* are CNAME to dkim*.mandrillapp.com)
- SendGrid: `s1`, `s2`, `sendgrid`
- Amazon SES: `ses`, `ses1`, `ses2`, `ses3`, `amazonses`
- Postmark: `postmark`, `pm`
- Mailgun: `mailgun`, `mailer`
- Brevo (Sendinblue): `brevo`, `mail`
- SparkPost: `sparkpost`
- Campaign Monitor: `cm`, `cmail`
- Firebase/GCP transactional: `firebase1`
- HubSpot: `hubspot`

**Key size assessment:** If DKIM is found, check the key size:
- `MIIBIjAN...` prefix = 2048-bit RSA (good)
- `MIGfMA0...` prefix = 1024-bit RSA (weak — below NIST 2048-bit minimum)
- Note which selectors use which key size

**CNAME delegation:** Some providers (especially Mandrill, SendGrid) use CNAME records pointing to their own DKIM infrastructure (e.g., `mte1._domainkey → dkim1.mandrillapp.com`). This is valid and allows the provider to rotate keys without DNS changes.

**Missing = CRITICAL:** Emails cannot be cryptographically verified as authentic.

---

## 4.3 — DMARC (Domain-based Message Authentication)

```bash
dig +short _dmarc.{target} TXT
```

**Evaluate the policy:**

| Policy | Meaning | Grade |
|---|---|---|
| `p=reject` | Failed auth → email rejected | A (strong) |
| `p=quarantine` | Failed auth → sent to spam | B (moderate) |
| `p=none` | Failed auth → delivered anyway | F (decorative) |
| No DMARC record | No policy at all | F |

**Parse ALL DMARC tags — each one matters:**

| Tag | What to check | Finding if weak |
|---|---|---|
| `p=` | Policy: reject > quarantine > none | `p=none` = no enforcement (Grade F) |
| `sp=` | Subdomain policy (inherits `p=` if absent) | `sp=none` = subdomains completely unprotected — attacker spoofs `anything@sub.{target}` |
| `pct=` | Percentage subject to policy (default 100) | `pct=90` = 10% of spoofed emails bypass policy entirely |
| `adkim=` | DKIM alignment: `s` (strict) or `r` (relaxed, default) | `r` allows subdomain DKIM to pass for parent domain |
| `aspf=` | SPF alignment: `s` (strict) or `r` (relaxed, default) | `r` allows envelope domain mismatch |
| `rua=` | Aggregate report destination | Missing = zero visibility into spoofing attempts |
| `ruf=` | Forensic report destination | Optional but valuable for incident response |

**Subdomain policy is critical:** If `sp=` is missing, subdomains inherit `p=`. If `sp=none` while `p=quarantine`, subdomains are wide open — attacker can spoof `orders@shipping.{target}`, `support@help.{target}`, etc. This was a real finding in fusepack.com (sp=none with pct=90).

---

## 4.4 — Mail Infrastructure Context

Cross-reference:
- MX records → identify email provider (Proofpoint, Mimecast, Google, M365)
- TXT records → Microsoft 365 tenant IDs (`*.onmicrosoft.com`), Google Workspace verification
- These identifiers enable targeted phishing — knowing the exact M365 tenant allows crafting convincing fake login pages

---

## 4.5 — Combined Assessment

Rate the overall email security posture:

| Control | Status | Grade |
|---|---|---|
| SPF | Present/Missing | A-F |
| DKIM | Present/Missing | A-F |
| DMARC | Policy level | A-F |
| Inbound filtering | Provider | — |

**All three (SPF + DKIM + DMARC enforcement) must be present for effective email security.** Missing any one leaves the domain vulnerable to spoofing.

---

## 4.6 — Advanced Email Controls (MTA-STS, TLS-RPT, BIMI, DANE)

These are defense-in-depth controls. Their absence is Low/Informational but their presence indicates maturity.

```bash
# MTA-STS — prevents TLS downgrade on inbound SMTP
dig +short _mta-sts.{target} TXT
curl -s "https://mta-sts.{target}/.well-known/mta-sts.txt" 2>/dev/null | head -10

# TLS-RPT — SMTP TLS failure reporting
dig +short _smtp._tls.{target} TXT

# BIMI — brand logo in email clients (requires DMARC p=quarantine or p=reject)
dig +short default._bimi.{target} TXT

# DANE/TLSA — certificate pinning for SMTP (requires DNSSEC)
dig +short _25._tcp.{target} TLSA
```

| Control | Missing Impact | Prerequisite |
|---|---|---|
| MTA-STS | No TLS enforcement for inbound mail — MITM can strip encryption | None |
| TLS-RPT | No visibility into SMTP TLS failures | None |
| BIMI | No brand logo in email clients | DMARC p=quarantine or p=reject |
| DANE/TLSA | No SMTP certificate pinning | DNSSEC enabled |

---

## 4.7 — Multi-Domain Email Assessment

**CRITICAL:** Check email security on ALL related domains discovered in earlier phases — not just the primary target. Real audits consistently find weaker email security on secondary/platform domains.

Common patterns:
- Primary domain has DMARC p=quarantine but related domain has p=none (tofulab.ai vs platonagent.ai)
- Brand domain has zero DNS records — fully spoofable (prowlsecurity.ai)
- Parent/sibling domain has no DMARC at all (bananas.im for partytime.gg)

```bash
# For each related domain from Phase 0/1 (redirects, canonical URLs, cert SANs, JS bundle refs):
for domain in {related1} {related2}; do
  echo "=== $domain ==="
  dig +short $domain TXT | grep -i spf
  dig +short _dmarc.$domain TXT
  dig +short google._domainkey.$domain TXT
  dig +short selector1._domainkey.$domain TXT
  dig +short $domain MX
done
```

**Domains with zero DNS records** (SOA falls back to TLD) are the worst — no SPF means SPF defaults to neutral, no DMARC means no policy. Anyone can send as @that-domain with zero resistance.

---

## 4.9 — Typosquatting / Lookalike Domain Detection (dnstwist)

**Why:** Even with perfect email security, attackers can register lookalike domains (e.g., `acme-inc.com` vs `acme1nc.com`) and send emails that appear to come from the target. This is a defensive finding — it warns the client about external threats they may not know about.

```bash
if command -v dnstwist &> /dev/null; then
  # Check for registered lookalike domains
  dnstwist --registered {target} 2>&1 | head -50
fi

# Manual check for common typosquatting patterns
DOMAIN=$(echo "{target}" | sed 's/\..*//')
TLD=$(echo "{target}" | sed 's/[^.]*\.//')

for variant in \
  "${DOMAIN}s.${TLD}" \
  "${DOMAIN}1.${TLD}" \
  "${DOMAIN}-.${TLD}" \
  "$(echo $DOMAIN | sed 's/\(.\)/\1\1/' | head -c $((${#DOMAIN}+1))).${TLD}" \
  "${DOMAIN}.co" \
  "${DOMAIN}.net" \
  "${DOMAIN}.org" \
  "${DOMAIN}.io"; do
  ip=$(dig +short "$variant" A 2>/dev/null | head -1)
  if [ -n "$ip" ]; then
    echo "!!! REGISTERED LOOKALIKE: $variant -> $ip"
  fi
done
```

**What dnstwist generates:**
- **Homoglyph** — character substitution (`rn` → `m`, `l` → `1`)
- **Bitsquatting** — single bit-flip domains
- **Transposition** — adjacent character swap (`acme` → `acme`)
- **Insertion/Omission** — extra/missing characters
- **TLD swap** — `.com` → `.co`, `.net`, `.org`

**Impact:** Registered lookalike domains are a concrete phishing threat. Combined with weak DMARC on the real domain, attackers can impersonate the company with high credibility.

---

## 4.10 — Email Spoofing Exploitation (Proof-of-Concept)

**When to run:** If DMARC is `p=none` or missing, AND SPF uses `~all` or is missing — attempt to confirm spoofing is actually deliverable, not just theoretically possible.

**Why:** DNS records showing weak email auth are a finding, but actually delivering a spoofed email is proof. Many mail providers (Gmail, iCloud) may silently drop spoofed emails despite `p=none` if the sending IP is on blocklists. Confirmed delivery elevates the finding from theoretical to proven.

### Method 1: Browser-based (no server needed)

1. Navigate to **emkei.cz** (free online SMTP sender)
2. Fill the form:
   - **From Name:** `{target company name}` (e.g., "Pantheon Design Security")
   - **From E-mail:** `spoofed-address@{target}` (e.g., "security@pantheondesign.com")
   - **To:** test recipient email address
   - **Subject:** `[SECURITY TEST] Email Spoofing Verification - {target}`
   - **Body:** Clearly label as a security audit test, explain what the email proves
3. Solve the hCaptcha and click Send
4. Check recipient inbox AND spam/junk folder

**Recipient selection tips:**
- Gmail and iCloud have aggressive filtering — spoofed emails may be silently dropped even with `p=none`
- Custom domain email (e.g., company Google Workspace, self-hosted) is more likely to deliver
- Try multiple recipients if the first doesn't arrive

### Method 2: CLI with swaks (requires port 25 access)

```bash
# Install swaks if needed
brew install swaks  # macOS
apt install swaks   # Debian/Ubuntu

# Send spoofed email directly to recipient's MX
swaks --to recipient@example.com \
      --from "ceo@{target}" \
      --h-From "CEO Name <ceo@{target}>" \
      --h-Subject "[SECURITY TEST] Email Spoofing - {target}" \
      --body "This is a security audit test. This email was NOT sent by {target}." \
      --server $(dig +short MX $(echo recipient@example.com | cut -d@ -f2) | head -1 | awk '{print $2}')
```

**Note:** Port 25 is blocked on most residential/consumer ISPs. This method requires a VPS or network with outbound port 25 open.

### Method 3: Python smtplib (requires port 25 access)

```python
import smtplib, socket
from email.mime.text import MIMEText

msg = MIMEText("Security audit test - spoofing verification")
msg["From"] = f"CEO Name <ceo@{target}>"
msg["To"] = "recipient@example.com"
msg["Subject"] = "[SECURITY TEST] Email Spoofing - {target}"

# Connect directly to recipient's MX server
mx_host = "mx1.recipient-domain.com"  # from: dig MX recipient-domain.com
smtp = smtplib.SMTP(mx_host, 25, timeout=10)
smtp.ehlo(socket.getfqdn())
smtp.starttls()
smtp.ehlo(socket.getfqdn())
smtp.mail(f"ceo@{target}")
smtp.rcpt("recipient@example.com")
smtp.data(msg.as_string())
smtp.quit()
```

### Documenting Results

Record in the audit report:
- **Delivered to inbox:** CRITICAL — full spoofing confirmed, no user interaction needed to be deceived
- **Delivered to spam/junk:** HIGH — spoofing works but mail provider flagged it; still dangerous as users check spam
- **Silently dropped:** Note that the mail provider blocked it despite `p=none`; the DNS misconfiguration is still a finding (other recipients/providers may deliver it)
- **Screenshot** the received email as proof if delivered

---

**Document:** Complete email security assessment with specific DNS records found, what's missing, typosquatting domains detected, spoofing PoC results, and the business impact.
