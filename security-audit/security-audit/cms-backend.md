---
description: "Phase 6: CMS & backend data exposure testing"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 6: CMS & Backend Data Exposure

**Target:** $ARGUMENTS

**Goal:** If a CMS or headless backend was identified, test whether its API allows unauthenticated access.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 6 status, add confirmed findings, chain candidates, and failed techniques.

---

## 6.1 — Sanity CMS

If Sanity project ID and dataset were found:

```bash
curl -s "https://{projectId}.api.sanity.io/v2021-06-07/data/query/{dataset}?query=count(*)"
curl -s "https://{projectId}.api.sanity.io/v2021-06-07/data/query/{dataset}?query=array::unique(*[]._type)"
curl -s "https://{projectId}.api.sanity.io/v2021-06-07/data/query/{dataset}?query=*[_type=='{type}']{...}[0..10]"
curl -s "https://{projectId}.api.sanity.io/v2021-06-07/data/query/{dataset}?query=*[_type=='sanity.fileAsset']{originalFilename,url,mimeType,size}|order(_createdAt desc)[0..20]"

# Test write access (should fail)
curl -s -X POST "https://{projectId}.api.sanity.io/v2021-06-07/data/mutate/{dataset}" \
  -H "Content-Type: application/json" \
  -d '{"mutations":[{"create":{"_type":"test","title":"security-audit-probe"}}]}'
```

---

## 6.2 — Contentful

```bash
curl -s "https://cdn.contentful.com/spaces/{spaceId}/environments/master/entries?access_token={token}"
```

---

## 6.3 — Strapi / WordPress REST API

```bash
# Strapi
curl -s "https://{target}/api/users"
curl -s "https://{target}/api/content-types"

# WordPress
curl -s "https://{target}/wp-json/wp/v2/users"
curl -s "https://{target}/wp-json/wp/v2/posts?per_page=100"
curl -s "https://{target}/wp-json/wp/v2/pages?per_page=100"
```

---

## 6.4 — GraphQL introspection

```bash
curl -s -X POST "https://{target}/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'
```

---

## 6.5 — Cloud storage buckets

```bash
# S3
curl -sI "https://{bucket-name}.s3.amazonaws.com/"

# GCS
curl -sI "https://storage.googleapis.com/{bucket-name}/"

# Azure
curl -sI "https://{account}.blob.core.windows.net/{container}?restype=container&comp=list"

# Vercel Blob Storage
curl -sI "https://{store-id}.public.blob.vercel-storage.com/"
```

**Vulnerable if:** Returns 200 with directory listing.

**For Vercel Blob Storage:** Root returning 400 = listing disabled (good). Try enumerating filenames based on discovered patterns.

---

## 6.5b — Supabase Open Database Testing

**Trigger:** When recon discovers Supabase URL and publishable anon key in JS bundles — pattern: `{project}.supabase.co` + `eyJ...` (JWT anon key).

**What to test (using Supabase REST API with anon key):**
- **Table access:** Try common table names (`users`, `profiles`, `orders`, `products`, `organizations`, `projects`, `tasks`). Test READ, then INSERT/UPDATE/DELETE.
- **PII exposure:** If users table is readable, check for emails, names, phones, hashed passwords
- **Auth endpoints:** Test Supabase auth API (`/auth/v1/signup`, `/auth/v1/token?grant_type=password`)
- **RLS bypass:** Test if Row Level Security is enforced — can anon key read all rows, or only own?
- **Write access:** Test UPDATE/DELETE on discovered tables — this was CONFIRMED on gilabs.xyz (204 responses)

**Origin:** gilabs.xyz audit discovered Supabase URL + key in JS → full READ+WRITE to users table with PII of 8 employees. CRITICAL finding.

```bash
# Basic table probe with anon key
curl -s "https://{project}.supabase.co/rest/v1/{table}?select=*&limit=5" \
  -H "apikey: {anon_key}" -H "Authorization: Bearer {anon_key}"
```

---

## 6.5c — Cloud Bucket CORS Testing

**Why:** Even if a bucket is publicly listable, CORS determines whether a malicious website can exfiltrate the data cross-origin via JavaScript. Wildcard CORS on a public bucket = drive-by data exfiltration.

**For each discovered bucket (S3/GCS/Azure):**
```bash
curl -sI "https://{bucket-url}/" -H "Origin: https://evil.com" | grep -i "access-control"
```

**CRITICAL if:** `Access-Control-Allow-Origin: *` + bucket is listable = any website can enumerate and download all contents via fetch(). Found in partytime.gg audit (44K files / 13.3 GB exfiltrable cross-origin).

---

## 6.6 — Firebase Hosting & Auth Exploitation

**Trigger:** When recon discovers Firebase project IDs — via CSP headers (`{project}.firebaseapp.com`), JS bundle scan (`firebase.initializeApp({...})`), or path enumeration (`/__firebase/init.json`).

### Step 1: Extract Firebase config

```bash
# Firebase Hosting auto-serves config at a well-known path
curl -s "https://{project}.firebaseapp.com/__/firebase/init.js"
```

**This file exposes:**
- `apiKey` — Firebase API key (needed for all Identity Toolkit calls)
- `projectId` — GCP project identifier
- `authDomain` — authentication domain
- `databaseURL` — Realtime Database endpoint
- `storageBucket` — Cloud Storage bucket name
- `messagingSenderId` — FCM sender ID
- `appId` — Firebase app identifier

### Step 2: Check for hosted application source

```bash
# If Firebase Hosting returns 200, check for exposed JS source
curl -s "https://{project}.firebaseapp.com/" | grep -oE 'src="[^"]+"'

# Download each JS file and scan for API endpoints, secrets
curl -s "https://{project}.firebaseapp.com/js/config.js"
curl -s "https://{project}.firebaseapp.com/js/app.js"
```

**Look for:** API base URLs, Firestore collection names, auth domain restrictions (client-side-only auth checks that the server doesn't enforce).

### Step 3: Test Firebase Auth open registration

```bash
# Test anonymous auth
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apiKey}" \
  -H "Content-Type: application/json" \
  -d '{"returnSecureToken":true}'

# Test email/password signup (CRITICAL if succeeds)
curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={apiKey}" \
  -H "Content-Type: application/json" \
  -d '{"email":"secaudit-test@test.com","password":"AuditTest123!","returnSecureToken":true}'
```

**Vulnerable if:** Either returns a valid `idToken`. This means anyone can create accounts on the Firebase project.

**If account creation succeeds:**
1. Test Firestore access with the token: `curl -s "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/{collection}?pageSize=3" -H "Authorization: Bearer {idToken}"`
2. Test Realtime Database: `curl -s "https://{project}.firebaseio.com/.json?auth={idToken}"`
3. **Delete the test account:** `curl -s -X POST "https://identitytoolkit.googleapis.com/v1/accounts:delete?key={apiKey}" -H "Content-Type: application/json" -d '{"idToken":"{idToken}"}'`

### Step 4: Test Firestore/RTDB without auth

```bash
# Firestore REST API (unauthenticated)
curl -s "https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/" | head -30

# Realtime Database (unauthenticated)
curl -s "https://{project}.firebaseio.com/.json" | head -30
```

**Impact:** Open Firebase registration on dev projects is high-risk because:
- Dev Firestore security rules are often permissive (common pattern: `allow read, write: if request.auth != null`)
- A registered user satisfies `request.auth != null`, granting full database access
- Dev projects may share data with production or contain production snapshots

**Origin:** Discovered during rezi.ai audit where the dev Firebase project (`rezi-develop`) had email/password signup open, hosting an unreleased "Deep Talent Search" product with full source code exposed. Firestore rules properly blocked access, but the open registration remained a persistent escalation vector.

### Step 5: Deep Firestore enumeration (from yummy-future audit)

**If Firestore is publicly readable, go deeper:**
- **Enumerate common collections:** `users`, `orders`, `products`, `offers`, `customers`, `payments`, `sessions`, `settings`, `admins`, `config`
- **Check for PII in users collection:** names, emails, phones, Stripe customer IDs, payment info
- **Check pagination:** First page may show 20 records — use `pageToken` or `startAfter` to count total records. yummy-future had 3,624+ users.
- **Test Firebase Storage bucket:** `https://firebasestorage.googleapis.com/v0/b/{project}.appspot.com/o` — check if publicly listable. yummy-future had a full 2.6GB Firestore database export downloadable.
- **Email enumeration:** `POST https://identitytoolkit.googleapis.com/v1/accounts:createAuthUri?key={apiKey}` with `{"identifier":"test@test.com","continueUri":"https://example.com"}` — reveals if email is registered
- **Password reset enumeration:** `POST .../accounts:sendOobCode?key={apiKey}` with `{"requestType":"PASSWORD_RESET","email":"test@test.com"}` — returns `EMAIL_NOT_FOUND` for unregistered emails
- **Check for cross-brand contamination:** Stripe IDs in Firestore may reveal multiple brands sharing one backend (yummy-future had "yummy_future" + "insomnia_water")

---

---

## 6.7 — WordPress Deep Scanning (WPScan)

**Trigger:** When WordPress is identified in recon.

```bash
# WPScan — comprehensive WordPress vulnerability scanner
if command -v wpscan &> /dev/null; then
  wpscan --url https://{target} --enumerate vp,vt,u,dbe \
    --plugins-detection aggressive \
    --random-user-agent \
    --no-banner 2>&1 | head -200
  # vp = vulnerable plugins, vt = vulnerable themes, u = users, dbe = DB exports
fi

# Manual WordPress enumeration (if WPScan not installed)
# Plugin enumeration — check top vulnerable plugins
for plugin in contact-form-7 elementor woocommerce yoast-seo akismet \
             jetpack wordfence wpforms all-in-one-seo-pack updraftplus \
             really-simple-ssl redirection duplicate-post advanced-custom-fields \
             wp-mail-smtp google-analytics-for-wordpress google-sitemap-generator \
             tinymce-advanced classic-editor wp-super-cache w3-total-cache \
             regenerate-thumbnails; do
  readme=$(curl -s "https://{target}/wp-content/plugins/${plugin}/readme.txt" 2>/dev/null)
  if [ -n "$readme" ] && echo "$readme" | grep -qi "stable tag"; then
    version=$(echo "$readme" | grep -i "stable tag:" | head -1 | awk '{print $NF}')
    echo "FOUND: $plugin v$version"
  fi
done

# Theme enumeration
for theme in twentytwentyfour twentytwentythree twentytwentytwo astra oceanwp \
             generatepress flavor flavor flavor flavor flavor flavor flavor flavor flavor flavor flavor flavour flavour flavour flavour flavour; do
  style_css=$(curl -sI "https://{target}/wp-content/themes/${theme}/style.css" 2>/dev/null | head -1)
  if echo "$style_css" | grep -q "200"; then
    echo "FOUND theme: $theme"
  fi
done
```

**What WPScan/manual enumeration reveals:**
- Plugins with known CVEs (check against WPVulnDB)
- Theme vulnerabilities
- User accounts (username enumeration via REST API)
- WordPress core version (check against known CVEs)
- XML-RPC enabled (brute force vector)

---

## 6.8 — Cloud Bucket Brute Forcing

**Why:** Many buckets use predictable naming based on company/product names. Our Phase 6.5 only checks buckets found in source code — this step discovers buckets we'd never find by reading HTML.

```bash
# Generate bucket name candidates from target intelligence
COMPANY=$(echo "{target}" | sed 's/\..*//')  # e.g., "acme" from "acme.com"

# Common bucket naming patterns
for name in \
  "$COMPANY" "${COMPANY}-assets" "${COMPANY}-static" "${COMPANY}-media" \
  "${COMPANY}-uploads" "${COMPANY}-backup" "${COMPANY}-backups" \
  "${COMPANY}-data" "${COMPANY}-staging" "${COMPANY}-dev" \
  "${COMPANY}-prod" "${COMPANY}-production" "${COMPANY}-public" \
  "${COMPANY}-private" "${COMPANY}-internal" "${COMPANY}-cdn" \
  "${COMPANY}-images" "${COMPANY}-files" "${COMPANY}-docs" \
  "${COMPANY}-logs" "${COMPANY}-db" "${COMPANY}-database" \
  "${COMPANY}-web" "${COMPANY}-site" "${COMPANY}-app"; do

  # Check S3
  s3_code=$(curl -sI -o /dev/null -w "%{http_code}" "https://${name}.s3.amazonaws.com/" --max-time 3 2>/dev/null)
  if [ "$s3_code" = "200" ]; then
    echo "!!! OPEN S3 BUCKET: ${name}.s3.amazonaws.com (listing enabled)"
  elif [ "$s3_code" = "403" ]; then
    echo "S3 bucket exists (access denied): ${name}"
  fi

  # Check GCS
  gcs_code=$(curl -sI -o /dev/null -w "%{http_code}" "https://storage.googleapis.com/${name}/" --max-time 3 2>/dev/null)
  if [ "$gcs_code" = "200" ]; then
    echo "!!! OPEN GCS BUCKET: storage.googleapis.com/${name} (listing enabled)"
  elif [ "$gcs_code" = "403" ]; then
    echo "GCS bucket exists (access denied): ${name}"
  fi
done
```

**If an open bucket is found:**
```bash
# List contents (S3)
curl -s "https://{bucket}.s3.amazonaws.com/" | head -100

# List contents (GCS)
curl -s "https://storage.googleapis.com/storage/v1/b/{bucket}/o?maxResults=50"

# Check for sensitive files
for file in .env backup.sql database.sql config.json credentials.json; do
  curl -sI "https://{bucket}.s3.amazonaws.com/${file}" --max-time 3 | head -1
done
```

**Impact:** Open bucket with listing = full data exposure. Even a 403 (exists but denied) confirms the bucket name, enabling targeted access policy attacks.

---

**Document:** For each CMS/backend — unauthenticated reads, document types, total count, write access blocked, sensitive data samples. For Firebase — auth registration status, Firestore/RTDB access with and without auth. For WordPress — plugin/theme inventory with versions and known CVEs. For cloud buckets — discovered buckets, access level, and contents if accessible.
