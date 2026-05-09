---
description: "Phase 7e: WebSocket & real-time security — unauthenticated WS probing, origin validation, session hijacking"
argument-hint: <url>
allowed-tools: [Bash, WebFetch, Write, Edit, Read]
---

# Phase 7e: WebSocket & Real-Time Security Testing

**Target:** $ARGUMENTS

**Trigger:** When recon (Phase 1) identifies WebSocket or real-time communication — `wss://` URLs in JS bundles, LiveKit/Agora/Twilio/Vonage/Daily SDKs, Socket.io references, or voice AI interfaces that use streaming connections.

**Goal:** Test unauthenticated WebSocket access, origin validation, protocol enumeration, and session security for real-time communication channels.

**Ledger:** `Read` the findings ledger from `audits/{domain}/ledger.md` before starting. After this phase completes, `Edit` the ledger to update Phase 7e status, add confirmed findings, chain candidates, and failed techniques.

---

## 7e.1 — WebSocket Endpoint Discovery

**From Phase 1 JS bundle scan, look for:**
```bash
# Search JS bundles for WebSocket URLs and real-time SDKs
curl -s "https://{target}" | grep -oE '/_next/static/chunks/[^"]+\.js' | sort -u | while read chunk; do
  curl -s "https://{target}${chunk}" | grep -oiE \
    '(wss?://[^"'\''` ]+|socket\.io|sockjs|WebSocket|livekit|agora|twilio|vonage|daily\.co|pusher|ably|centrifugo|SignalR|\.signalr\.|actioncable)'
done

# Check page source directly
curl -s "https://{target}" | grep -oiE '(wss?://[^"'\''` ]+|socket\.io|new WebSocket)'
```

**Probe common WebSocket paths:**
```bash
for path in /ws /wss /socket /socket.io /sockjs /cable /hub /signalr \
            /realtime /stream /live /events /pubsub; do
  # Check if HTTP upgrade is accepted
  code=$(curl -sI -o /dev/null -w "%{http_code}" \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "https://{target}${path}" --max-time 5 2>/dev/null)
  if [ "$code" = "101" ] || [ "$code" = "200" ]; then
    echo "!!! WebSocket upgrade accepted: ${path} -> $code"
  elif [ "$code" != "404" ] && [ "$code" != "000" ]; then
    echo "Responded (not WS): ${path} -> $code"
  fi
done

# Socket.io handshake
curl -s "https://{target}/socket.io/?EIO=4&transport=polling" | head -20
```

---

## 7e.2 — Origin Validation Testing

**Critical test: does the WebSocket accept connections from any origin?**

```bash
# Test with legitimate origin
curl -sI \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: https://{target}" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://{target}/ws" | head -10

# Test with evil origin — should be rejected
curl -sI \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: https://evil.com" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://{target}/ws" | head -10

# Test with null origin (some apps whitelist null)
curl -sI \
  -H "Upgrade: websocket" \
  -H "Connection: Upgrade" \
  -H "Origin: null" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Version: 13" \
  "https://{target}/ws" | head -10
```

**Vulnerable if:** WebSocket upgrade succeeds (101) with `Origin: https://evil.com` — any website can open a cross-origin WebSocket to the target. Combined with missing auth, this enables cross-site WebSocket hijacking (CSWSH).

---

## 7e.3 — Unauthenticated Connection Testing

**Test if WebSocket connections require authentication:**

```bash
# Try connecting without any auth tokens
# Using websocat if available, otherwise curl
if command -v websocat &> /dev/null; then
  # Connect and send a test message
  echo '{"type":"ping"}' | websocat -1 "wss://{target}/ws" 2>&1 | head -20
  echo '{"action":"subscribe","channel":"*"}' | websocat -1 "wss://{target}/ws" 2>&1 | head -20
else
  # Fallback: test upgrade handshake only
  curl -sI \
    -H "Upgrade: websocket" \
    -H "Connection: Upgrade" \
    -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Sec-WebSocket-Version: 13" \
    "wss://{target}/ws" | head -10
fi
```

**For Socket.io specifically:**
```bash
# Socket.io polling transport doesn't need WS — test via HTTP
# Handshake
curl -s "https://{target}/socket.io/?EIO=4&transport=polling" | head -20

# If handshake succeeds, try subscribing to events
SID=$(curl -s "https://{target}/socket.io/?EIO=4&transport=polling" | grep -oE '"sid":"[^"]+"' | cut -d'"' -f4)
if [ -n "$SID" ]; then
  echo "!!! Socket.io session created without auth: sid=$SID"
  # Try to receive events
  curl -s "https://{target}/socket.io/?EIO=4&transport=polling&sid=$SID" | head -20
fi
```

---

## 7e.4 — Protocol & Message Enumeration

**If a connection is established, enumerate what the server accepts:**

```bash
# Common message patterns to probe server capabilities
if command -v websocat &> /dev/null; then
  for msg in \
    '{"type":"ping"}' \
    '{"type":"subscribe","channel":"#"}' \
    '{"action":"list_channels"}' \
    '{"event":"join","room":"*"}' \
    '{"type":"auth","token":""}' \
    '{"method":"listRooms"}' \
    '{"type":"enumerate"}'; do

    echo "$msg" | timeout 5 websocat -1 "wss://{target}/ws" 2>&1 | head -10
  done
fi
```

**What to look for in responses:**
- Channel/room listings — reveals what real-time data streams exist
- User presence info — who else is connected
- Error messages — may leak internal structure, valid message formats
- Auth error format — "invalid token" vs "token required" vs silent disconnect

---

## 7e.5 — LiveKit / Voice Platform Specific Tests

**Trigger:** When LiveKit, Agora, Twilio, or similar real-time voice/video platform is detected.

```bash
# LiveKit API discovery
for lk_host in $(grep -oE 'wss://[^"'\''` ]+livekit[^"'\''` ]*' /tmp/js_scan_results 2>/dev/null); do
  # Strip wss:// to get hostname for HTTP API
  LK_HTTP=$(echo "$lk_host" | sed 's|wss://|https://|')

  # Try LiveKit Twirp API (unauth)
  curl -s "${LK_HTTP}/twirp/livekit.RoomService/ListRooms" \
    -H "Content-Type: application/json" \
    -d '{}' | head -20

  curl -s "${LK_HTTP}/twirp/livekit.RoomService/ListParticipants" \
    -H "Content-Type: application/json" \
    -d '{"room":"*"}' | head -20
done

# Check for exposed room tokens in page source or JS
curl -s "https://{target}" | grep -oiE '(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)'
```

**LiveKit JWT token analysis (if found):**
```bash
# Decode the LiveKit access token
TOKEN="eyJ..."
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || \
echo "$TOKEN" | cut -d'.' -f2 | base64 -D 2>/dev/null | python3 -m json.tool 2>/dev/null

# Look for: room permissions (canPublish, canSubscribe), room name, participant identity
# A token with canSubscribe=true + no room restriction = eavesdrop on any room
```

---

## 7e.6 — WebSocket Session Token Exposure

**Check how auth tokens are passed to WebSocket connections:**

```bash
# Token in URL query parameter (BAD — logged in access logs, referrer headers)
curl -s "https://{target}" | grep -oiE 'wss?://[^"'\''` ]*token=[^"'\''` &]+'
curl -s "https://{target}" | grep -oiE 'wss?://[^"'\''` ]*key=[^"'\''` &]+'
curl -s "https://{target}" | grep -oiE 'wss?://[^"'\''` ]*auth=[^"'\''` &]+'

# Check JS bundles for token-in-URL patterns
curl -s "https://{target}" | grep -oE '/_next/static/chunks/[^"]+\.js' | sort -u | while read chunk; do
  curl -s "https://{target}${chunk}" | grep -oiE '(new WebSocket\([^)]*token|new WebSocket\([^)]*auth|\.connect\([^)]*token)'
done
```

**Risks of token-in-URL:**
- Tokens appear in server access logs
- Tokens leak via Referrer header if user navigates away
- Tokens visible in browser history
- Proxy/CDN logs capture the full URL

---

## Adapting to the Stack

| Real-Time Tech | Focus on | Skip |
|---|---|---|
| Socket.io | Polling transport (no WS needed), namespace enumeration, event subscription | LiveKit-specific |
| LiveKit | Twirp API, room listing, JWT analysis, eavesdrop risk | Socket.io-specific |
| Pusher/Ably | Channel enumeration, public vs private channel auth | Voice-specific |
| SignalR | Hub discovery, method enumeration, negotiate endpoint | Voice-specific |
| Raw WebSocket | Origin validation, unauthenticated access, message fuzzing | Platform-specific |
| ActionCable (Rails) | Channel subscription, turbo stream injection | Voice-specific |

---

**Document:** For each WebSocket endpoint — whether auth is required, origin validation result, protocol/message format, token exposure method, and specific risks for voice/video sessions.
