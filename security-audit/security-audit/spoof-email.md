---
description: "Send a spoofed email to demonstrate DMARC/SPF vulnerability — requires Chrome browser"
argument-hint: "<from@domain> <to@recipient> [subject]"
allowed-tools: [Bash, Read, WebFetch, mcp__claude-in-chrome__tabs_context_mcp, mcp__claude-in-chrome__tabs_create_mcp, mcp__claude-in-chrome__navigate, mcp__claude-in-chrome__read_page, mcp__claude-in-chrome__form_input, mcp__claude-in-chrome__computer, mcp__claude-in-chrome__switch_browser]
---

# Email Spoofing Proof of Concept

**Arguments:** $ARGUMENTS

Parse the arguments:
- First argument: the spoofed From address (e.g., `security@target.com`)
- Second argument: the recipient address (e.g., `user@example.com`)
- Third argument (optional): custom subject line. Default: `[SECURITY AUDIT] DMARC Spoofing Proof - {domain}`

## Prerequisites Check

Before sending, verify the target domain actually has weak DMARC:

```bash
# Check DMARC
dig +short _dmarc.{domain} TXT
# Check SPF
dig +short {domain} TXT | grep spf
```

If DMARC `p=reject` or `p=quarantine`, warn the user that the email will likely be rejected/quarantined and ask if they still want to proceed as a test.

## Send via emkei.cz (browser-based)

This skill uses Chrome browser automation to send via emkei.cz, a free anonymous mailer commonly used in authorized penetration tests.

### Step 1: Get Chrome context

Call `mcp__claude-in-chrome__tabs_context_mcp` with `createIfEmpty: true`. If the browser extension isn't connected, call `mcp__claude-in-chrome__switch_browser` first.

### Step 2: Create tab and navigate

1. Create a new tab via `mcp__claude-in-chrome__tabs_create_mcp`
2. Navigate to `https://emkei.cz/`

### Step 3: Fill the form

Use `mcp__claude-in-chrome__form_input` to fill:

| Field | ref | Value |
|---|---|---|
| From Name | ref_1 | `{Domain} Security Team` (derive from the spoofed domain) |
| From E-mail | ref_2 | The spoofed From address |
| To | ref_3 | The recipient address |
| Subject | ref_4 | The subject line |

For the body text (ref_11), use this template:

```
SECURITY AUDIT — EMAIL SPOOFING PROOF OF CONCEPT

This email was sent as part of an authorized security audit of {domain}.

This email was NOT sent from {domain}'s servers. It was sent by spoofing
the From address to "{from_address}" — and it reached your inbox because
{domain}'s DMARC policy is set to p={current_dmarc_policy} (no enforcement).

WHAT THIS PROVES:
- Anyone can send email pretending to be @{domain}
- The email passes filters because DMARC does not enforce rejection
- This enables phishing, invoice fraud, and social engineering attacks

HOW TO FIX:
1. Change DMARC from p={current_policy} to p=reject
2. Change SPF from ~all to -all (if applicable)
3. Ensure DKIM is configured for ALL outbound mail services

— Prowl Security (prowlsecurity.ai) | Email Spoofing PoC
```

### Step 4: Handle CAPTCHA

After filling all fields, take a screenshot. If there is an hCaptcha or reCAPTCHA:
- Check if it's already solved (green checkmark)
- If not solved, tell the user: "Please solve the CAPTCHA in the browser, then tell me to continue."
- Wait for the user to confirm before proceeding

### Step 5: Submit

1. Take a screenshot to verify all fields are correct
2. Click the Send button (ref_13)
3. Wait 2 seconds
4. Take a screenshot to capture the result
5. Look for "E-mail sent successfully" confirmation

### Step 6: Report

Tell the user:
- Whether the email was sent successfully
- Remind them to check inbox AND spam folder
- Explain what the email landing in inbox vs spam proves:
  - **Inbox:** DMARC provides zero protection — critical finding
  - **Spam:** Other anti-spam heuristics caught it, but DMARC itself didn't reject — still a finding, just lower severity
  - **Bounced/rejected:** DMARC or the receiving server's IP reputation blocked it — note this in the report

### Troubleshooting

If emkei.cz is down or blocked:
1. Try alternative: `https://anonymousemail.me/`
2. Try alternative: `https://www.guerrillamail.com/compose`
3. As last resort, suggest the user install swaks: `brew install swaks` and use:
   ```
   swaks --to {recipient} --from {from} --server aspmx.l.google.com --header "Subject: {subject}" --body "{body}"
   ```

## Important Notes

- This skill is for **authorized security testing only**
- Only use against domains you own or have written authorization to test
- The spoofed email clearly identifies itself as a security audit proof
- Never use this for actual phishing or social engineering attacks
