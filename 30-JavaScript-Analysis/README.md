# JavaScript Analysis

> Comprehensive methodology and one‑liner commands for analyzing JavaScript files to extract sensitive information (secrets, endpoints, internal IPs, hidden routes), incorporating 2025–2026 trends (client‑side secret leakage, JavaScript source maps, obfuscation/deobfuscation, WebSocket endpoints) and authoritative references (OWASP Client‑Side Security, PortSwigger Web Security Academy, JS‑beautifier, LinkFinder).

JavaScript files are a treasure trove for bug hunters: they often contain hard‑coded API keys, cloud credentials, internal endpoints, administrative routes, and business logic flaws. Analyzing client‑side JS is a critical step in modern web application security assessments.

## Methodology

### Sources of JavaScript Files

- **Live JS URLs** – extracted from crawling (`*.js` files)
- **Source maps** (`*.js.map`) – contain original source code, variable names, and sometimes secrets
- **Inline scripts** – embedded in HTML (`<script>` tags)
- **Dynamic JS** – loaded via XHR/fetch or generated at runtime
- **Third‑party libraries** – may include vulnerable versions or leak information

### Common Patterns to Hunt

1. **Secrets & Credentials**
   - Cloud keys (AWS, Azure, GCP)
   - API tokens (Google Maps, Stripe, GitHub, Slack, Discord)
   - OAuth client secrets
   - Database connection strings
   - Private keys (RSA, EC, SSH)

2. **Internal Infrastructure**
   - Internal IP addresses (RFC 1918)
   - Hostnames (`internal‑api`, `staging`, `dev`)
   - Network paths (`/admin`, `/debug`, `/api/v1/internal`)

3. **Endpoints & Routes**
   - API endpoints (REST, GraphQL, WebSocket)
   - Hidden administrative interfaces
   - Debug/development endpoints

4. **Business Logic Flaws**
   - Client‑side access control checks
   - Price manipulation variables
   - Input validation bypasses

5. **Configuration & Environment**
   - Feature flags
   - Debug mode toggles
   - Version numbers (may indicate outdated libraries)

## Tool Installation & Setup

### LinkFinder (JavaScript endpoint extractor)

```bash
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
python3 setup.py install
```

### JS‑beautifier (code formatting)

```bash
npm install -g js-beautify
```

### source‑map‑explorer (source map analysis)

```bash
npm install -g source-map-explorer
```

### trufflehog (secret scanning)

```bash
pip3 install trufflehog
```

### nuclei (template‑based scanning)

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### katana (crawler for JS discovery)

```bash
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

## Testing Commands (One‑Liners)

### 1. Extract Live JavaScript Files

```bash
# Filter crawled URLs for .js files, verify they are live
cat crawledurls.txt | grep "\.js" | grep -Ev "\.json|\.jsp" | sort -u | httpx -silent -mc 200,301,302 -threads 200 -o livejslinks.txt
```

### 2. Secret Scanning

#### AWS Keys
```bash
cat livejslinks.txt | xargs -P 20 -I{} sh -c 'curl -sk {} 2>/dev/null | grep -oE "(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}" && echo "Found in: {}"' | tee aws-keys-js.txt
```

#### Google API Keys + Firebase URLs
```bash
cat livejslinks.txt | xargs -P 20 -I{} sh -c 'curl -sk {} 2>/dev/null | grep -oE "(AIza[0-9A-Za-z_-]{35}|[a-z0-9-]+\.firebaseio\.com|[a-z0-9-]+\.firebaseapp\.com)" && echo "[SOURCE] {}"' | tee google-firebase-keys.txt
```

#### Slack Webhooks + Discord Tokens
```bash
cat livejslinks.txt | xargs -P 20 -I{} sh -c 'curl -sk {} 2>/dev/null | grep -oE "(https://hooks\.slack\.com/services/[A-Za-z0-9/]+|[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27})" && echo "[SOURCE] {}"' | tee slack-discord-js.txt
```

#### GitHub Tokens + Private Keys
```bash
cat livejslinks.txt | xargs -P 20 -I{} sh -c 'curl -sk {} 2>/dev/null | grep -oE "(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}|-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----)" && echo "[SOURCE] {}"' | tee github-privkeys-js.txt
```

#### General Secret Scanning with TruffleHog
```bash
cat livejslinks.txt | grep -o 'https://[^ ]*' | sort -u | while read url; do
    echo "Scanning: $url"
    curl -s "$url" | trufflehog stdin --no-verification --no-update
done
```

### 3. Internal IP Address Leakage

```bash
cat livejslinks.txt | xargs -P 20 -I{} sh -c 'curl -sk {} 2>/dev/null | grep -oE "(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})" && echo "[SOURCE] {}"' | sort -u | tee internal-ips-js.txt
```

### 4. Endpoint & Route Extraction

#### S3 Buckets
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9.-]+|s3-[a-zA-Z0-9-]+\.amazonaws\.com/[a-zA-Z0-9.-]+" | sort -u | anew s3-from-js.txt
```

#### Firebase URLs
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "https://[a-zA-Z0-9-]+\.firebaseio\.com|https://[a-zA-Z0-9-]+\.firebase\.com" | sort -u | anew firebase-urls.txt
```

#### All URLs
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "(https?://[^\"\'\`\s\<\>]+)" | sort -u | anew js-urls.txt
```

#### Hidden Admin/Dashboard Routes
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "[\"\'][/][a-zA-Z0-9_/-]*(admin|dashboard|manage|config|settings|internal|private|debug|api/v[0-9])[a-zA-Z0-9_/-]*[\"\']" | tr -d "\"'" | sort -u | anew hidden-routes.txt
```

### 5. Subdomain & Email Extraction

#### Subdomains
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sed 's|https\?://||' | cut -d'/' -f1 | sort -u | anew subdomains-from-js.txt
```

#### Email Addresses
```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | sort -u | anew emails-from-js.txt
```

### 6. Sensitive Keywords Grep

```bash
cat livejslinks.txt | xargs -I@ curl -s @ | grep -iE "(password|passwd|pwd|secret|api_key|apikey|token|auth)" | sort -u
```

### 7. Nuclei Scanning on JS Files

```bash
# Scan for tokens/exposures using nuclei templates
cat livejslinks.txt | httpx -silent -sr -srd js_files/ && nuclei -t exposures/ -target js.txt
# Or directly
cat livejslinks.txt | nuclei -t http/exposures/tokens/ -silent | anew api-keys.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Source Map Analysis

Source maps (`*.js.map`) map minified code back to original source. They can reveal:

- Original variable/function names
- Comments and developer notes
- Full file paths on development machines
- Sometimes secrets that were stripped during minification

**Extraction:**
```bash
# Find source map references in JS files
curl -s https://target.com/app.js | grep -o '//# sourceMappingURL=.*'
# Download and explore source map
curl -s https://target.com/app.js.map | jq .
```

### Deobfuscation & Beautification

- Use `js‑beautify` to reformat minified code for readability
- Tools like `de4js` (online), `javascript‑deobfuscator` (npm) for common obfuscation techniques
- Manual analysis of packed code (e.g., `eval`, `Function`, `\x` escapes)

### WebSocket Endpoint Discovery

- Look for `new WebSocket(` or `ws://`, `wss://` in JS
- WebSocket endpoints often lack authentication and may expose real‑time data

### Client‑Side Storage Inspection

- `localStorage`, `sessionStorage`, `IndexedDB` may contain tokens, user data, or configuration
- Use browser DevTools → Application tab to inspect

### JavaScript Prototype Pollution

- Look for `merge`, `extend`, `assign` functions that may be vulnerable (see [Prototype Pollution](../23‑Prototype‑Pollution/README.md))

### GraphQL Introspection Queries

- GraphQL endpoints may be embedded in JS; try introspection queries to enumerate schema

### API Key Scope Abuse

- Even if API keys are intended for client‑side use, they may have overly permissive scopes (e.g., Google Maps API key with billing enabled)
- Test keys against their respective APIs to determine permissions

### Dynamic Import Analysis

- ES6 dynamic imports (`import()`) can reveal lazy‑loaded modules and routes
- Use browser’s Network tab to monitor module loading

## Detection & Verification

**Indicators of Exposure:**

- Regex matches for secret patterns in JS files
- Internal IPs/hostnames in client‑side code
- Hidden routes or debug endpoints
- Source maps accessible without authentication

**Verification Steps:**

1. Validate secrets (test API keys, tokens for active access)
2. Probe discovered endpoints for functionality and potential vulnerabilities
3. Check if internal IPs are reachable (from external perspective)
4. Assess impact: data leakage, unauthorized access, lateral movement

## Prevention Guidance (Client‑Side Security Best Practices)

1. **Never Store Secrets in Client‑Side Code** – use server‑side proxies, API gateways, or tokenization
2. **Use Environment Variables** for configuration (but remember they are still exposed in client‑side bundles)
3. **Implement Proper Authentication & Authorization** – rely on server‑side checks, not client‑side logic
4. **Minify & Obfuscate** – but assume attackers can deobfuscate; security through obscurity is insufficient
5. **Disable Source Maps in Production** – or restrict access to authenticated users
6. **Regularly Scan Your Own JS** – use secret‑detection tools in CI/CD pipelines
7. **Review Third‑Party Libraries** – keep them updated, monitor for known vulnerabilities
8. **Use Subresource Integrity (SRI)** for external scripts to prevent tampering
9. **Implement Content Security Policy (CSP)** to restrict script sources
10. **Educate Developers** – secure coding training, code reviews, and threat modeling for client‑side code

## References

- **OWASP Client‑Side Security Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Client_Side_Security_Cheat_Sheet.html)
- **PortSwigger Web Security Academy – Client‑side topics** – [PortSwigger](https://portswigger.net/web-security)
- **LinkFinder** – [GitHub Repository](https://github.com/GerbenJavado/LinkFinder)
- **TruffleHog** – [TruffleSecurity](https://trufflesecurity.com)
- **Recent Research (2025–2026)** – JavaScript source map leaks, client‑side storage attacks, API key scope abuse
