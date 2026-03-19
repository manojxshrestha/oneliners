# Directory & File Enumeration

> Comprehensive guide for **Directory & File Enumeration** during web pentests, bug bounty hunting, and security assessments.  
> Covers modern tools (ffuf, gobuster, feroxbuster, wfuzz), advanced techniques (recursive scanning, extension fuzzing, response filtering), and 2025–2026 trends (rate‑limit evasion, obfuscated paths, cloud storage enumeration, API endpoint discovery).

Directory and file enumeration is the process of discovering hidden resources (directories, files, endpoints) on web servers. It’s a fundamental reconnaissance step that often exposes sensitive files, admin panels, backup archives, and vulnerable endpoints.

## Methodology (Based on OWASP WSTG & Industry Best Practices)

**1. Target mapping**  
- Identify target scope (domain, subdomains, IP ranges)  
- Determine technology stack (server, framework, CMS) to tailor wordlists  
- Check robots.txt, sitemap.xml, source code for hints

**2. Tool selection**  
- **Speed & simplicity:** `ffuf`, `gobuster`  
- **Recursive depth:** `feroxbuster`  
- **Advanced filtering:** `wfuzz`  
- **Integrated suites:** Burp Suite Intruder, OWASP ZAP

**3. Wordlist choice**  
- **Common directories:** `common.txt`, `directory‑list‑2.3‑medium.txt`  
- **Technology‑specific:** `wordpress.txt`, `apache.txt`, `nginx.txt`  
- **Custom wordlists:** generated from target content, GitHub repos, API docs

**4. Scanning techniques**  
- **Basic directory brute‑forcing**  
- **Recursive scanning** (be careful with depth)  
- **Extension fuzzing** (.php, .json, .bak, .tar.gz)  
- **Parameter fuzzing** (GET/POST)  
- **Response filtering** by size, status code, lines, words

**5. Advanced bypasses & 2025–2026 trends**  
- Rate‑limit evasion (slow scanning, rotating user‑agents, IP rotation)  
- Obfuscated paths (URL encoding, case variation, adding junk parameters)  
- Cloud storage enumeration (AWS S3, Azure Blobs, GCP buckets)  
- API endpoint discovery (REST, GraphQL)  
- JavaScript‑based endpoint extraction (LinkFinder, JS‑Scan)

## Tool Installation & Setup

```bash
# ffuf – fast web fuzzer
go install github.com/ffuf/ffuf@latest

# gobuster – directory/subdomain brute‑forcer
go install github.com/OJ/gobuster/v3@latest

# feroxbuster – recursive content discovery
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash

# wfuzz – advanced fuzzing with filters
sudo apt install wfuzz -y

# SecLists – comprehensive wordlist collection
git clone https://github.com/danielmiessler/SecLists.git /home/pwn/wordlists/SecLists
```

## Detection & Enumeration Commands

### Basic Directory Discovery
```bash
# ffuf (fast, recommended)
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 50 -c -fs 0

# gobuster
gobuster dir -u https://target.com -w /home/pwn/wordlists/common.txt -t 20 -b 301,302,404,403

# feroxbuster (recursive, auto‑filtering)
feroxbuster -u https://target.com -w /home/pwn/wordlists/common.txt -t 10 -C 404,403 -x php,html,json,txt

# wfuzz (legacy but powerful)
wfuzz -c -z file,/home/pwn/wordlists/raft-medium-directories.txt --hc 404,403 "https://target.com/FUZZ/"
```

### File Discovery with Extensions
```bash
# ffuf with extension flag
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/raft-medium-files.txt -t 50 -c -e .php,.bak,.tar.gz,.json -fs 0

# gobuster with extensions
gobuster dir -u https://target.com -w /home/pwn/wordlists/common.txt -x php,txt,html -t 20 -b 404,403
```

### Recursive Scanning (Careful!)
```bash
# feroxbuster (built‑in recursion)
feroxbuster -u https://target.com -w /home/pwn/wordlists/common.txt -t 10 -C 404,403 -r

# ffuf with recursion (requires separate script)
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 50 -c -recursion -recursion-depth 2 -fs 0
```

### Parameter Discovery
```bash
# Fuzz GET parameters
wfuzz -c -z file,/home/pwn/wordlists/Web-Content/burp-parameter-names.txt --hc 404,301 "https://target.com/index.php?FUZZ=data"

# Fuzz POST parameters
wfuzz -c -z file,/home/pwn/wordlists/Web-Content/burp-parameter-names.txt --hc 404 -d "FUZZ=test" "https://target.com/login.php"
```

### Subdomain Discovery
```bash
# gobuster DNS mode
gobuster dns -d target.com -w /home/pwn/wordlists/subdomains-top1million-110000.txt -t 30

# ffuf vhost mode
ffuf -u https://target.com -H "Host: FUZZ.target.com" -w /home/pwn/wordlists/subdomains.txt -t 50 -c -fs 0
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

### Response Size Filtering
```bash
# Find baseline size
curl -s "https://target.com/verify?token=test" -w "\nSize: %{size_download}" | tail -1

# Hide baseline size (--hh) in wfuzz
wfuzz -c -z file,/home/pwn/wordlists/common.txt --hh 30741 "https://verified.clearme.com/verify?token=FUZZ"

# Show only responses with different size (--sh)
wfuzz -c -z file,/home/pwn/wordlists/common.txt --sh 0-1000 "https://target.com/endpoint?param=FUZZ"
```

### Rate‑Limit Evasion
```bash
# Slow scanning with delays
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 5 -c -p 0.5 -fs 0

# Rotate user‑agents
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 10 -c -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" -fs 0

# Use proxy rotation (Burp, etc.)
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 10 -c -x http://127.0.0.1:8080 -fs 0
```

### Obfuscated Path Discovery
```bash
# URL‑encoded paths
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/common.txt -t 20 -c -H "Accept-Encoding: gzip" -H "X-Original-URL: /admin" -fs 0

# Case variation (Linux vs Windows)
for word in $(cat /home/pwn/wordlists/common.txt); do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/${word^^}" | grep -v "404\|403" && echo "Found: ${word^^}"
done
```

### Cloud Storage Enumeration
```bash
# AWS S3 bucket discovery
s3scanner scan --buckets mybucket-list.txt --region us-east-1

# Azure Blob enumeration
az storage container list --account-name target --sas-token "..." 2>/dev/null

# GCP bucket testing
gsutil ls gs://bucket-name/ 2>/dev/null
```

### API Endpoint Discovery
```bash
# Extract endpoints from JavaScript files
cat target.js | grep -oE "['\"](/[a-zA-Z0-9_\-/.]+)['\"]" | cut -d"'" -f2 | cut -d'"' -f2 | sort -u

# Use LinkFinder
python3 LinkFinder.py -i https://target.com/script.js -o cli

# GraphQL introspection
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

### Sensitive File Detection
```bash
# Common backup/configuration files
for ext in .bak .old .backup .swp .tar.gz .zip .sql .env .gitignore; do
  curl -s -o /dev/null -w "%{http_code}" "https://target.com/config$ext" | grep -v "404\|403" && echo "Found: config$ext"
done

# Check for .git directory exposure
curl -s https://target.com/.git/HEAD | head -1
```

## Prevention Guidance (Developer‑Focused)

1. **Restrict directory listing** – Disable auto‑indexing in web server config (Apache `Options -Indexes`, Nginx `autoindex off`).
2. **Remove sensitive files** – Delete backup, configuration, and temporary files from production.
3. **Implement proper access controls** – Admin panels, API endpoints should require authentication.
4. **Use obscurity cautiously** – Hiding resources is not security; rely on authentication/authorization.
5. **Rate limiting** – Limit requests per IP to slow down enumeration.
6. **WAF rules** – Deploy WAF to detect and block scanning patterns.
7. **Regular audits** – Periodically scan your own assets for exposed sensitive files.
8. **Security headers** – Use `X‑Content‑Type‑Options: nosniff`, `X‑Frame‑Options: DENY`, etc.

## References

- [OWASP WSTG: Mapping](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [PortSwigger: Discovering hidden content](https://portswigger.net/web-security/hidden-content)
- [SecLists GitHub Repository](https://github.com/danielmiessler/SecLists)
- **Wfuzz cheatsheet:** [wfuzz.md](../wfuzz.md)
