# Specialized Recon

> Comprehensive guide for **specialized reconnaissance techniques** during web pentests, bug bounty hunting, and security assessments.  
> Covers favicon‑based searching, historical endpoint discovery, exposed configuration files, advanced recon pipelines, and 2025–2026 trends (AI‑driven recon, cloud asset discovery, API endpoint enumeration).

Specialized reconnaissance goes beyond basic subdomain enumeration and directory brute‑forcing. It involves creative techniques to discover hidden assets, endpoints, and misconfigurations that automated tools might miss.

## Methodology (Based on OWASP Reconnaissance & Bug Bounty Playbooks)

**1. Asset discovery** – Identify all assets belonging to the target:
   - **Traditional:** Subdomains, IP ranges, ASNs
   - **Cloud:** S3 buckets, Azure blobs, GCP storage, cloud‑front domains
   - **Historical:** Wayback Machine, Common Crawl, archival services
   - **Certificate transparency:** crt.sh, certspotter, monitor new certificates

**2. Fingerprinting & mapping** – Gather technology stack, versions, and unique identifiers (favicon hashes, static file hashes, headers).

**3. Endpoint enumeration** – Extract endpoints from JavaScript files, API documentation, mobile apps, and third‑party integrations.

**4. Configuration file discovery** – Hunt for exposed configuration files (`.env`, `config.json`, `auth.json`, `wp‑config.php`).

**5. Advanced correlation** – Combine multiple data sources (Shodan, Censys, FOFA, BinaryEdge) to map external attack surface.

## Tool Installation & Setup

```bash
# Shodan CLI
pip3 install shodan

# waybackurls (from Wayback Machine)
go install github.com/tomnomnom/waybackurls@latest

# httpx (HTTP toolkit)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ffuf (fuzzer)
go install github.com/ffuf/ffuf@latest

# gau (fetch known URLs from AlienVault OTX, Common Crawl, etc.)
go install github.com/lc/gau/v2/cmd/gau@latest

# hakrawler (web crawler)
go install github.com/hakluke/hakrawler@latest
```

## Detection & Enumeration Commands

### Shodan Favicon‑Based Search
```bash
# Compute favicon hash (MurmurHash3)
curl -s https://target.com/favicon.ico | python3 -c 'import mmh3, sys, codecs; print(mmh3.hash(codecs.encode(sys.stdin.buffer.read(), "base64")))'

# Search Shodan for same hash
shodan search org:"Target" http.favicon.hash:116323821 --fields ip_str,port --separator | awk '{print $1":"$2}'
```

### Find JSON Endpoints from Historical URLs
```bash
cat https-subs.txt | waybackurls | httpx -mc 200 -ct | grep application/json

# Alternative: gau + httpx
gau target.com | httpx -mc 200 -ct application/json -o json-endpoints.txt
```

### Probe for Exposed auth.json Files
```bash
cat alive-domains.txt | httpx -path "/auth.json" -title -status-code -content-length -t 80 -p 80,443,8080,8443,9000,9001,9002,9003

# Also check other sensitive configs
for file in .env config.json wp-config.php settings.php; do
  echo "Checking $file"
  cat alive-domains.txt | httpx -path "/$file" -mc 200 -silent -o $file‑exposed.txt
done
```

### Advanced Web Recon Pipeline
```bash
cat alive-domains.txt | httprobe -c 50 -t 100 | wfuzz -w /home/pwn/wordlists/subdomains-top1million-20000.txt -c -u 'http://FUZZ.TARGET.COM/' -H 'X-Forwarded-For: FUZZ' -v --hc 404 | grep -e "code-200" | awk '{print $5}' | grep -E '.php|.asp|.jsp' | hakcheckurl -verbose | grep -E 'high|medium' | sort -u > vuln-url.txt
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

### Favicon Hash Correlation Across Multiple Sources
```bash
# Use multiple search engines (Shodan, Censys, FOFA, ZoomEye) for same favicon hash
# Example with Censys (requires API key)
censys search "services.http.response.favicons.mmh3:116323821" | jq -r '.ip'
```

### JavaScript Endpoint Extraction
```bash
# Use LinkFinder
python3 LinkFinder.py -i https://target.com/script.js -o cli | grep -E "api|endpoint|auth|token"

# Use js‑endpoints
cat target.js | grep -oE "['\"](/[a-zA-Z0-9_\-/.]+)['\"]" | cut -d"'" -f2 | cut -d'"' -f2 | sort -u

# Use subjs
subjs -i https://target.com -o js-urls.txt
```

### Cloud Asset Discovery
```bash
# S3 bucket enumeration
s3scanner scan --buckets bucket-list.txt --region us-east-1

# Azure blob scanning
az storage container list --account-name target --sas-token "..." 2>/dev/null

# GCP bucket testing
gsutil ls gs://bucket-name/ 2>/dev/null
```

### Certificate Transparency Logs
```bash
# Use certspotter
certspotter -d target.com

# Use crt.sh via curl
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u

# Use subfinder with cert‑sources
subfinder -d target.com -sources crt -silent
```

### Historical Data Analysis
```bash
# Combine waybackurls, gau, and commoncrawl
waybackurls target.com | gau target.com | sort -u | httpx -mc 200 -o historical-urls.txt

# Filter for interesting parameters
cat historical-urls.txt | grep -E "(\?|&)(id|token|key|auth|secret|password)="
```

### API Documentation Discovery
```bash
# Common API doc paths
for path in /api/docs /swagger/index.html /openapi.json /api/v1/swagger.json; do
  curl -s https://target.com$path | grep -q "swagger\|openapi" && echo "Found API docs: $path"
done
```

### Mobile App Recon (APK Analysis)
```bash
# Extract endpoints from APK
apktool d target.apk
grep -r "http://" target.apk/smali/ | grep -v "\.google\|\.facebook"

# Use MobSF for automated analysis
docker run -p 8000:8000 opensecurity/mobile‑security‑framework‑mobsf
```

## Automation Pipelines

### Full Recon Pipeline (Subdomains → HTTP → Endpoints)
```bash
subfinder -d target.com -silent | httpx -silent -o live.txt
cat live.txt | waybackurls | gau | sort -u | httpx -mc 200 -o endpoints.txt
cat endpoints.txt | grep -E "\.json$|\.xml$|\.yaml$" | httpx -ct -o api-endpoints.txt
```

### Shodan + Nuclei for Exposed Services
```bash
shodan search "http.component:GitLab" --fields ip_str,port --limit 100 | awk '{print $1":"$2}' | httpx -silent | nuclei -t http/exposures/gitlab -o gitlab-exposed.txt
```

### Cloud Recon Pipeline
```bash
# Enumerate cloud assets from certificate transparency
crt.sh -q %%.target.com | grep -E "s3\.amazonaws\.com|blob\.core\.windows\.net|storage\.googleapis\.com" | sort -u
```

## Prevention Guidance (Defender‑Focused)

1. **Monitor certificate transparency** – Set up alerts for new certificates issued for your domains.
2. **Regularly scan your external footprint** – Use tools like Shodan, Censys to see what attackers see.
3. **Remove exposed configuration files** – Ensure `.env`, `config.json`, etc. are not accessible via web.
4. **Implement proper access controls** – Even internal endpoints should require authentication.
5. **Use security headers** – `X‑Robots‑Tag: noindex` to discourage indexing of sensitive pages.
6. **Limit information leakage** – Suppress server banners, version numbers, and stack traces.
7. **Cloud storage permissions** – Apply least‑privilege principles to S3 buckets, Azure blobs, etc.
8. **Educate developers** – Include security in DevOps (DevSecOps) to avoid exposing secrets in code.

## References

- [OWASP Reconnaissance](https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/01‑Information_Gathering/)
- [Shodan Search Guide](https://help.shodan.io/)
- [Censys Search Syntax](https://support.censys.io/hc/en‑us/articles/360043177092‑Search‑2‑0‑Query‑Syntax)
- [Bug Bounty Recon Methodology](https://github.com/owasp/API‑Security/blob/master/guides/reconnaissance.md)
