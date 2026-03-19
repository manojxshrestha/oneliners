# Live Host Discovery

> Filter discovered subdomains to find only live/responsive hosts

> **💡 Tip:** Use [subenum](https://github.com/manojxshrestha/subenum) with `-fb -hp` flags for automated subdomain discovery + live host filtering in one step!

## 🚀 Automated (Recommended)

```bash
# Using subenum - auto discovers subdomains AND probes live hosts
./subenum.sh -d target.com -fb -hp

# Results are saved in results/ folder
# - alive-domains.txt  # Live probed hosts
# - https-subs.txt      # HTTPS subdomains with status codes
```

---

## Probe Live Subdomains with HTTPX

```bash
# Basic HTTP probing
httpx -l subdomains.txt -silent -o live-hosts.txt

# With status codes, titles, and tech detection
cat subdomains.txt | httpx -ports 80,443,8080 -status-code -mc 200,301,302,403,500 -title -tech-detect -web-server -threads 100 -silent -o probed-hosts.txt
```

---

## Advanced Live Host Detection

```bash
# DNS resolution + HTTP probing combined
dnsx -l subdomains.txt -silent -a | cut -d ' ' -f1 | httpx -ports 80,443,8080 -status-code -mc 200,301,302,403,500 -title -tech-detect -web-server -threads 100 -silent -o alive-subs.txt
```

---

## Clean Domain Lists

```bash
# Extract clean domain names
cat probed-hosts.txt | awk '{print $1}' | sed 's|^https\?://||' | sed 's|/$||' | sort -u > alive-domains.txt

# Extract URLs with specific status codes
cat probed-hosts.txt | grep "200" | awk '{print $1}' > 200-status-urls.txt

# Extract https URLs only
grep "https" probed-hosts.txt | awk '{print $1}' > https-subs.txt
```

---

## Shodan IP Discovery

```bash
# Search Shodan for target domains
shodan search "ssl:'target.com'" --fields ip_str,port --limit 1000 >> shodan-ips.txt

# Search by hostname
shodan search "hostname:target.com" --fields ip_str --limit 1000 >> shodan-ips.txt
```

---

## Port Scanning

### DNS Resolution to IPs

```bash
# Resolve domains to IP addresses
dnsx -l alive-domains.txt -a -resp-only -o ips.txt

# With A, AAAA, and CNAME records
dnsx -l alive-domains.txt -a -aaaa -cname -resp-only -o resolved-ips.txt
```

### Fast Port Discovery with Naabu

```bash
# Quick scan - top 100 ports
naabu -list alive-domains.txt -top-ports 100 -o scanned-ports.txt -silent -c 50

# Full scan - top 1000 ports
naabu -list alive-domains.txt -top-ports 1000 -o scanned-ports.txt -silent -c 50

# With Nmap service detection
naabu -list alive-domains.txt -top-ports 100 -nmap-cli 'nmap -sV -Pn -oN -' -o nmap-results.txt -silent -c 50
```

### Targeted Port Scanning with RustScan

```bash
./rustscan -a ips.txt -p 80,81,443,8080,8443,8000,8888,22,21,23,25,53,110,143,3306,3389,5900,6379,7001,9200,27017 --ulimit 5000 -- -sV -oX rustscan.xml
```

---

## High-Value Ports Reference

| Port | Why it matters |
|------|----------------|
| 80 / 443 | Web apps, APIs, HTTPS |
| 8080 / 8443 | Admin panels, dev apps |
| 8000 / 8888 | Alternative web servers |
| 22 | SSH (brute-force, key leaks) |
| 21 | FTP (anonymous access) |
| 3306 | MySQL (exposed DBs) |
| 6379 | Redis (no auth = critical) |
| 9200 | Elasticsearch (often unauth) |
| 27017 | MongoDB (no auth) |
| 7001 | WebLogic (RCE history) |
| 3389 | RDP |

---

## References

- **[subenum](https://github.com/manojxshrestha/subenum)** - Subdomain + Live host enumeration
- **[httpx](https://github.com/projectdiscovery/httpx)** - Fast HTTP probing
- **[dnsx](https://github.com/projectdiscovery/dnsx)** - DNS resolution
- **[naabu](https://github.com/projectdiscovery/naabu)** - Fast port scanner
