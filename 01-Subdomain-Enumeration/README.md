# Subdomain Enumeration

> Discover all subdomains belonging to your target

## 🚀 Automated Subdomain Enumeration (Recommended)

Use **[subenum](https://github.com/manojxshrestha/subenum)** - A fast, automated bash-based subdomain enumeration tool that:
- Collects subdomains from **50+ passive sources** (Subfinder, Amass, Assetfinder, Findomain)
- Performs **FFUF DNS brute-forcing**
- **Automatically probes live hosts** (HTTP/HTTPS with status codes, titles, tech detection)
- ASN/Organization-based enumeration
- Certificate transparency search
- Parallel execution for faster results

### Installation

```bash
# Clone the repository
git clone https://github.com/manojxshrestha/subenum.git
cd subenum

# Run the installer (installs all required tools)
chmod +x install.sh
./install.sh

# Verify installation
chmod +x check.sh
./check.sh
```

### Usage

```bash
# Make executable
chmod +x subenum.sh

# Basic subdomain enumeration
./subenum.sh -d target.com

# With FFUF bruteforce
./subenum.sh -d target.com -fb

# With FFUF + HTTP probing (auto filter live hosts)
./subenum.sh -d target.com -fb -hp

# Parallel mode (auto runs FFUF + HTTP probe - fastest)
./subenum.sh -d target.com -p

# Full mode (parallel + ASN enumeration)
./subenum.sh -d target.com -p -an

# ASN by organization name
./subenum.sh -ao "Company Name"

# ASN by number
./subenum.sh -aa AS13335

# Custom wordlist
./subenum.sh -d target.com -fb -fw /home/pwn/wordlists/subdomains-top1million-110000.txt
```

### Options

| Option | Description |
|--------|-------------|
| `-d` | Target domain |
| `-fb` | Run FFUF bruteforce |
| `-hp` | HTTP probing (live host filter) |
| `-p` | Parallel mode (fastest) |
| `-an` | Auto ASN enumeration |
| `-ao` | ASN by organization name |
| `-aa` | ASN by number |
| `-ac` | Certificate transparency search |
| `-fw` | Custom FFUF wordlist |

### Output

Results are saved in `results/` folder:
- `alive-domains.txt` - Live probed hosts
- `https-subs.txt` - HTTPS subdomains
- `asnresults.txt` - ASN enumeration results

---

## Google Dorks for Initial Recon

```bash
site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)
```

## 1. Initial Recon

### ViewDNS – Find Origin IP

* Use **[ViewDNS](https://viewdns.info/)** to check **IP history** and attempt to grab the **origin IP** of the target.

```bash
# CDN detection and origin IP discovery
cat alive-domains.txt | httpx -silent -cdn | grep -v "true" > non-cdn.txt
dnsx -l non-cdn.txt -silent -a -resp  # Potential origin IPs
cat alive-domains.txt | httpx -silent -asn | grep -E "13335|15169|16509" > cloudflare-ips.txt  # CDN‑hosted
```

### Port Scan

Run a port scan to identify open services:

```bash
nmap -Pn --open target.com
```

* If open ports are found, inspect them individually.
* If **port 53 (DNS)** is open, begin DNS enumeration.

---

# Nmap Scanning Reference

For detailed OSCP-style enumeration and Nmap scanning methodology, refer to the following resource:

* [https://www.emmanuelsolis.com/oscp.html](https://www.emmanuelsolis.com/oscp.html)

---

## 2. DNS Enumeration

### Zone Transfer Attempt

```bash
dig axfr @target.com target.com
```

If the zone transfer fails, continue with **subdomain brute forcing**.

---

## 3. Manual Subdomain Brute Force

```bash
# Using subfinder (passive sources only)
subfinder -d target.com -all -o subfinder-subs.txt

# Using amass
amass enum -passive -d target.com -o amass-subs.txt

# Using assetfinder
assetfinder target.com > assetfinder-subs.txt

# DNS brute-forcing with gobuster
gobuster dns -d target.com -t 25 -w /home/pwn/wordlists/subdomains-top1million-20000.txt -o subdomains.txt

# Combine all results and probe for live hosts
cat *.txt | sort -u | httpx -silent -o live-hosts.txt
```

---

## 4. Virtual Host Discovery

```bash
gobuster vhost -u https://www.target.com -w /home/pwn/wordlists/common.txt --append-domain -o vhosts.txt

# With ffuf
ffuf -u https://www.target.com -H "Host: FUZZ.target.com" -w /home/pwn/wordlists/subdomains-top1million-110000.txt -t 50 -c -fs 0
```

## References

- **[subenum](https://github.com/manojxshrestha/subenum)** - Automated subdomain enumeration tool
- **[Subfinder](https://github.com/projectdiscovery/subfinder)** - Passive subdomain discovery
- **[Amass](https://github.com/OWASP/Amass)** - DNS enumeration
- **[Assetfinder](https://github.com/tomnomnom/assetfinder)** - Find subdomains
