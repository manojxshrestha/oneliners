# Nuclei Cheat Sheet

> Comprehensive **Nuclei commands by vulnerability category** for bug bounty hunters, penetration testers, and security engineers.  
> Includes curated command‑line examples for scanning CVEs, cloud misconfigurations, information disclosure, default credentials, technology‑specific vulnerabilities, and DAST testing. Updated with 2025–2026 trends (new template categories, headless scanning, workflow automation).

Nuclei is the go‑to tool for fast, template‑based vulnerability scanning. This cheat sheet organizes commands by target category to help you run focused or broad scans efficiently.

## Methodology (How to Use This Cheat Sheet)

1. **Target list preparation** – Generate a list of live hosts (`https‑subs.txt`, `all‑assets‑with‑ports.txt`) using tools like `subfinder`, `httpx`, `naabu`.
2. **Category selection** – Choose the relevant category (e.g., CVEs, cloud, exposures) based on your target’s technology stack.
3. **Adjust parameters** – Modify concurrency (`-c`), rate limit (`-rl`), retries, and output format as needed.
4. **Run scan** – Execute the command, monitor progress, and review findings.
5. **Triage & reporting** – Filter false positives, prioritize critical/high severity, and document results.

**Best practices:**  
- Start with low‑intensity scans (`-c 20`, `-rl 50`) to avoid overwhelming targets.  
- Use `-severity critical,high` to focus on high‑impact issues.  
- Combine with `-tags` to filter templates (e.g., `-tags cve,rce`).  
- Update templates regularly (`nuclei -update‑templates`).

---

## CVEs & Recent Vulnerabilities

```bash
# Scan for all CVEs (2025 and previous years)
nuclei -l https-subs.txt -t http/cves/ -c 50 -rl 100 -retries 2 -o nuclei-cves.txt

# Scan only 2025 CVEs
nuclei -l https-subs.txt -t http/cves/2025/ -c 50 -rl 100 -retries 2 -o nuclei-2025-cves.txt

# Scan specific year CVEs
nuclei -l https-subs.txt -t http/cves/2024/ -c 50 -rl 100 -retries 2 -o nuclei-2024-cves.txt
nuclei -l https-subs.txt -t http/cves/2023/ -c 50 -rl 100 -retries 2 -o nuclei-2023-cves.txt
```

---

## Cloud Misconfigurations

```bash
# AWS misconfigurations
nuclei -l https-subs.txt -t ~/nuclei-templates/cloud/aws/ -c 50 -rl 100 -retries 2 -o nuclei-aws.txt -esc -code

# Azure misconfigurations
nuclei -l https-subs.txt -t cloud/azure/ -c 50 -rl 100 -retries 2 -o nuclei-azure.txt

# GCP misconfigurations
nuclei -l https-subs.txt -t cloud/gcp/ -c 50 -rl 100 -retries 2 -o nuclei-gcp.txt

# Kubernetes misconfigurations
nuclei -l https-subs.txt -t cloud/kubernetes/ -c 50 -rl 100 -retries 2 -o nuclei-k8s.txt
```

---

## Information Disclosure & Exposures

```bash
# Config file exposures
nuclei -l https-subs.txt -t http/exposures/configs/ -c 50 -rl 100 -retries 2 -o nuclei-configs.txt

# Token/API key exposures
nuclei -l https-subs.txt -t http/exposures/tokens/ -c 50 -rl 100 -retries 2 -o nuclei-tokens.txt

# Backup file exposures
nuclei -l https-subs.txt -t http/exposures/backups/ -c 50 -rl 100 -retries 2 -o nuclei-backups.txt

# Log file exposures
nuclei -l https-subs.txt -t http/exposures/logs/ -c 50 -rl 100 -retries 2 -o nuclei-logs.txt
```

---

## Default Credentials & Panels

```bash
# Default credentials scanning
nuclei -l https-subs.txt -t http/default-logins/ -c 50 -rl 100 -retries 2 -o nuclei-default-creds.txt

# Exposed panels detection
nuclei -l https-subs.txt -t http/exposed-panels/ -c 50 -rl 100 -retries 2 -o nuclei-panels.txt
```

---

## Technology-Specific Scanning

```bash
# Next.js specific vulnerabilities
nuclei -l https-subs.txt -t ~/nuclei-templates/http/vulnerabilities/nextjs/ -c 50 -rl 100 -retries 2 -o nuclei-nextjs.txt

# WordPress vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/wordpress/ -c 50 -rl 100 -retries 2 -o nuclei-wordpress.txt

# Joomla vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/joomla/ -c 50 -rl 100 -retries 2 -o nuclei-joomla.txt

# Drupal vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/drupal/ -c 50 -rl 100 -retries 2 -o nuclei-drupal.txt

# Apache vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/apache/ -c 50 -rl 100 -retries 2 -o nuclei-apache.txt

# Jenkins vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/jenkins/ -c 50 -rl 100 -retries 2 -o nuclei-jenkins.txt

# GitLab vulnerabilities
nuclei -l https-subs.txt -t http/vulnerabilities/gitlab/ -c 50 -rl 100 -retries 2 -o nuclei-gitlab.txt
```

---

## Security Misconfigurations

```bash
# General misconfigurations
nuclei -l https-subs.txt -t http/misconfiguration/ -c 50 -rl 100 -retries 2 -o nuclei-misconfig.txt

# Debug modes enabled
nuclei -l https-subs.txt -t http/misconfiguration/debug/ -c 50 -rl 100 -retries 2 -o nuclei-debug.txt

# CORS misconfigurations
nuclei -l https-subs.txt -t http/misconfiguration/ -tags cors -c 50 -rl 100 -retries 2 -o nuclei-cors.txt
```

---

## File & DNS Scanning

```bash
# File-based vulnerabilities
nuclei -l https-subs.txt -t file/ -c 50 -rl 100 -retries 2 -o nuclei-file.txt

# DNS-based vulnerabilities
nuclei -l https-subs.txt -t dns/ -c 50 -rl 100 -retries 2 -o nuclei-dns.txt

# SSL/TLS vulnerabilities
nuclei -l https-subs.txt -t ssl/ -c 50 -rl 100 -retries 2 -o nuclei-ssl.txt
```

---

## DAST (Dynamic Application Security Testing)

```bash
# DAST vulnerabilities
nuclei -l https-subs.txt -t dast/vulnerabilities/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast.txt

# DAST CVEs
nuclei -l https-subs.txt -t dast/cves/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-cves.txt
```

---

## Headless Browser Scanning

```bash
# Headless browser vulnerabilities
nuclei -l https-subs.txt -t headless/vulnerabilities/ -headless -c 50 -rl 100 -retries 2 -o nuclei-headless.txt

# Headless CVEs
nuclei -l https-subs.txt -t headless/cves/ -headless -c 50 -rl 100 -retries 2 -o nuclei-headless-cves.txt
```

---

## Network & TCP Scanning

```bash
# Network vulnerabilities
nuclei -l all-assets-with-ports.txt -t network/vulnerabilities/ -c 50 -rl 100 -retries 2 -o nuclei-network.txt

# Network CVEs
nuclei -l all-assets-with-ports.txt -t network/cves/ -c 50 -rl 100 -retries 2 -o nuclei-network-cves.txt
```

---

## JavaScript & Code Analysis

```bash
# JavaScript vulnerabilities
nuclei -l https-subs.txt -t javascript/ -c 50 -rl 100 -retries 2 -o nuclei-js.txt

# Code vulnerabilities
nuclei -l https-subs.txt -t code/ -c 50 -rl 100 -retries 2 -o nuclei-code.txt
```

---

## Advanced Scanning with Filters

```bash
# Scan by severity
nuclei -l https-subs.txt -s critical,high -c 50 -rl 100 -retries 2 -o nuclei-critical-high.txt

# Scan by tags
nuclei -l https-subs.txt -tags cve -c 50 -rl 100 -retries 2 -o nuclei-cve-tagged.txt

# Scan by author
nuclei -l https-subs.txt -author pdteam -c 50 -rl 100 -retries 2 -o nuclei-pdteam.txt

# Exclude specific templates
nuclei -l https-subs.txt -t http/cves/ -exclude-tags "dos" -c 50 -rl 100 -retries 2 -o nuclei-cves-no-dos.txt
```

---

## Comprehensive Multi-Category Scan

```bash
nuclei -l https-subs.txt \
  -t http/cves/ \
  -t http/exposures/ \
  -t http/misconfiguration/ \
  -t http/vulnerabilities/ \
  -s critical,high,medium \
  -c 50 -rl 100 \
  -retries 2 \
  -o nuclei-comprehensive.txt
```

---

## DAST Vulnerability Commands

### Command Injection (CMDI)

```bash
nuclei -l https-subs.txt -t dast/vulnerabilities/cmdi/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-cmdi.txt
```

### CRLF Injection

```bash
nuclei -l crlf-urls.txt -t dast/vulnerabilities/crlf/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-crlf.txt
```

### Client-Side Template Injection (CSTI)

```bash
nuclei -l csti-urls.txt -t dast/vulnerabilities/csti/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-csti.txt
```

### General Injection

```bash
nuclei -l injection-urls.txt -t dast/vulnerabilities/injection/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-injection.txt
```

### Local File Inclusion (LFI)

```bash
nuclei -l lfi-urls.txt -t dast/vulnerabilities/lfi/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-lfi.txt
```

### Open Redirect

```bash
nuclei -l redirect-urls.txt -t dast/vulnerabilities/redirect/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-redirect.txt
```

### Remote File Inclusion (RFI)

```bash
nuclei -l rfi-urls.txt -t dast/vulnerabilities/rfi/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-rfi.txt
```

### SQL Injection (SQLi)

```bash
nuclei -l sqli-urls.txt -t dast/vulnerabilities/sqli/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-sqli.txt
```

### Server-Side Request Forgery (SSRF)

```bash
nuclei -l ssrf-urls.txt -t dast/vulnerabilities/ssrf/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-ssrf.txt
```

### Server-Side Template Injection (SSTI)

```bash
nuclei -l ssti-urls.txt -t dast/vulnerabilities/ssti/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-ssti.txt
```

### Cross-Site Scripting (XSS)

```bash
nuclei -l xss-urls.txt -t dast/vulnerabilities/xss/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-xss.txt
```

### XML External Entity (XXE)

```bash
nuclei -l xxe-urls.txt -t dast/vulnerabilities/xxe/ -dast -c 50 -rl 100 -retries 2 -o nuclei-dast-xxe.txt
```

### Comprehensive DAST Scan (All Categories)

```bash
nuclei -l https-subs.txt \
  -t dast/vulnerabilities/ \
  -dast \
  -c 50 -rl 100 \
  -retries 2 \
  -o nuclei-dast-comprehensive.txt
```

---

## Why These Are Important

### High-Impact Vulnerabilities
- **SQLi, XSS, SSRF** - Critical web app security risks
- **LFI/RFI** - File system access vulnerabilities
- **CMDI** - Remote code execution potential
- **XXE** - XML parsing attacks

### Bug Bounty Favorites
- **Open Redirect** - Common, easy to find
- **CRLF Injection** - Header manipulation
- **SSTI/CSTI** - Template engine attacks

---

## Execution Priority

1. **Start with**: SQLi, XSS, SSRF (highest impact)
2. **Then**: LFI, RFI, CMDI (medium impact)
3. **Finally**: Redirect, CRLF, XXE (context-dependent)

---

## Trends & Advanced Tips (2025–2026)

**1. Headless scanning** – Use `-headless` flag for JavaScript‑rendered pages; combines browser automation with Nuclei detection.

**2. Workflow automation** – Create custom workflows (`nuclei‑workflows`) to chain templates (e.g., detect CMS → run CMS‑specific templates).

**3. DAST integration** – Nuclei’s DAST engine performs deep interactive testing; combine with `-dast` and `-interactsh` for OOB detection.

**4. Cloud‑native templates** – New categories for AWS, Azure, GCP, Kubernetes misconfigurations; scan cloud metadata endpoints.

**5. Zero‑day response** – ProjectDiscovery releases Nuclei templates for new CVEs within hours; monitor `-new‑templates`.

**6. CI/CD integration** – Embed Nuclei in GitHub Actions, GitLab CI, Jenkins for continuous security testing.

**7. Custom template development** – Write YAML templates for proprietary technologies; validate with `nuclei‑validate`.

**8. Performance tuning** – Use `-bulk‑size`, `-template‑spray`, `-scan‑strategy` for large‑scale scans.

**9. Reporting enhancements** – Export findings to Markdown, HTML, JSONL; integrate with notification tools (Discord, Slack, Telegram).

**10. Community templates** – Contribute to the `nuclei‑templates` repository; leverage community‑discovered detection logic.

## References

- [Nuclei Official Documentation](https://nuclei.projectdiscovery.io/)
- [Nuclei‑Templates GitHub](https://github.com/projectdiscovery/nuclei‑templates)
- [Nuclei‑Workflows GitHub](https://github.com/projectdiscovery/nuclei‑workflows)
