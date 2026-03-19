# Nuclei Vulnerability Scanning

> Comprehensive guide for **automated vulnerability scanning with Nuclei** during web pentests, bug bounty hunting, and security assessments.  
> Covers Nuclei installation, scanning strategies, template management, integrations with recon tools, and 2025–2026 trends (new template categories, JavaScript/headless scanning, DAST integration, enterprise workflows).

Nuclei is a fast, customizable vulnerability scanner that uses YAML‑based templates to detect security issues across web applications, networks, cloud services, and APIs. It’s the de‑facto standard for bug‑bounty hunters and penetration testers.

## Methodology (Based on ProjectDiscovery Best Practices)

**1. Target preparation** – Gather URLs, subdomains, IPs, and open ports using tools like `subfinder`, `httpx`, `naabu`, `shodan`.

**2. Template selection** – Choose templates based on:
   - **Severity:** critical, high, medium, low
   - **Tags:** cve, rce, sqli, xss, lfi, ssrf, config, exposure
   - **Technology:** wordpress, jira, aws, azure, kubernetes
   - **Category:** http, network, dast, cloud, file, ssl

**3. Scanning strategies**  
   - **Template spray:** Run all templates against each target (resource‑intensive)  
   - **Target spray:** Run each template against all targets (better for distributed scanning)  
   - **Smart workflows:** Use `nuclei‑workflows` to chain templates based on previous findings

**4. Rate limiting & concurrency** – Adjust `-rl` (requests per second) and `-c` (concurrency) to avoid overloading targets or being blocked.

**5. Output & triage** – Export results in JSON, JSONL, Markdown, or HTML; filter false positives; prioritize critical findings.

**6. Continuous scanning** – Integrate Nuclei into CI/CD pipelines, nightly scans, and monitoring.

## Tool Installation & Setup

```bash
# Install latest Nuclei (go)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates (regularly)
nuclei -update-templates

# Install nuclei‑templates repository (optional)
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates

# Install nuclei‑workflows (pre‑defined scanning flows)
git clone https://github.com/projectdiscovery/nuclei-workflows.git ~/nuclei-workflows
```

## Scanning Commands

### Basic Nuclei Scan
```bash
nuclei -l https-subs.txt -severity medium,high,critical -c 100 -rl 200 -o nuclei-hits.txt
```

### Scan All Assets
```bash
nuclei -l all-assets-with-ports.txt -severity medium,high,critical -c 100 -rl 200 -o nuclei-allhits.txt
```

### CVE‑Specific Scanning
```bash
nuclei -l all-assets-with-ports.txt -t http/cves/2025/ -c 50 -rl 100 -retries 2 -v -o nuclei-results.txt
```

### Specific CVE (e.g., CVE‑2025‑55182)
```bash
nuclei -l all-assets-with-ports.txt -t http/cves/2025/CVE-2025-55182.yaml -c 50 -rl 100 -retries 2 -v -o nuclei-results.txt
```

### Cloud‑Focused Scanning (AWS, Azure, GCP)
```bash
nuclei -l all-assets-with-ports.txt -t cloud/aws/ -c 50 -rl 100 -retries 2 -v -esc -code -o nuclei-results.txt
```

### DAST Scanning (Dynamic Application Security Testing)
```bash
nuclei -l all-targets.txt -t dast/vulnerabilities/ -dast -retries 3 -timeout 15 -markdown-export BUGS -o nuclei-dast.txt
```

### Scan by Custom Tags
```bash
nuclei -l https-subs.txt -tags cve,rce,sqli,xss -severity critical,high -o tagged-results.txt
```

### Network Scanning (SSL, SSH, FTP, etc.)
```bash
nuclei -l ips.txt -t network/ -c 25 -o network-vulns.txt
```

## Advanced Scanning Techniques

### Shodan Recon → Nuclei Pipeline
```bash
shodan search "hostname:example.com" --fields ip_str --limit 1000 | sort -u | httpx -silent | nuclei -t /nuclei-templates/ -severity critical,high -stats -jsonl
```

```bash
shodan domain example.com | awk '{print $NF}' | sort -u | httpx -silent | nuclei -t ~/nuclei-templates -severity critical,high -c 50
```

### Swagger/OpenAPI Detection & Export
```bash
cat https-subs.txt | nuclei -disable-clustering -scan-strategy template-spray -bulk-size 300 -concurrency 25 -retries 2 -timeout 10 -v -no-color -disable-update-check -stats -templates /home/pwn/wordlists/swagger-api.yaml -markdown-export BUGS | tee -a bugs-verbose.txt
```

### Recursive Crawl + Nuclei Pipeline
```bash
katana -u https://example.com -d 6 -jc -kf all -aff -silent | tee crawl-output.txt | grep -E "\.(php|asp|aspx|jsp|do|action)(\?|$)" | nuclei -t /nuclei-templates/ -severity high,critical -silent -o crawl-vulns.txt
```

### Post‑Crawl Nuclei Scan
```bash
nuclei -l katana-urls.txt -severity low,medium,high,critical -o nuclei-results.txt
```

### Workflow‑Based Scanning
```bash
nuclei -l targets.txt -w ~/nuclei-workflows/web-scan.yaml -c 50 -rl 150 -o workflow-results.txt
```

### Headless Scanning (JavaScript‑rendered pages)
```bash
nuclei -l targets.txt -t headless/ -headless -page-timeout 30 -c 10 -o headless-results.txt
```

### Interactive Scan with Debug
```bash
nuclei -l targets.txt -t http/exposures/ -debug -interactsh-url https://interact.sh -o debug-results.txt
```

## Template Management & Customization

```bash
# List all templates
nuclei -tl

# Search templates by keyword
nuclei -ts "wordpress"

# Validate a custom template
nuclei -validate ~/custom-template.yaml

# Run only new templates (added since last update)
nuclei -l targets.txt -new-templates -c 30 -rl 100

# Run templates with specific author
nuclei -l targets.txt -author pdteam -severity high
```

## Integration with Recon Pipelines

```bash
# Subfinder → httpx → nuclei
subfinder -d target.com -silent | httpx -silent | nuclei -severity critical,high -c 50 -rl 150 -o subfinder-nuclei.txt

# Naabu (port scan) → httpx → nuclei
naabu -list hosts.txt -p 80,443,8080 -silent | httpx -silent | nuclei -t http/ -severity high -c 30 -o naabu-nuclei.txt

# Waybackurls → nuclei
waybackurls target.com | httpx -silent | nuclei -t http/ -severity medium,high -c 20 -o wayback-nuclei.txt
```

## Output Formats & Reporting

```bash
# JSONL (machine‑readable)
nuclei -l targets.txt -severity high -jsonl -o results.jsonl

# Markdown (human‑readable)
nuclei -l targets.txt -severity high -markdown -o report.md

# HTML report
nuclei -l targets.txt -severity high -report-html report.html

# CSV output
nuclei -l targets.txt -severity high -csv -o results.csv

# Send findings to Discord/Slack/Telegram (via notify)
nuclei -l targets.txt -severity critical -json | notify -provider slack -webhook-url $WEBHOOK
```

## Advanced Techniques & 2025‑2026 Trends

**1. JavaScript/headless scanning** – Nuclei’s headless engine can detect client‑side vulnerabilities (DOM XSS, JS framework issues).

**2. DAST integration** – Combine Nuclei with traditional DAST tools for comprehensive coverage.

**3. Workflow automation** – Use `nuclei‑workflows` to create multi‑step testing scenarios (e.g., detect CMS → run CMS‑specific templates).

**4. Cloud‑native scanning** – Templates for AWS, Azure, GCP misconfigurations (IAM, storage, secrets).

**5. CI/CD integration** – Run Nuclei in GitHub Actions, GitLab CI, Jenkins to catch vulnerabilities early.

**6. Zero‑day detection** – Rapid template creation for emerging CVEs (ProjectDiscovery releases templates within hours).

**7. Interactsh integration** – OOB (Out‑of‑Band) detection for blind vulnerabilities (SSRF, RCE, XXE).

**8. Custom template development** – Write YAML templates for proprietary technologies or internal APIs.

## Prevention Guidance (Defender‑Focused)

1. **Regularly scan your own assets** – Run Nuclei against your public footprint to discover exposed vulnerabilities.
2. **Monitor for new templates** – Subscribe to Nuclei template updates to stay aware of emerging detection methods.
3. **Implement WAF/IPS rules** – Block scanning patterns (e.g., excessive 404s, known Nuclei user‑agents).
4. **Rate limit per IP** – Reduce scan speed and detect scanning activity.
5. **Harden services** – Patch known CVEs, disable unnecessary features, follow security best practices.
6. **Use nuclei‑as‑a‑defender** – Incorporate Nuclei into your vulnerability management program.

## References

- [Nuclei Official Documentation](https://nuclei.projectdiscovery.io/)
- [Nuclei GitHub Repository](https://github.com/projectdiscovery/nuclei)
- [Nuclei‑Templates GitHub](https://github.com/projectdiscovery/nuclei-templates)
- [Nuclei‑Workflows GitHub](https://github.com/projectdiscovery/nuclei-workflows)
