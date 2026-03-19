# AWS S3 Bucket Hunting

> Comprehensive methodology and one‑liner commands for discovering, enumerating, and testing AWS S3 buckets for misconfigurations (public access, sensitive data exposure, writable buckets), incorporating 2025–2026 trends (S3 Block Public Access bypasses, cross‑account bucket policies, S3 Express One Zone security, multi‑region replication leaks, encryption bypass) and authoritative references (AWS Security Best Practices, CloudSploit, S3Scanner, OWASP Cloud Security).

AWS S3 (Simple Storage Service) buckets are a frequent source of data breaches due to misconfigured permissions, public access settings, and insecure bucket policies. Hunting for exposed S3 buckets is a critical reconnaissance activity in bug‑bounty programs and cloud security assessments.

## Methodology

### Bucket Discovery Sources

**1. Subdomain Enumeration**
- S3 bucket endpoints follow `[bucket‑name].s3.amazonaws.com` or regional variants (`s3‑[region].amazonaws.com`)
- Use subdomain enumeration tools (`subfinder`, `amass`, `shuffledns`) and filter for S3 patterns

**2. JavaScript Analysis**
- Frontend JavaScript often contains hard‑coded S3 URLs, API endpoints, and bucket names
- Extract S3 URLs from static JS files and source maps

**3. Wordlist Generation**
- Generate bucket name candidates from target vocabulary (company name, project names, environments)
- Use tools like `cewl` to create custom wordlists from target website content

**4. Public Datasets & OSINT**
- Search GitHub, GitLab, public pastebins for AWS keys, bucket names, and configuration files
- Use tools like `truffleHog`, `git‑all‑secrets`, `AWS‑Extractor‑CLI`

**5. Permission Checking**
- Test discovered bucket names for public `LIST` (list objects), `READ` (download), `WRITE` (upload), `FULL_CONTROL`
- Check bucket policies, ACLs, and S3 Block Public Access settings

**6. Sensitive File Detection**
- Scan bucket contents for common sensitive file extensions (`.env`, `.pem`, `.sql`, `.json`, etc.)
- Look for configuration files, backups, credentials, and logs

### Common Misconfigurations

- **Public Access Enabled** – bucket ACL or policy allows `AllUsers` or `AuthenticatedUsers`
- **Insecure Bucket Policies** – overly permissive `Principal: "*"` with dangerous actions
- **Cross‑Account Access** – bucket policy grants access to unauthorized AWS accounts
- **Missing Encryption** – objects stored without SSE‑S3, SSE‑KMS, or SSE‑C
- **Disabled Logging** – no S3 server‑access logging enabled
- **Versioning with Delete Markers** – deleted objects retained but accessible via version ID
- **S3 Block Public Access Bypass** – via bucket policy, ACL, or cross‑account access

## Tool Installation & Setup

### AWS CLI

```bash
# Install AWS CLI v2
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install --update
aws configure  # set credentials (optional for public bucket checks)
```

### S3Scanner

```bash
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner
pip3 install -r requirements.txt
# Usage: python3 s3scanner.py --bucket-file /home/pwn/wordlists/wordlist.txt
```

### cloud_enum (multi‑cloud enumeration)

```bash
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
```

### AWS‑Extractor‑CLI

```bash
git clone https://github.com/jobertabma/aws-extractor-cli.git
cd aws-extractor-cli
npm install
```

### cewl (Custom Wordlist Generator)

```bash
# Kali: apt install cewl
# Or Ruby gem
gem install cewl
```

### nuclei (S3 detection templates)

```bash
# Install nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Update templates
nuclei -update-templates
```

## Testing Commands (One‑Liners)

### S3 Bucket Detection from Crawled URLs

```bash
# Extract S3 bucket URLs from crawled URLs
cat crawledurls.txt | grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com" | anew s3-buckets.txt
cat crawledurls.txt | grep -oE "s3://[a-zA-Z0-9.-]+" | anew s3-buckets.txt
```

### Nuclei S3 Detection

```bash
# Use nuclei with S3 detection templates
subfinder -d example.com -all -silent | nuclei -t /wordlists/s3-detect.yaml -o s3-nuclei.txt
```

### Filter Live S3 Subdomains

```bash
# Filter subdomains identified as Amazon S3
grep -i "Amazon S3" alive-subs.txt > s3-subs.txt
```

### Extract S3 URLs from JavaScript

```bash
# Collect JS files with katana, extract S3 URLs
katana -u https://example.com -d 5 -jc -silent | grep -iE '\.js($|\?)' | tee all-js.txt
cat all-js.txt | xargs -I {} curl -s {} | grep -oE 'https?://[^" ]*\.s3\.amazonaws\.com/[^" ]+' | sort -u > s3-from-js.txt
```

### Java2S3 Tool (LinkedIn bucket discovery)

```bash
python java2s3.py alive-domains.txt linkedin.com output.txt
cat output.txt | grep -oP 'https?://[a-zA-Z0-9.-]*s3(\.dualstack)?\.ap-[a-z0-9-]+\.amazonaws\.com/[^\s"<>]+' | sort -u > s3-aws.txt
```

### Custom Wordlist + S3Scanner

```bash
# Generate wordlist from target site
cewl https://example.com -m 6 -d 3 --lowercase -w /home/pwn/wordlists/wordlist.txt
# Scan with S3Scanner
s3scanner -bucket-file /home/pwn/wordlists/wordlist.txt -enumerate -threads 20 | tee s3scanner-raw.txt
```

### Filter Open/Interesting Buckets

```bash
# Extract buckets with public permissions
cat s3scanner-raw.txt | grep -aE 'AllUsers:.*(READ|WRITE|FULL|LIST)' | grep -v 'None' > open-s3-buckets.txt
```

### S3 Permission Check via AWS CLI

```bash
# Test bucket list permission without authentication
cat s3-buckets.txt | xargs -I@ sh -c 'aws s3 ls s3://@ --no-sign-request 2>/dev/null && echo "OPEN: @"'
```

### List Bucket Contents

```bash
# Basic listing
aws s3 ls s3://bucket-name-here --no-sign-request
# Recursive with human-readable sizes
aws s3 ls s3://bucket-name-here --no-sign-request --recursive --human-readable
```

### Hunt for Sensitive Files

```bash
# Basic sensitive file extensions
aws s3 ls s3://bucket-name-here --no-sign-request --recursive | grep -iE '\.env|\.pem|\.key|\.json|\.yml|\.yaml|\.config|config\.php|\.ini|\.sql|\.db|\.log|\.backup|\.bkp|\.crt|\.cert|\.pfx|\.p12|\.keystore|id_rsa|id_dsa|\.passwd|\.htpasswd|\.htaccess|\.csv|\.xlsx|\.docx|\.pdf'
# Aggressive comprehensive search (extended list)
aws s3 ls s3://bucket-name-here --no-sign-request --recursive | grep -iE '\.(env|pem|key|json|yml|yaml|config|php|ini|sql|db|log|backup|bkp|crt|cert|pfx|p12|keystore|rsa|dsa|passwd|htpasswd|htaccess|csv|xlsx|xls|docx|doc|pdf|pptx|ppt|md|txt|bak|old|orig|swp|tar|zip|rar|7z|gz|tgz|enc|sh|ps1|bat|exe|dll|class|jar|war|jsp|asp|php|py|rb|cgi|pl|cfm|aspx|vb|vbs|c|cpp|h|cs|swift|go|rs|log|session|token|auth|access|secret|private|ssh|gpg|pgp|kdbx|wallet|dat|sqlite|ldb|ndjson|nd|out|pid|dump|tar\.gz|tar\.bz2|zipx|xz|bak\.gz)'
```

### Quick Multi‑Bucket Check

```bash
while read bucket; do
  echo "[*] Checking $bucket"
  aws s3 ls s3://$bucket --no-sign-request --recursive --human-readable | grep -iE '\.env|\.key|\.pem|\.sql|\.json' && echo "[!] Juicy files found in $bucket"
done < open-s3-buckets.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Bypassing S3 Block Public Access

S3 Block Public Access (BPA) is an account‑level setting that blocks public ACLs and policies. Bypasses include:

- **Cross‑Account Bucket Policies** – attach a bucket policy from another AWS account that grants public access (BPA does not block cross‑account policies)
- **AWS Service Principals** – use `"Principal": {"Service": "s3.amazonaws.com"}` to allow S3 service‑to‑service access that may be leveraged
- **Conditional Policies** – use `Condition` with `"aws:SourceVpc"` or `"aws:SourceIp"` that can be spoofed via VPC peering or IP forgery (limited)

### Exploiting Bucket Policies

- **Overly Permissive `Principal: "*"`** – classic misconfiguration still common
- **`Principal: {"AWS": "*"}`** – allows any authenticated AWS user (different from anonymous)
- **Missing `Deny` for `s3:DeleteObject`** – allows deletion of objects (data destruction)
- **`s3:PutObject` with `"Condition": {"StringEquals": {"s3:x-amz-acl": "public-read"}}`** – allows upload of public objects

### Cross‑Account Access Enumeration

- Use `aws s3api get-bucket-policy` to examine bucket policies for cross‑account ARNs
- Check if bucket policy grants access to other AWS accounts (e.g., `"Principal": {"AWS": "arn:aws:iam::123456789012:root"}`)
- Attempt to assume role in target account (if credentials leaked) and access bucket

### S3 Encryption Bypass

- **SSE‑S3 (Amazon S3‑managed keys)** – default encryption; if disabled, objects are stored unencrypted
- **SSE‑KMS (AWS KMS keys)** – check if KMS key policy allows public access (unlikely)
- **SSE‑C (customer‑provided keys)** – requires key; if key leaked, decrypt objects
- **Client‑Side Encryption** – encryption performed before upload; keys may be hard‑coded in client apps

### S3 Versioning & Delete Markers

- If versioning enabled, deleted objects remain accessible via version ID
- Use `aws s3api list-object-versions` to list all versions
- Retrieve deleted objects with `aws s3api get-object --bucket bucket‑name --key file.txt --version-id versionid`

### S3 Replication Leaks

- Cross‑region replication may copy objects to a bucket with weaker permissions
- Enumerate replication configuration: `aws s3api get-bucket-replication`

### S3 Express One Zone Security

- New storage class (2025) designed for low‑latency; check for public access and encryption settings
- Same permission model as standard S3; test for misconfigurations

## Detection & Verification

**Indicators of Misconfiguration:**

- Bucket lists objects without authentication (`aws s3 ls` succeeds with `--no-sign-request`)
- Objects downloadable via direct URL without credentials
- Bucket policy contains `"Effect": "Allow"` with `"Principal": "*"` or `"AWS": "*"`
- ACL includes `AllUsers` or `AuthenticatedUsers` grants

**Verification Steps:**

1. Confirm public `LIST` permission by listing bucket contents
2. Confirm public `READ` permission by downloading a sample object
3. Confirm public `WRITE` permission by uploading a test file (and deleting it)
4. Check bucket policy and ACL for explicit public grants
5. Validate impact: sensitive data exposure, data integrity, data destruction

## Prevention Guidance (AWS Best Practices)

1. **Enable S3 Block Public Access** at account and bucket levels
2. **Use Bucket Policies** instead of ACLs for fine‑grained control
3. **Principle of Least Privilege** – grant only necessary permissions to specific IAM users/roles
4. **Enable Encryption** – SSE‑S3 or SSE‑KMS for all objects
5. **Enable S3 Server Access Logging** to monitor access patterns
6. **Enable Versioning** and MFA Delete for critical buckets
7. **Regular Audits** – use AWS Config, CloudTrail, and third‑party tools (CloudSploit, ScoutSuite)
8. **Monitor with AWS Security Hub** and Amazon GuardDuty for suspicious S3 activity
9. **Use VPC Endpoints** for S3 to restrict access to within VPC
10. **Implement S3 Object Lock** for compliance and WORM (Write Once Read Many) requirements

## References

- **AWS Security Best Practices for Amazon S3** – [AWS Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- **CloudSploit** – [Open‑source AWS security scanning](https://github.com/aquasecurity/cloudsploit)
- **S3Scanner** – [Bucket discovery and enumeration tool](https://github.com/sa7mon/S3Scanner)
- **OWASP Cloud Security** – [Cloud Storage Security](https://owasp.org/www-project-cloud-security/)
- **AWS CLI S3 Reference** – [AWS CLI Command Reference](https://docs.aws.amazon.com/cli/latest/reference/s3/)
- **Recent Research (2025–2026)** – S3 Block Public Access bypass techniques, cross‑account bucket policy attacks, S3 Express One Zone security analysis
