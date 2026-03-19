# Cloud Credential Files

> Comprehensive methodology and one‑liner commands for discovering exposed cloud credential files (AWS keys, Azure secrets, GCP service accounts, Docker config, Kubernetes kubeconfig) across web servers, Git repositories, container images, and logs, incorporating 2025–2026 trends (CI/CD secret leaks, public container registries, infrastructure‑as‑code misconfigurations) and authoritative references (OWASP Secrets Management, GitGuardian, TruffleHog).

Cloud credential files contain access keys, secrets, tokens, and configuration that grant access to cloud resources. Accidental exposure via public repositories, misconfigured web servers, or leaked logs is a leading cause of cloud account compromise.

## Methodology

### Common Credential File Locations

**Web Server Paths:**
- `/.aws/credentials`, `/.aws/config`
- `/.docker/config.json`
- `/kubeconfig`, `~/.kube/config`
- `/.git/config` (may contain remote URLs with credentials)
- `/.env`, `/config/.env`, `/app/.env`
- `/.npmrc`, `/.yarnrc`
- `/.passwd`, `/shadow`, `/etc/shadow`

**Git Repositories:**
- Historical commits containing hard‑coded secrets
- Configuration files (`*.tf`, `*.yml`, `*.json`, `*.env`)
- CI/CD pipeline files (`.gitlab‑ci.yml`, `.github/workflows/*.yml`)

**Container Images:**
- Layers containing credential files
- Environment variables set via `ENV` instructions
- Build‑time secrets leaked in final image

**Logs & Monitoring:**
- Application logs that print secrets in error messages
- Cloud audit logs (CloudTrail, Azure Activity Log, GCP Audit Logs) exported to public buckets
- Debug endpoints that leak environment variables

**CI/CD Artifacts:**
- Pipeline logs stored in public artifacts
- Temporary credential files in runner workspaces

### Credential Patterns (Regex)

- **AWS Access Key ID**: `AKIA[0‑9A‑Z]{16}`
- **AWS Secret Access Key**: `[a‑zA‑Z0‑9+/]{40}` (but context‑dependent)
- **Azure Storage Account Connection String**: `DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+`
- **Azure AD Client Secret**: `[a‑zA‑Z0‑9~!_@#$%^&*()_+={}\|:;"'<>,.?/-]{20,}`
- **GCP Service Account JSON Key**: `"type": "service_account", "private_key_id": "[a‑z0‑9]+"`
- **Google API Key**: `AIza[0‑9A‑Z\-_]{35}`
- **Docker Registry Auth**: `"auths": {".*": {.*"auth": "[a‑zA‑Z0‑9+/=]+"`
- **Kubernetes Service Account Token**: `eyJhbGciOiJSUzI1NiIsImtpZCI6.*` (JWT)
- **Generic Bearer Token**: `Bearer [a‑zA‑Z0‑9\-._~+/]+=*`
- **Slack Webhook URL**: `https://hooks.slack.com/services/T[a‑zA‑Z0‑9]+/B[a‑zA‑Z0‑9]+/[a‑zA‑Z0‑9]+`
- **GitHub Personal Access Token**: `ghp_[a‑zA‑Z0‑9]{36}`

## Tool Installation & Setup

### TruffleHog (secret scanning)

```bash
# Install via pip
pip3 install trufflehog
# Or Docker
docker run -it trufflesecurity/trufflehog:latest github --repo https://github.com/user/repo
```

### gitleaks (Git secret scanner)

```bash
# Binary release
curl -sL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz | tar xz
sudo mv gitleaks /usr/local/bin/
# Or Docker
docker run -v $(pwd):/path zricethezav/gitleaks:latest detect --source /path
```

### git‑all‑secrets (mass Git repo scanning)

```bash
git clone https://github.com/anshumanbh/git-all-secrets.git
cd git-all-secrets
docker build -t git-all-secrets .
```

### shhgit (static analysis)

```bash
# Binary from releases
curl -L https://github.com/eth0izzle/shhgit/releases/latest/download/shhgit_linux_amd64 -o shhgit
chmod +x shhgit
```

### cloud‑custodian (policy‑based scanning)

```bash
pip3 install c7n
```

### AWS‑Extractor‑CLI

```bash
git clone https://github.com/jobertabma/aws-extractor-cli.git
cd aws-extractor-cli
npm install
```

## Testing Commands (One‑Liners)

### Cloud Credential Detection on Web Servers

```bash
# Test common credential file paths with httpx
cat crawledurls.txt | httpx -silent -path /.aws/credentials,/.docker/config.json,/kubeconfig,/config/.env,/app/.env,/etc/shadow -mc 200 -o cloud-creds.txt
```

### Regex‑Based Secret Scanning in Files

```bash
# Search for AWS keys in downloaded files
grep -rE "AKIA[0-9A-Z]{16}" downloaded/ --include="*.txt" --include="*.json" --include="*.yml" --include="*.yaml" | anew aws-keys.txt
```

### Git Repository Cloning and Scanning

```bash
# Clone a repo and run gitleaks
git clone https://github.com/org/repo.git && cd repo && gitleaks detect --source . --report gitleaks-report.json
```

### Mass Git Scanning with git‑all‑secrets

```bash
docker run -it -v $(pwd):/opt/results git-all-secrets -org "target-org" -token YOUR_GITHUB_TOKEN
```

### Container Image Scanning

```bash
# Use dive to explore layers
dive target/image:latest
# Use grype or trivy for secret detection
trivy image --security-checks secret target/image:latest
```

### CI/CD Log Scanning

```bash
# Download pipeline logs from public CI (e.g., GitHub Actions)
curl -s https://api.github.com/repos/org/repo/actions/runs | jq '.workflow_runs[].logs_url' | xargs -I@ curl -s @ | grep -E "AKIA|Bearer|Token"
```

### Extract Secrets from Wayback Machine

```bash
# Use gau to get historical URLs, then grep for secrets
gau target.com | httpx -silent -mc 200 | xargs -I@ sh -c 'curl -s @ | grep -E "AKIA|ghp_|eyJ" && echo "@"'
```

### Enumerate Public S3 Buckets for Credential Files

```bash
# List buckets and search for .env, credentials, etc.
aws s3 ls s3://bucket-name --no-sign-request --recursive 2>/dev/null | grep -iE '\.env|credentials|config\.json|kubeconfig' | head -20
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### CI/CD Secret Leakage

- **GitHub Actions secrets** exposed via print‑statement debugging (`echo ${{ secrets.TOKEN }}`)
- **GitLab CI variables** printed in job logs when `masked` flag is false
- **Azure DevOps secret variables** leaked via logging commands
- **CircleCI context** values printed in `run` steps

### Container Registry Misconfigurations

- **Public container registries** (Docker Hub, GitHub Container Registry, AWS ECR Public) with images containing secrets
- **Image layer caching** – secrets added in intermediate `RUN` commands may remain in final layer if not removed in same layer

### Infrastructure‑as‑Code (IaC) Secrets

- **Terraform state files** stored in public S3 buckets containing sensitive outputs
- **CloudFormation templates** with hard‑coded secrets in `Parameters` or `Mappings`
- **Ansible vault passwords** committed without encryption

### Secret Rotation & Historical Exposure

- **Rotated keys** still present in old commits, backups, or logs
- **Git history rewriting** (`git filter‑branch`, `BFG Repo‑Cleaner`) may not purge all references

### Entropy‑Based Detection Evasion

- **Obfuscated secrets** (base64‑encoded, hex‑encoded, encrypted) may bypass regex scanners
- **Secrets split across multiple variables** and assembled at runtime

### Cloud Metadata Service Abuse

- **Instance metadata service (IMDS)** – if credentials are stored as instance metadata, attacker with SSRF can retrieve them
- **Kubernetes service account tokens** mounted in pods; accessible via container escape or misconfigured permissions

## Detection & Verification

**Indicators of Exposure:**

- HTTP 200 on credential file paths (`/.aws/credentials`, `/.env`)
- Regex matches for known secret patterns in crawled content
- Git commit history containing keywords like `password`, `secret`, `key`
- Container image layers with sensitive files (`/root/.ssh/id_rsa`, `/home/user/.aws/credentials`)

**Verification Steps:**

1. Confirm the secret is valid (e.g., test AWS key with `aws sts get‑caller‑identity`)
2. Assess scope of access (IAM roles, resource permissions)
3. Determine if secret is still active (not rotated)
4. Evaluate impact: data exposure, resource compromise, lateral movement

## Prevention Guidance (Secrets Management Best Practices)

1. **Use a Secrets Manager** – AWS Secrets Manager, Azure Key Vault, Google Secret Manager, HashiCorp Vault
2. **Never Commit Secrets** – use `.gitignore` for credential files; employ pre‑commit hooks (gitleaks, truffleHog)
3. **Implement Secret Scanning in CI/CD** – integrate tools like GitGuardian, GitHub Advanced Security, GitLab Secret Detection
4. **Rotate Secrets Regularly** – automate rotation using cloud native services
5. **Principle of Least Privilege** – assign minimal permissions to service accounts and IAM roles
6. **Secure Container Images** – use multi‑stage builds, remove secrets from final layers, scan images with Trivy, Grype, or Docker Scout
7. **Protect Metadata Services** – restrict IMDS access (IMDSv2 with hop limit), use Kubernetes network policies to limit pod‑to‑metadata access
8. **Audit Logs for Secret Usage** – monitor CloudTrail, Azure Activity Logs, GCP Audit Logs for anomalous access patterns
9. **Educate Developers** – security training on secret handling, use of environment variables, and secure coding practices
10. **Regular External Scans** – use tools like `trufflehog` on public repositories, `shhgit` on external assets, and commercial secret‑detection services

## References

- **OWASP Secrets Management Cheat Sheet** – [OWASP Documentation](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- **GitGuardian Public Monitoring** – [GitGuardian](https://gitguardian.com)
- **TruffleHog Documentation** – [TruffleSecurity](https://trufflesecurity.com)
- **GitHub Secret Scanning** – [GitHub Docs](https://docs.github.com/en/code‑security/secret‑scanning)
- **Recent Research (2025–2026)** – CI/CD secret leakage patterns, container image secret detection, metadata service attacks
