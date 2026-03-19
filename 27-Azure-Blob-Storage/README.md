# Azure Blob Storage

> Comprehensive methodology and one‑liner commands for discovering and testing exposed Azure Blob Storage containers, incorporating 2025–2026 trends (SAS token leaks, private endpoint misconfigurations, storage account firewall bypass, access tier abuse) and authoritative references (Microsoft Azure Storage Security, OWASP Cloud Security, MicroBurst).

Azure Blob Storage is Microsoft’s object storage solution for the cloud. Storage accounts host **containers** that hold **blobs** (files). Misconfigured permissions, leaked Shared Access Signature (SAS) tokens, and overly permissive network rules can lead to sensitive data exposure, data tampering, and financial impact (high egress costs).

## Methodology

### Azure Blob Storage Detection

- **Endpoint pattern**: `[storage‑account].blob.core.windows.net`
- Extract storage account names from subdomain enumeration, JavaScript files, network traffic
- Also watch for `[storage‑account].z[0‑9].blob.core.windows.net` (geo‑redundant endpoints)

### Permission Model

Azure Blob Storage offers several access control mechanisms:

1. **Container Public Access Level**:
   - `Private` (default) – no anonymous access
   - `Blob` – anonymous read access to blobs only (no container listing)
   - `Container` – anonymous read access to entire container (list + read blobs)

2. **Shared Access Signature (SAS)** tokens – time‑limited, granular permissions (read, write, delete, list) that can be attached to container or blob URLs. Leaked SAS tokens are a common source of compromise.

3. **Storage Account Keys** – full control over the entire storage account; equivalent to root access.

4. **Azure Active Directory (Azure AD) authentication** – recommended, uses RBAC roles.

5. **Network Security** – storage account firewall rules restricting access to specific IPs/VNets; misconfigured rules may allow public access.

### Sources for Storage Account Names

- Subdomain enumeration (`*.blob.core.windows.net`)
- JavaScript files (Azure SDK calls, hard‑coded URLs)
- Mobile app decompilation (strings search)
- GitHub repositories (connection strings, SAS tokens)
- Azure DevOps pipelines, ARM templates

## Tool Installation & Setup

### Azure CLI

```bash
# Install Azure CLI
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
# Authenticate (optional for public testing)
az login
```

### MicroBurst (Azure security toolkit)

```bash
git clone https://github.com/NetSPI/MicroBurst.git
cd MicroBurst
Import‑Module ./MicroBurst.psm1  # PowerShell
```

### Azurite (local Azure Storage emulator)

```bash
npm install -g azurite
```

### blob‑scanner (Python)

```bash
git clone https://github.com/cyberaz0r/blob-scanner.git
cd blob-scanner
pip3 install -r requirements.txt
```

## Testing Commands (One‑Liners)

### Azure Blob Storage Detection from Crawled URLs

```bash
# Extract blob.core.windows.net endpoints
cat crawledurls.txt | grep -oE "[a-zA-Z0-9-]+\.blob\.core\.windows\.net" | sort -u > azure-blobs.txt
```

### Check Container Public Access Level

```bash
# Test for anonymous container listing (Container public access)
while read account; do
  curl -s "https://$account/?comp=list" | grep -q "EnumerationResults" && echo "[CONTAINER PUBLIC] $account"
done < azure-blobs.txt
```

### Check Blob‑Level Public Access

```bash
# Attempt to list blobs in a common container name (e.g., 'assets', 'uploads')
while read account; do
  curl -s "https://$account/assets?restype=container&comp=list" | grep -q "Blob" && echo "[BLOB PUBLIC] $account/assets"
done < azure-blobs.txt
```

### Extract Storage Account Names from JavaScript

```bash
# Search for blob.core.windows.net URLs in JS files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE 'https?://[a-zA-Z0-9-]+\.blob\.core\.windows\.net/[^"'\'' ]+' | anew azure-js-urls.txt
```

### Enumerate Container Names (Wordlist)

```bash
# Use common container names wordlist
cat common-containers.txt | while read container; do
  while read account; do
    curl -s "https://$account/$container?restype=container&comp=list" | grep -q "Blob" && echo "[CONTAINER FOUND] $account/$container"
  done < azure-blobs.txt
done
```

### Test for SAS Token Leaks

```bash
# Search for SAS tokens in crawled URLs (pattern: 'sv=', 'sig=')
cat crawledurls.txt | grep -oE 'https?://[^ ]*\?[^ ]*sv=[^ &]*&[^ ]*sig=[^ &]*' | anew sas-tokens.txt
```

### Validate SAS Token Permissions

```bash
# Use Azure Storage REST API to test token permissions (read, write, list)
# Example: curl -H "x-ms-date: $(date -u +'%a, %d %b %Y %H:%M:%S GMT')" "https://[account].blob.core.windows.net/[container]?[sas‑token]&comp=list"
```

### Check Storage Account Firewall Bypass

```bash
# Attempt to access storage account from different IP (use proxies/VPN)
# If firewall misconfigured (e.g., allows all Azure services), access may be granted
# Use Azure CLI with --query to check network rules (requires authentication)
az storage account show --name [account] --resource-group [rg] --query 'networkRuleSet'
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### SAS Token Abuse

- **Stolen SAS tokens** – often leaked in GitHub commits, logs, client‑side code
- **Token permissions escalation** – some tokens grant `write` or `delete` even if only `read` intended
- **Time‑limited tokens** – if token expiry is far future, long‑term access
- **Service‑level SAS** – scoped to entire storage account; more dangerous than container‑level SAS

### Container Public Access Bypass

- **Blob‑level public access** – if container is private but individual blobs have public read ACLs, enumerate blobs via guessable names (e.g., `logo.png`, `default.jpg`)
- **Hierarchical namespace (Azure Data Lake Storage Gen2)** – ACL inheritance misconfigurations may expose sub‑directories

### Storage Account Firewall Misconfiguration

- **Allow trusted Azure services** – firewall rule that allows all Azure services can be bypassed by deploying a malicious Azure function or VM in same region
- **IP‑based rules with wide ranges** (e.g., `/24` subnet) – attacker may reside within allowed range via compromised host or VPN
- **Missing deny rules** – default allow if no rules defined (depends on configuration)

### Access Tier Abuse

- **Hot/Cool/Archive tiers** – moving blobs to Archive tier can cause data retrieval delays and costs; attacker could maliciously archive critical data
- **Blob rehydration** – attacker could trigger rehydration of archived blobs incurring costs

### Azure AD Authentication Bypass

- **Weak RBAC assignments** – over‑permissive roles (e.g., `Storage Blob Data Contributor` on entire subscription)
- **Service principal with storage permissions** – leaked client secrets or certificate‑based auth

### Cross‑Tenant Access

- If storage account is configured to allow cross‑tenant replication, data may be copied to attacker‑controlled tenant

## Detection & Verification

**Indicators of Misconfiguration:**

- HTTP 200 with `EnumerationResults` on `/?comp=list` (container listing)
- Successful blob download without authentication
- SAS tokens present in URLs or source code
- Storage account firewall disabled or overly permissive rules

**Verification Steps:**

1. Confirm anonymous container listing (`/?comp=list`)
2. Confirm anonymous blob download (e.g., `/[container]/[blob]`)
3. Test SAS token permissions (list, read, write, delete) – **only if authorized**
4. Review network rules (if authenticated)
5. Assess impact: sensitivity of exposed data, potential for data destruction, financial impact (egress/archive costs)

## Prevention Guidance (Azure Storage Security Best Practices)

1. **Disable Public Access** – set container public access level to `Private` unless absolutely required
2. **Use Azure AD Authentication** instead of shared keys or SAS tokens where possible
3. **Rotate Storage Account Keys** regularly and monitor for unauthorized usage
4. **Restrict SAS Tokens** – use short expiry, least privilege, and store tokens securely (never in client‑side code)
5. **Enable Storage Account Firewall** – restrict access to specific IPs/VNets; disable public network access if not needed
6. **Enable Network Security Groups (NSGs)** and Private Endpoints for VNet‑integrated storage
7. **Enable Logging and Monitoring** – Azure Monitor, Storage Analytics logs, and Azure Sentinel for anomaly detection
8. **Use Immutable Blob Storage** (WORM) for compliance‑sensitive data
9. **Regular Audits** – use Azure Policy, Azure Security Center, and third‑party tools (MicroBurst, ScoutSuite) to detect misconfigurations
10. **Encrypt Data at Rest** – Azure Storage Service Encryption (SSE) is enabled by default; consider customer‑managed keys (CMK) for additional control

## References

- **Microsoft Azure Storage Security Guide** – [Azure Documentation](https://docs.microsoft.com/en‑us/azure/storage/blobs/security‑recommendations)
- **OWASP Cloud Security** – [Cloud Storage Security](https://owasp.org/www‑project‑cloud‑security/)
- **MicroBurst** – [Azure Security Toolkit](https://github.com/NetSPI/MicroBurst)
- **Azure Storage SAS Token Reference** – [SAS Overview](https://docs.microsoft.com/en‑us/azure/storage/common/storage‑sas‑overview)
- **Recent Research (2025–2026)** – SAS token leakage patterns, firewall bypass techniques, cross‑tenant attacks
