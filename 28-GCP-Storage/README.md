# GCP Storage

> Comprehensive methodology and one‑liner commands for discovering and testing Google Cloud Storage (GCS) buckets, incorporating 2025–2026 trends (uniform bucket‑level access, IAM condition bypass, cross‑project access, sensitive data exposure) and authoritative references (Google Cloud Security Best Practices, OWASP Cloud Security, gsutil).

Google Cloud Storage (GCS) is Google’s object storage service. Buckets are globally unique and can be configured with fine‑grained permissions via Cloud IAM policies and/or legacy ACLs. Misconfigured buckets are a common source of data breaches in GCP environments.

## Methodology

### GCS Bucket Detection

- **Endpoint pattern**: `storage.googleapis.com/[bucket‑name]` and `[bucket‑name].storage.googleapis.com`
- Also `[bucket‑name].cdn.storage‑googleapis.com` (CDN endpoints)
- Bucket names are globally unique; enumerate via wordlists, subdomain enumeration, and OSINT

### Permission Model

GCS offers two permission systems:

1. **Uniform bucket‑level access (recommended)** – permissions managed solely through IAM policies; ACLs are disabled. IAM roles (e.g., `roles/storage.objectViewer`, `roles/storage.objectCreator`) are assigned at bucket or project level.

2. **Fine‑grained access control (legacy)** – uses both IAM policies and ACLs. ACLs grant permissions to individual users, groups, or projects (e.g., `allUsers`, `allAuthenticatedUsers`).

Key dangerous permissions:

- `storage.objects.get` – read objects
- `storage.objects.list` – list bucket contents
- `storage.objects.create` – upload objects
- `storage.objects.delete` – delete objects
- `storage.buckets.get` – get bucket metadata

### Sources for Bucket Names

- Subdomain enumeration (`*.storage.googleapis.com`)
- JavaScript files (GCS URLs, API calls)
- Mobile app decompilation (strings search)
- GitHub repositories (configuration files, deployment scripts)
- Public datasets (Common Crawl, Wayback Machine)
- Google Cloud Pub/Sub messages, Cloud Functions logs (if leaked)

## Tool Installation & Setup

### Google Cloud SDK (gcloud + gsutil)

```bash
# Install Google Cloud SDK
curl https://sdk.cloud.google.com | bash
exec -l $SHELL
gcloud init  # authenticate (optional for public testing)
```

### gsutil (standalone)

```bash
# Install gsutil via pip
pip3 install gsutil
```

### cloud‑enum (multi‑cloud)

```bash
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt
```

### GCPBucketBrute

```bash
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git
cd GCPBucketBrute
pip3 install -r requirements.txt
```

## Testing Commands (One‑Liners)

### GCS Bucket Detection from Crawled URLs

```bash
# Extract storage.googleapis.com URLs
cat crawledurls.txt | grep -oE "storage\.googleapis\.com/[a-zA-Z0-9-]+" | sort -u > gcp-buckets.txt
# Extract bucket names from subdomains
cat crawledurls.txt | grep -oE "[a-zA-Z0-9-]+\.storage\.googleapis\.com" | sed 's/\.storage\.googleapis\.com//' | anew gcp-bucket-names.txt
```

### Check Bucket Public Access via gsutil

```bash
# Test list permission (anonymous)
while read bucket; do
  gsutil ls gs://$bucket 2>/dev/null | head -1 && echo "[PUBLIC LIST] $bucket"
done < gcp-bucket-names.txt
```

### Check Object Read Permission

```bash
# Attempt to download a common object (e.g., index.html, robots.txt)
while read bucket; do
  gsutil -q cp gs://$bucket/robots.txt . 2>/dev/null && echo "[PUBLIC READ] $bucket/robots.txt" && rm -f robots.txt
done < gcp-bucket-names.txt
```

### Enumerate Bucket Contents (if public list)

```bash
# List all objects in a public bucket
gsutil ls -r gs://public-bucket/
```

### Detect Uniform vs Fine‑Grained Access

```bash
# Check if uniform bucket-level access is enabled (requires authenticated gcloud)
gcloud storage buckets describe gs://bucket-name --format="value(iamConfiguration.uniformBucketLevelAccess.enabled)"
```

### Search for Sensitive Files

```bash
# Use gsutil with grep on object names
gsutil ls -r gs://bucket-name/** 2>/dev/null | grep -iE '\.(env|pem|key|json|yml|yaml|config|php|ini|sql|db|log|backup|bkp|crt|cert|pfx|p12|keystore|rsa|dsa|passwd|htpasswd|htaccess|csv|xlsx|docx|pdf)'
```

### Extract Bucket Names from JavaScript

```bash
# Search for storage.googleapis.com URLs in JS files
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE 'https?://[a-zA-Z0-9-]+\.storage\.googleapis\.com/[^"'\'' ]+' | anew gcs-js-urls.txt
```

### GCPBucketBrute Enumeration

```bash
# Enumerate bucket names using wordlist
python3 gcpbucketbrute.py --wordlist /home/pwn/wordlists/wordlist.txt --threads 20 --output found-buckets.txt
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### IAM Condition Bypass

- **Time‑based conditions** (`request.time < …`) – if condition uses stale timestamp, attacker may wait until time passes
- **Resource‑based conditions** (`resource.name.startsWith('projects/…')`) – may be bypassed via path traversal‑like techniques
- **IP‑based conditions** (`request.ip in […]`) – spoofing via compromised VM in allowed range or using Google Cloud Load Balancer

### Cross‑Project Access

- **Service account impersonation** – if a service account in Project A has permissions on a bucket in Project B, compromise of Project A leads to cross‑project access
- **Resource sharing via IAM** – bucket IAM policy may grant roles to users/service accounts from other projects

### Uniform Bucket‑Level Access Misconfiguration

- **Missing IAM deny policies** – overly permissive IAM roles at project level may grant unintended bucket access
- **Role inheritance** – roles assigned at folder or organization level may cascade to buckets

### Legacy ACLs Still Active

- Even with uniform bucket‑level access enabled, legacy ACLs may still be active if bucket was migrated incorrectly
- Check ACLs: `gsutil acl get gs://bucket`

### Signed URLs (Temporary Access)

- **Leaked signed URLs** – allow time‑limited access to specific objects; if leaked, attacker can download/upload
- **URL parameter tampering** – some signed URL implementations may have weak signature validation

### Cloud Storage FUSE Mounts

- If a VM mounts a GCS bucket via Cloud Storage FUSE, local file permissions on the VM may expose bucket contents

### Data Exfiltration via Cloud Functions / Cloud Run

- Serverless functions with overly permissive service accounts may be used to exfiltrate data from private buckets

## Detection & Verification

**Indicators of Misconfiguration:**

- `gsutil ls` succeeds without authentication (public list)
- Objects downloadable via direct URL (`https://storage.googleapis.com/[bucket]/[object]`)
- IAM policy contains `allUsers` or `allAuthenticatedUsers` bindings
- Legacy ACLs grant `READ` or `WRITE` to `allUsers`

**Verification Steps:**

1. Confirm public list permission (`gsutil ls gs://bucket`)
2. Confirm public read permission (download a test object)
3. Check IAM policy and ACLs (if authenticated)
4. Test for public write (upload test object and delete) – **only if authorized**
5. Assess impact: sensitivity of exposed data, potential for data destruction, financial impact (egress costs)

## Prevention Guidance (GCP Storage Security Best Practices)

1. **Enable Uniform Bucket‑Level Access** – disable legacy ACLs and manage permissions solely through IAM
2. **Principle of Least Privilege** – assign minimal IAM roles (e.g., `roles/storage.objectViewer` instead of `roles/storage.admin`)
3. **Block Public Access** – use organization policies (`constraints/storage.publicAccessPrevention`) to prevent public buckets
4. **Use VPC Service Controls** to restrict access to trusted networks
5. **Encrypt Data** – use Google‑managed keys (default) or customer‑managed keys (CMEK) for additional control
6. **Enable Audit Logging** – Cloud Audit Logs for Storage API calls; monitor with Cloud Security Command Center
7. **Regularly Review IAM Policies** – use Policy Intelligence and IAM Recommender to detect over‑permissive bindings
8. **Secure Service Accounts** – avoid using default compute engine service accounts; use dedicated service accounts with limited permissions
9. **Validate Signed URLs** – implement short expiry and strict signature verification
10. **Educate Developers** – avoid hard‑coding bucket names in client‑side code; use environment variables and secret management (Secret Manager)

## References

- **Google Cloud Storage Security Best Practices** – [GCP Documentation](https://cloud.google.com/storage/docs/security)
- **OWASP Cloud Security** – [Cloud Storage Security](https://owasp.org/www‑project‑cloud‑security/)
- **GCPBucketBrute** – [GitHub Repository](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
- **gsutil Command Reference** – [Google Cloud Documentation](https://cloud.google.com/storage/docs/gsutil)
- **Recent Research (2025–2026)** – IAM condition bypasses, cross‑project bucket access, uniform bucket‑level access misconfigurations
