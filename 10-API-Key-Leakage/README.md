# API Key & Secret Leakage Testing

> Comprehensive methodology for discovering exposed API keys, secrets, tokens, and credentials in web applications, JavaScript files, GitHub repositories, error messages, and environment variables (2025‑2026 trends).

## Methodology Overview

API keys and secrets are often accidentally exposed through:
1. **Client‑side JavaScript** (frontend code, bundled assets)
2. **Git repositories** (committed config files, .env, history)
3. **Error messages & stack traces** (debug mode enabled)
4. **Environment variables** (exposed via /proc/self/environ, /etc/profile)
5. **Public documentation** (API docs, README files, tutorials)
6. **Third‑party services** (pastebin, cloud storage, CI/CD logs)
7. **Mobile/desktop apps** (hardcoded in binaries, config files)

Test these areas systematically using regex patterns, dedicated tools, and manual inspection.

## Detection Techniques

### 1. JavaScript File Analysis

```bash
# Extract all JavaScript URLs
cat crawledurls.txt | grep -i "\.js$" | httpx -silent -mc 200 | anew js-urls.txt

# Search for API keys, tokens, secrets
cat js-urls.txt | while read url; do
  curl -s "$url" | grep -oiE "(api[_-]?key|apikey|api_secret|access_token|bearer|secret|token|password|credential|client_id|client_secret)[=:]['\"]?[a-zA-Z0-9_\-]{16,}['\"]?" | sed "s|^|$url: |"
done | anew api-keys.txt

# Use nuclei templates for comprehensive detection
cat js-urls.txt | nuclei -t http/exposures/tokens/ -silent -o nuclei-keys.txt
```

### 2. Comprehensive Regex Patterns

```bash
# Extended regex for various secret types
SECRET_REGEX='(api[_-]?key|apikey|api_secret|access[_-]?token|bearer|secret[_-]?key|secret|token|password|credential|client[_-]?id|client[_-]?secret|aws[_-]?access[_-]?key|aws[_-]?secret[_-]?key|ssh[_-]?rsa|private[_-]?key|encryption[_-]?key|jwt|firebase|stripe|twilio|sendgrid|mailgun|slack|github[_-]?token|gitlab[_-]?token|digitalocean[_-]?token|heroku[_-]?api[_-]?key|mongodb[_-]?uri|postgresql[_-]?uri|mysql[_-]?uri|redis[_-]?uri|rabbitmq[_-]?uri)'

# Format variations
FORMAT_REGEX='[=:]["'\'' ]?([a-zA-Z0-9_\-\.=+/]{16,})["'\'' ]?'

# Combined search
grep -oiE "$SECRET_REGEX$FORMAT_REGEX" target-file.js | sort -u
```

### 3. GitHub / GitLab Reconnaissance

```bash
# Clone repo and search history
git clone --depth 1 https://github.com/org/repo.git
cd repo
git log -p --all --full-history | grep -iE "$SECRET_REGEX" | head -100

# Use gitleaks
gitleaks detect --source . --report gitleaks-report.json

# Use trufflehog
trufflehog filesystem --directory=. --json | jq -r '.Raw' | grep -v "^null$"

# Search GitHub via API (requires token)
curl -H "Authorization: token $GITHUB_TOKEN" "https://api.github.com/search/code?q=org:target+api_key+OR+apikey+OR+secret" | jq '.items[].html_url'
```

### 4. Error Messages & Stack Traces

```bash
# Trigger errors with malformed requests
cat endpoints.txt | while read url; do
  curl -s "$url'\"\\\0" | grep -iE "$SECRET_REGEX|exception|error|stacktrace|traceback|debug"
done | anew error-secrets.txt

# Check common debug endpoints
for path in /debug /console /phpinfo /admin/debug /api/debug /dev/debug; do
  curl -s "https://target.com$path" | grep -iE "$SECRET_REGEX"
done
```

### 5. Environment Variable Exposure

```bash
# Check /proc/self/environ (LFI)
curl -s "https://target.com/page?file=../../../proc/self/environ" | strings | grep -iE "$SECRET_REGEX"

# Check .env files
for path in /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /config/.env /app/.env /api/.env; do
  curl -s "https://target.com$path" | grep -iE "$SECRET_REGEX"
done

# Check config files
for path in /config.json /config.yml /config.yaml /config.php /appsettings.json /settings.json /web.config /firebase.json /google-services.json; do
  curl -s "https://target.com$path" | grep -iE "$SECRET_REGEX"
done
```

### 6. Mobile App Analysis (APK/iPA)

```bash
# Extract APK
apktool d app.apk -o decompiled/
grep -r -iE "$SECRET_REGEX" decompiled/

# Check strings.xml, AndroidManifest.xml, .java/.kt files
find decompiled -type f -name "*.xml" -o -name "*.java" -o -name "*.kt" | xargs grep -iE "$SECRET_REGEX"

# iOS IPA analysis (requires decryption)
unzip app.ipa -d extracted/
find extracted -type f -name "*.plist" -o -name "*.strings" -o -name "*.swift" | xargs grep -iE "$SECRET_REGEX"
```

## Tool Automation

### gitleaks

```bash
# Configure gitleaks.toml
cat > gitleaks.toml <<EOF
[[rules]]
id = "api-key"
description = "API Key"
regex = '''(api[_-]?key|apikey)[=:]["'\'' ]?([a-zA-Z0-9_\-]{16,})["'\'' ]?'''
tags = ["key", "api"]
EOF

# Scan directory
gitleaks detect --config gitleaks.toml --source . --verbose --report leaks.json
```

### truffleHog

```bash
# Scan filesystem
trufflehog filesystem --directory=. --json | jq -c 'select(.FoundLine != null)' > findings.json

# Scan git repo
trufflehog git https://github.com/target/repo.git --json | jq -r '.Raw' | grep -v "^null$"
```

### nuclei

```bash
# Use token exposure templates
nuclei -l targets.txt -t http/exposures/tokens/ -silent -o tokens.txt

# Custom template for API keys
cat > api-key-template.yaml <<EOF
id: api-key-exposure
info:
  name: API Key Exposure
  author: yourname
  severity: high
  description: Detects exposed API keys in responses

requests:
  - method: GET
    path:
      - "{{BaseURL}}"

    matchers:
      - type: word
        words:
          - "api_key"
          - "apikey"
          - "api-secret"
        condition: or
EOF
nuclei -l targets.txt -t api-key-template.yaml
```

## Validation & Impact Assessment

### Verify Found Keys

```bash
# Test AWS keys
AWS_ACCESS_KEY_ID="AKIA..."
AWS_SECRET_ACCESS_KEY="..."
aws sts get-caller-identity --profile test 2>&1 | grep -v "InvalidClientTokenId\|SignatureDoesNotMatch"

# Test GitHub token
curl -H "Authorization: token $TOKEN" https://api.github.com/user | grep -i "login\|name"

# Test Stripe key
curl https://api.stripe.com/v1/balance -u "$STRIPE_KEY:" | grep -i "available\|error"

# Test Google API key
curl "https://maps.googleapis.com/maps/api/geocode/json?address=NYC&key=$GOOGLE_KEY" | grep -i "error_message\|results"

# Test Firebase URL
curl "$FIREBASE_URL/.json" | head -c 100
```

### Impact Classification

1. **Critical**: AWS root keys, GitHub personal access tokens with repo scope, database credentials
2. **High**: Stripe live keys, SendGrid API keys, Slack bot tokens, cloud provider access keys
3. **Medium**: Google Maps API keys, Firebase URLs (read-only), third‑party service keys
4. **Low**: Public/limited‑scope keys, test environment keys, expired keys

## Prevention & Best Practices

1. **Never commit secrets to version control**
   - Use .gitignore for .env, config files
   - Use pre‑commit hooks (gitleaks, trufflehog)
   - Use secret scanning in CI/CD (GitHub Advanced Security, GitLab Secret Detection)

2. **Use environment variables & secret managers**
   - AWS Secrets Manager, HashiCorp Vault, Azure Key Vault
   - Docker secrets, Kubernetes secrets
   - Never hardcode in source code

3. **Implement proper error handling**
   - Disable debug mode in production
   - Sanitize error messages
   - Use generic error pages

4. **Regular scanning & monitoring**
   - Scheduled scans of repositories
   - Monitor for secrets in logs
   - Alert on unauthorized API usage

5. **Use short‑lived tokens & rotation**
   - JWT with short expiration
   - API key rotation policies
   - Revoke compromised keys immediately

6. **Client‑side security**
   - Never expose secrets in frontend code
   - Use backend proxies for API calls
   - Implement proper CORS policies

## References

- **GitHub Secret Scanning**: https://docs.github.com/en/code-security/secret-scanning
- **GitLab Secret Detection**: https://docs.gitlab.com/ee/user/application_security/secret_detection/
- **OWASP Proactive Controls C3: Secure Database Access**: https://owasp.org/www-project-proactive-controls/v3/en/c3-secure-database
- **TruffleHog**: https://github.com/trufflesecurity/trufflehog
- **gitleaks**: https://github.com/gitleaks/gitleaks
- **HaveIBeenPwned Pwned Passwords**: https://haveibeenpwned.com/Passwords
- **2025‑2026 Trends**: AI‑assisted secret discovery, cloud metadata service abuse, CI/CD pipeline leaks


