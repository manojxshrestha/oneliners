# Firebase Database

> Comprehensive methodology and one‑liner commands for discovering and testing exposed Firebase Realtime Databases and Cloud Firestore instances, incorporating 2025–2026 trends (security rules bypass, unauthenticated access, Firestore misconfigurations, chained authentication flaws) and authoritative references (Firebase Security Rules documentation, OWASP Mobile Security, Firebase‑scanner).

Firebase (Google’s mobile/web development platform) offers two database services: **Realtime Database** (endpoint `[project‑id].firebaseio.com`) and **Cloud Firestore** (REST endpoint `firestore.googleapis.com/v1/projects/[project‑id]/databases/(default)/documents/`). Misconfigured security rules often lead to public read/write access, exposing sensitive user data, API keys, and application logic.

## Methodology

### Firebase Realtime Database Detection

- **Endpoint pattern**: `[project‑id].firebaseio.com`
- Extract project IDs from JavaScript files, network traffic, and subdomain enumeration
- Test for public access by requesting `/.json` path

### Cloud Firestore Detection

- **Endpoint pattern**: `firestore.googleapis.com/v1/projects/[project‑id]/databases/(default)/documents/`
- Project IDs may be embedded in mobile app binaries, web JS, or API responses
- Test for public read access by listing collections

### Security Rules Analysis

Firebase security rules are JSON‑based policies that govern read/write permissions. Common misconfigurations:

- `{".read": true, ".write": true}` – public read/write (full exposure)
- `{".read": "auth != null", ".write": "auth != null"}` – requires authentication; may be bypassed if auth is weak
- **Conditional rules** with flawed logic (e.g., `request.auth.uid == resource.data.uid` but resource data is user‑controllable)
- **Wildcard paths** that inadvertently expose child nodes

### Sources for Project IDs

- JavaScript files (`firebaseConfig`, `apiKey`, `authDomain`, `databaseURL`, `projectId`)
- Mobile app APK/IPA decompilation (strings search)
- Subdomain enumeration (`*.firebaseio.com`)
- Public GitHub repositories (hard‑coded Firebase config)
- Network traffic from mobile apps (Burp Suite intercept)

## Tool Installation & Setup

### Firebase‑scanner

```bash
git clone https://github.com/shivsahni/FireBaseScanner.git
cd FireBaseScanner
pip3 install -r requirements.txt
```

### firebase‑exploit (Python script)

```bash
git clone https://github.com/ansarap/firebase-exploit.git
cd firebase-exploit
pip3 install -r requirements.txt
```

### firebase‑rules‑checker (Node.js)

```bash
npm install -g @firebase/rules-unit-testing
```

### apktool (for APK decompilation)

```bash
# Kali: apt install apktool
# Or download from https://ibotpeaches.github.io/Apktool/
```

## Testing Commands (One‑Liners)

### Firebase Realtime Database Detection

```bash
# Extract firebaseio.com endpoints from crawled URLs
cat crawledurls.txt | grep -oE "[a-zA-Z0-9-]+\.firebaseio\.com" | sort -u > firebase-endpoints.txt
```

### Test Public Read Access

```bash
# Attempt to read root data (/.json)
cat firebase-endpoints.txt | xargs -I@ sh -c 'curl -s "https://@/.json" | grep -v "null" && echo "[PUBLIC READ] @"'
```

### Enumerate Database Structure

```bash
# Recursive traversal (if public read)
curl -s "https://[project-id].firebaseio.com/.json" | jq 'keys[]'
```

### Cloud Firestore Detection

```bash
# Extract project IDs from JS files (pattern: projectId: "…")
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE 'projectId["\'\`]?\s*:\s*["\'\`]([^"\'\`]+)["\'\`]' | cut -d'"' -f2 | anew firestore-projects.txt
```

### Test Firestore Public Read

```bash
# Try to list collections
while read project; do
  curl -s "https://firestore.googleapis.com/v1/projects/$project/databases/(default)/documents" | grep -q "collections" && echo "[PUBLIC FIRESTORE] $project"
done < firestore-projects.txt
```

### Extract Firebase Config from JavaScript

```bash
# Search for firebaseConfig object
cat livejslinks.txt | xargs -I@ curl -s @ | grep -A 10 -B 2 "firebaseConfig" | grep -E "(apiKey|authDomain|databaseURL|projectId|storageBucket|messagingSenderId|appId)" | tr -d ' ,' | sed 's/["'\'']//g' | anew firebase-configs.txt
```

### Subdomain Enumeration for Firebase

```bash
# Use subfinder/amass to find firebaseio subdomains
subfinder -d example.com -silent | grep "firebaseio.com" | anew firebase-subdomains.txt
```

### Mobile App Analysis (APK)

```bash
# Decompile APK and search for Firebase strings
apktool d app.apk -o decompiled
grep -r "firebaseio\|firebaseapp\|projectId" decompiled/ | grep -v ".java" | cut -d':' -f2 | sort -u
```

## Advanced Techniques & Bypasses (2025–2026 Trends)

### Security Rules Bypass

- **Rule Flaw: `request.auth != null`** – if authentication is weak (e.g., anonymous auth enabled), attacker can create anonymous account and access data
- **Rule Flaw: `request.auth.uid == resource.data.uid`** – if resource data contains user‑controllable `uid` field, attacker can manipulate data to match their UID
- **Rule Flaw: `request.query.orderBy`** – Firestore rules that allow `orderBy` on public fields may leak data via sorting side‑channels
- **Rule Flaw: `request.time < resource.data.expires`** – if `expires` is client‑controlled, attacker can set future date to bypass time‑based restrictions

### Firebase Authentication Bypass

- **Anonymous Sign‑In** – enabled by default in some projects; allows unauthenticated users to obtain a temporary UID
- **Email/Password Auth with Weak Validation** – lack of email verification leads to account takeover via password reset
- **Social Auth (OAuth) Misconfiguration** – insufficient OAuth scope validation may allow access to unauthorized resources

### Chained Vulnerabilities

- **Firebase + XSS** – steal Firebase credentials (API keys, auth tokens) via XSS in web app
- **Firebase + Insecure Direct Object Reference (IDOR)** – manipulate resource paths to access other users’ data (if rules only protect by path)
- **Firebase + SSRF** – use SSRF to interact with Firebase metadata endpoints (e.g., `metadata.google.internal`)

### Firestore Specific Bypasses

- **Collection‑Group Queries** – rules that restrict collection‑level access but allow collection‑group queries may expose data across sub‑collections
- **Document‑Level vs Collection‑Level Rules** – inconsistent granularity may leave gaps
- **Offline Persistence** – client‑side cached data may be accessible if app uses persistent storage without encryption

### Firebase Cloud Storage

- Separate service (`firebasestorage.googleapis.com`) with its own security rules
- Test for public read/write on storage buckets (similar to S3)

## Detection & Verification

**Indicators of Misconfiguration:**

- HTTP 200 response with JSON data from `/.json` endpoint (Realtime Database)
- Firestore REST API returns collections or documents without authentication
- Security rules file (e.g., `firebase‑rules.json`) contains `"read": true` or `"write": true` for public paths
- Firebase config exposed in client‑side code with API keys and project IDs

**Verification Steps:**

1. Confirm public read by retrieving data from database root or specific collections
2. Confirm public write by pushing test data (and removing it) – **only if authorized**
3. Review security rules (if accessible via `/.settings/rules.json` or source code)
4. Assess impact: sensitivity of exposed data, potential for data manipulation/deletion

## Prevention Guidance (Firebase Security Best Practices)

1. **Lock Down Default Rules** – never start with `{".read": true, ".write": true}`; use `false` in production
2. **Use Authentication** – require `auth != null` and validate `request.auth.uid` matches resource ownership
3. **Validate Input** – use rule functions to enforce data schemas, type checks, and business logic
4. **Least Privilege** – grant read/write only to specific paths and conditions
5. **Regular Audits** – test rules with the Firebase Rules Unit Testing library
6. **Avoid Client‑Side Secrets** – API keys are not secrets; restrict using Firebase App Check and API key restrictions
7. **Enable Firebase App Check** to protect against abuse from unauthorized clients
8. **Monitor with Firebase Crashlytics and Performance Monitoring** for anomalous access patterns
9. **Use Cloud Firestore** over Realtime Database for more granular security rules and better scalability
10. **Encrypt Sensitive Data** client‑side before storing in Firebase (end‑to‑end encryption)

## References

- **Firebase Security Rules Documentation** – [Firebase Rules Guide](https://firebase.google.com/docs/rules)
- **OWASP Mobile Security Testing Guide** – [Firebase Security](https://owasp.org/www-project-mobile-security-testing-guide/)
- **Firebase‑scanner** – [GitHub Repository](https://github.com/shivsahni/FireBaseScanner)
- **Firebase Exploitation Blog Posts** – [Medium Articles](https://medium.com/tag/firebase‑security)
- **Recent Research (2025–2026)** – Firestore rule bypasses, Firebase App Check circumvention, chained vulnerabilities
