# URL Collection

> Crawl discovered hosts to build a comprehensive URL list for testing

## Historical URL Collection

### Waymore - Comprehensive Historical Data

```bash
waymore -i example.com -mode U -oU wayurls.txt
```

### GAU - GetAllUrls (optional)

```bash
echo "example.com" | gau --threads 10 --subs | anew gauurls.txt
```

### Combine and Deduplicate Historical URLs

```bash
cat wayurls.txt gauurls.txt | uro | sort -u > waygauurls.txt
```

## Web Crawling

### # 1. Hakrawler – fast crawling

```bash
cat https-subs.txt | hakrawler -subs -u -d 3 > hakcrawlurls.txt
```

### # 2. Katana – modern crawler with JavaScript execution

```bash
cat scopeurls.txt | katana -d 3 -jc -timeout 15 -c 20 -kf -fx ssr -aff | anew crawledurls.txt
```

### # 3. Katana for HTTPS subdomains

```bash
cat https-subs.txt | katana -d 3 -jc -timeout 15 -c 20 | anew cleansubskatanaurls.txt
```

### # 4. GoSpider – sophisticated spider

```bash
gospider -S https-subs.txt -o gooutput -c 10 -d 3 -t 20
```

### # 5. Extract URLs from GoSpider output

```bash
find gooutput -name "*.txt" -exec cat {} \; | grep -oE 'https?://[^ ]+' | anew gospider-urls.txt
```

### # 6. Merge crawl results

```bash
cat waygauurls.txt crawledurls.txt | uro > katanaurls.txt
cat waygauurls.txt cleansubskatanaurls.txt hakcrawlurls.txt | uro > katanaurls.txt
```

## Filter URLs by Domain

Use `filter.sh` to filter URLs from katana output that belong to your target domain.

### Create the filter script

```bash
nano filter.sh
chmod +x filter.sh
```

```bash
#!/bin/bash

input_file="katanaurls.txt"
output_file="crawledurls.txt"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' not found in the current directory."
    exit 1
fi

# Prompt user for domain
read -p "Enter domain to filter (e.g., example.com): " domain

# Exit if no domain entered
if [ -z "$domain" ]; then
    echo "No domain entered. Exiting."
    exit 1
fi

# Escape dots in the domain for regex
escaped_domain=$(printf '%s\n' "$domain" | sed 's/\./\\./g')

# Filter URLs belonging to the domain
grep -E -i "https?://([a-zA-Z0-9.-]+\.)?$escaped_domain([/:?]|$)" "$input_file" > "$output_file"

echo "Filtered URLs saved to $output_file"
```

### Usage

```bash
# Run the filter
./filter.sh

# Enter domain: example.com
# Filtered URLs saved to crawledurls.txt
```

## Screenshot for Visual Recon

Get live host IPs from subenum results, reverse DNS lookup, then screenshot.

```bash
# 1. Get IPs from alive-domains.txt (from subenum results)
dnsx -l alive-domains.txt -a -resp-only -o ips.txt

# 2. DNS PTR record lookup
cat ips.txt | dnsx -retry 3 -threads 300 -stats -silent -resp-only -ptr | tee -a dnsx.txt

# 3. Screenshot with gowitness
./gowitness scan file -f dnsx.txt --screenshot-path ./screenshots --threads 10 --timeout 60 --screenshot-fullpage --write-db --write-jsonl
```

## References

