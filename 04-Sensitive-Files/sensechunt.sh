#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD_BLUE='\033[1;34m'
DARK_BLUE='\033[0;90m'
BOLD='\033[1m'
RESET='\033[0m'
NC='\033[0m'

SECRET_PATTERN="password|api_key|apikey|secret|token|private key|aws_access|db_pass|credential|jwt|bearer|access_key|secret_key|client_secret|refresh_token|authorization|Basic |Bearer |mongodb://|postgresql://|mysql://|redis://|smtp|passwd|pwd"

BANNER="\n"
BANNER+="${BLUE}  ◉━━◉              ${RESET}\n"
BANNER+="${BLUE} ╱    ╲             ${RESET}\n"
BANNER+="${BLUE}◉      ◉━━◉    ${BOLD_BLUE}sensechunt${RESET}\n"
BANNER+="${CYAN} ╲    ╱         ${CYAN}Sensitive File Hunter${RESET}\n"
BANNER+="${CYAN}  ◉━━◉          ${DARK_BLUE}by ~/.manojxshrestha${RESET}\n"
BANNER+="${CYAN}       ╲        ${RESET}\n"
BANNER+="${CYAN}        ◉       ${RESET}\n"

for tool in httpx curl; do
    if ! command -v $tool &>/dev/null; then
        echo -e "${RED}[!] $tool not installed${NC}"
        exit 1
    fi
done

echo -e "$BANNER"
echo ""

read -p "Enter path to alive-domains.txt: " DOMAINS_FILE
read -p "Enter path to crawledurls.txt: " CRAWLED_FILE
read -p "Enter path to https-subs.txt: " HTTPS_FILE

if [ ! -f "$DOMAINS_FILE" ]; then
    echo -e "${RED}[!] File not found: $DOMAINS_FILE${NC}"
    exit 1
fi

if [ ! -f "$CRAWLED_FILE" ]; then
    echo -e "${RED}[!] File not found: $CRAWLED_FILE${NC}"
    exit 1
fi

if [ ! -f "$HTTPS_FILE" ]; then
    echo -e "${RED}[!] File not found: $HTTPS_FILE${NC}"
    exit 1
fi

mkdir -p results/raw

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 1/6:${YELLOW} CONFIG & SECRET PROBING"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $DOMAINS_FILE | sed -E 's#^https?://([^:/]+).*#\1#' | sort -u | while read host; do"
echo -e "    [ -z \"\$host\" ] && continue"
echo -e "    for path in /config.js /config.json /app/config.js /settings.json /database.json"
echo -e "                 /firebase.json /.env /.env.production /.env.local /.env.example"
echo -e "                 /.env.bak /.env.backup /api-keys.json /credentials.json /secret.json"
echo -e "                 /google-services.json /package.json /package-lock.json /composer.json"
echo -e "                 /po.xml /docker-compose.yml /manifest.json /service-worker.js"
echo -e "                 /config.yml /config.yaml /config.xml /config.php /web.config"
echo -e "                 /config.bak /config.example /config/secrets.json /config/keys.json"
echo -e "                 /_wpeprivate/config.json /.git/config; do"
echo -e "        echo \"http://\${host}\${path}\""
echo -e "        echo \"https://\${host}\${path}\""
echo -e "    done"
echo -e "done | httpx -mc 200,301,302 -silent -retries 2 -threads 100 -delay 500ms \\"
echo -e "| awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    if curl -s -L -k --max-time 8 \"\$url\" | grep -Eqi \"$SECRET_PATTERN\"; then"
echo -e "        echo \"\$url\""
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/results.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$DOMAINS_FILE" | sed -E 's#^https?://([^:/]+).*#\1#' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /config.js /config.json /app/config.js /settings.json /database.json /firebase.json /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /api-keys.json /credentials.json /secret.json /google-services.json /package.json /package-lock.json /composer.json /po.xml /docker-compose.yml /manifest.json /service-worker.js /config.yml /config.yaml /config.xml /config.php /web.config /config.bak /config.example /config/secrets.json /config/keys.json /_wpeprivate/config.json /.git/config; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302 -retries 2 -threads 100 -delay 500ms \
| awk '{print $1}' \
| while read url; do
    if curl -s -L -k --max-time 8 "$url" 2>/dev/null | grep -Eqi "$SECRET_PATTERN"; then
        echo "$url"
    fi
    sleep 0.2
done | tee results/raw/results.txt | while read url; do echo -e "${GREEN}$url${NC}"; done

cp results/raw/results.txt results/results-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 2/6:${YELLOW} COMPREHENSIVE SENSITIVE FILE DISCOVERY"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $DOMAINS_FILE | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u"
echo -e "    | while read host; do"
echo -e "    [ -z \"\$host\" ] && continue"
echo -e "    for path in /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup"
echo -e "                 /.env.test /.env.staging /.env.development /.env.old /.env.save /.env.tmp"
echo -e "                 /config.json /config.php /web.config /api-keys.json /credentials.json"
echo -e "                 /secret.json /secrets.json /database.json /firebase.json /google-services.json"
echo -e "                 /config.yaml /config.yml /appsettings.json /configuration.json /settings.json"
echo -e "                 /wp-config.php /config.inc.php /db.config /database.yml /config/database.yml"
echo -e "                 /backup.sql /dump.sql /backup.zip /dump.tar /backup.rar /dump.rar"
echo -e "                 /.git/config /.svn/entries /CVS/Entries /_wpeprivate/config.json"
echo -e "                 /admin/config.json /api/config.json /app/config.json /src/config.json"
echo -e "                 /includes/config.php /inc/config.php /system/config.php"
echo -e "                 /application/config.php /app/config/database.json /app/config/secrets.json; do"
echo -e "        echo \"http://\${host}\${path}\""
echo -e "        echo \"https://\${host}\${path}\""
echo -e "    done"
echo -e "done | httpx -mc 200,301,302 -retries 2 -threads 100 -delay 500ms \\"
echo -e "| awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    if curl -s -L -k --max-time 8 \"\$url\" | grep -Eqi \"$SECRET_PATTERN\"; then"
echo -e "        echo \"\$url\""
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/leaks.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$DOMAINS_FILE" | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /.env.test /.env.staging /.env.development /.env.old /.env.save /.env.tmp /config.json /config.php /web.config /api-keys.json /credentials.json /secret.json /secrets.json /database.json /firebase.json /google-services.json /config.yaml /config.yml /appsettings.json /configuration.json /settings.json /wp-config.php /config.inc.php /db.config /database.yml /config/database.yml /backup.sql /dump.sql /backup.zip /dump.tar /backup.rar /dump.rar /.git/config /.svn/entries /CVS/Entries /_wpeprivate/config.json /admin/config.json /api/config.json /app/config.json /src/config.json /includes/config.php /inc/config.php /system/config.php /application/config.php /app/config/database.json /app/config/secrets.json; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302 -retries 2 -threads 100 -delay 500ms \
| awk '{print $1}' \
| while read url; do
    if curl -s -L -k --max-time 8 "$url" 2>/dev/null | grep -Eqi "$SECRET_PATTERN"; then
        echo "$url"
    fi
    sleep 0.2
done | tee results/raw/leaks.txt | while read url; do echo -e "${GREEN}$url${NC}"; done

cp results/raw/leaks.txt results/leaks-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 3/6:${YELLOW} TARGETED SENSITIVE FILE CHECKS"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $CRAWLED_FILE | httpx -silent -threads 100 \\"
echo -e "    -path /.env,/config.php,/wp-config.php.bak,/.htaccess,/server-status \\"
echo -e "    -mc 200 -delay 500ms | awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    if curl -s -L -k --max-time 8 \"\$url\" | grep -Eqi \"$SECRET_PATTERN\"; then"
echo -e "        echo \"\$url\""
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/sensitive.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$CRAWLED_FILE" | httpx -threads 100 -path /.env,/config.php,/wp-config.php.bak,/.htaccess,/server-status -mc 200 -delay 500ms | awk '{print $1}' \
| while read url; do
    if curl -s -L -k --max-time 8 "$url" 2>/dev/null | grep -Eqi "$SECRET_PATTERN"; then
        echo "$url"
    fi
    sleep 0.2
done | tee results/raw/sensitive.txt | while read url; do echo -e "${GREEN}$url${NC}"; done

cp results/raw/sensitive.txt results/sensitive-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 4/6:${YELLOW} SOURCE CODE & VCS EXPOSURE"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $CRAWLED_FILE | httpx -silent -threads 100 \\"
echo -e "    -path /.svn/entries,/.bzr/README,/CVS/Root -mc 200 -delay 500ms \\"
echo -e "    | awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    if curl -s -L -k --max-time 8 \"\$url\" | grep -Eqi \"$SECRET_PATTERN\"; then"
echo -e "        echo \"\$url\""
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/vcs-exposed.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$CRAWLED_FILE" | httpx -threads 100 -path /.svn/entries,/.bzr/README,/CVS/Root -mc 200 -delay 500ms | awk '{print $1}' \
| while read url; do
    if curl -s -L -k --max-time 8 "$url" 2>/dev/null | grep -Eqi "$SECRET_PATTERN"; then
        echo "$url"
    fi
    sleep 0.2
done | tee results/raw/vcs-exposed.txt | while read url; do echo -e "${GREEN}$url${NC}"; done

cp results/raw/vcs-exposed.txt results/vcs-exposed-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 5/6:${YELLOW} DATABASE FILES"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $CRAWLED_FILE | httpx -silent -threads 100 \\"
echo -e "    -path /database.sql,/db.sql,/backup.sql,/dump.sql -mc 200 -delay 500ms \\"
echo -e "    | awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    if curl -s -L -k --max-time 8 \"\$url\" | grep -Eqi \"$SECRET_PATTERN\"; then"
echo -e "        echo \"\$url\""
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/db-files.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$CRAWLED_FILE" | httpx -threads 100 -path /database.sql,/db.sql,/backup.sql,/dump.sql -mc 200 -delay 500ms | awk '{print $1}' \
| while read url; do
    if curl -s -L -k --max-time 8 "$url" 2>/dev/null | grep -Eqi "$SECRET_PATTERN"; then
        echo "$url"
    fi
    sleep 0.2
done | tee results/raw/db-files.txt | while read url; do echo -e "${GREEN}$url${NC}"; done

cp results/raw/db-files.txt results/db-files-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  ${CYAN}SCAN 6/6:${YELLOW} LOG FILES & DEBUG LEAKAGE"
echo -e "==========================================${NC}"
echo ""
echo -e "${RED}Command:"
echo -e "cat $HTTPS_FILE | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u \\"
echo -e "    | while read host; do"
echo -e "    [ -z \"\$host\" ] && continue"
echo -e "    echo \"\$host/app.log\""
echo -e "    echo \"\$host/error.log\""
echo -e "    echo \"\$host/access.log\""
echo -e "    ... (27 log paths) ..."
echo -e "done | sort -u | httpx -mc 200 -fr -rl 50 -threads 50 -silent -delay 500ms \\"
echo -e "| awk '{print \$1}' \\"
echo -e "| while read url; do"
echo -e "    content=\$(curl -s -L -k --max-time 10 \"\$url\")"
echo -e "    if echo \"\$content\" | grep -Eqi \"$SECRET_PATTERN|error|exception|...\"; then"
echo -e "        echo \"==== \$url ====\""
echo -e "        echo \"\$content\" | head -20"
echo -e "    fi"
echo -e "    sleep 0.2"
echo -e "done | tee results/raw/log-leaks.txt${NC}"
echo ""
echo -e "${CYAN}[*] Running scan...${NC}"

cat "$HTTPS_FILE" | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u | while read host; do
    [ -z "$host" ] && continue
    echo "$host/app.log"
    echo "$host/error.log"
    echo "$host/access.log"
    echo "$host/debug.log"
    echo "$host/laravel.log"
    echo "$host/logs/error.log"
    echo "$host/logs/access.log"
    echo "$host/logs/production.log"
    echo "$host/logs/development.log"
    echo "$host/nginx/error.log"
    echo "$host/nginx/access.log"
    echo "$host/php_errors.log"
    echo "$host/php_error.log"
    echo "$host/wp-content/debug.log"
    echo "$host/backup/error.log"
    echo "$host/tmp/error.log"
    echo "$host/rails/log/production.log"
    echo "$host/rails/log/development.log"
    echo "$host/mail.log"
    echo "$host/auth.log"
    echo "$host/apache/error.log"
    echo "$host/apache/access.log"
    echo "$host/iis/logs/error.log"
    echo "$host/docker/logs/app.log"
    echo "$host/k8s/logs/pod.log"
    echo "$host/error.log.bak"
    echo "$host/logs/error.log.old"
    echo "$host/var/log/apache2/error.log"
done | sort -u | httpx -mc 200 -fr -rl 50 -threads 50 -delay 500ms \
| awk '{print $1}' \
| while read url; do
    content=$(curl -s -L -k --max-time 10 "$url" 2>/dev/null)
    if echo "$content" | grep -Eqi "$SECRET_PATTERN|error|exception|stacktrace|traceback|unauthorized|fatal|critical"; then
        echo "==== $url ===="
        echo "$content" | head -20
    fi
    sleep 0.2
done | tee results/raw/log-leaks.txt

grep "^==== " results/raw/log-leaks.txt | sed 's/^==== //; s/ ====$//' > results/log-leaks-bugs.txt

echo ""
echo -e "${YELLOW}${BOLD}=========================================="
echo -e "  SCAN COMPLETE"
echo -e "==========================================${NC}"
echo ""
echo -e "${GREEN}[+] Raw files saved to: results/raw/${NC}"
ls -la results/raw/
echo ""
echo -e "${GREEN}[+] Filtered results saved to: results/${NC}"
ls -la results/*.txt 2>/dev/null
echo ""
echo -e "${GREEN}[+] Summary:${NC}"
echo -e "    results-bugs.txt:     ${GREEN}$(wc -l < results/results-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo -e "    leaks-bugs.txt:       ${GREEN}$(wc -l < results/leaks-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo -e "    sensitive-bugs.txt:   ${GREEN}$(wc -l < results/sensitive-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo -e "    vcs-exposed-bugs.txt: ${GREEN}$(wc -l < results/vcs-exposed-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo -e "    db-files-bugs.txt:    ${GREEN}$(wc -l < results/db-files-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo -e "    log-leaks-bugs.txt:   ${GREEN}$(wc -l < results/log-leaks-bugs.txt 2>/dev/null || echo 0)${NC} findings"
echo ""
