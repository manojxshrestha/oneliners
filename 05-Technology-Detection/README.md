# Technology & Exposed Panel Detection

> Identify technologies and exposed administrative interfaces

## Technology Detection

```bash
cat https-subs.txt | httpx | nuclei -t technologies/tech-detect.yaml
```

## Exposed Panels

```bash
nuclei -l https-subs.txt -t http/exposed-panels/ -c 50 | anew panels.txt
```

## Debug Endpoints

```bash
cat https-subs.txt | httpx -silent -threads 100 -path /debug,/trace,/actuator,/metrics,/health,/info -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew debug-endpoints.txt
```

## Spring Boot Actuators

```bash
cat https-subs.txt | httpx -silent -threads 100 -path /actuator/env,/actuator/heapdump,/actuator/mappings -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew spring-actuators.txt
```

## WordPress Enumeration

```bash
cat https-subs.txt | httpx -silent -threads 100 -path /wp-json/wp/v2/users -mc 200 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew wp-users.txt
```

## Laravel Debug Mode

```bash
cat https-subs.txt | httpx -silent -threads 100 -match-string "Whoops" -match-string "Laravel" | anew laravel-debug.txt
```

## Django Debug

```bash
cat https-subs.txt | httpx -silent -threads 100 -match-string "Django" -match-string "DEBUG" | anew django-debug.txt
```

## Exposed Admin Panels

```bash
cat https-subs.txt | httpx -silent -threads 100 -path /admin,/administrator,/admin.php,/wp-admin,/manager,/phpmyadmin -mc 200,301,302 -cl | awk '$2 != 0 && $2 != 986 { print $1 }' | anew admin-panels.txt
```

## References

