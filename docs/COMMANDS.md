# Commands & Workflows

Every command is independent and writes JSON into a per-target folder, so stages
compose freely. Run `fp <command> -h` for the full flag list.

Global convention — each command that launches an external tool can instead
**import** an existing run of that tool (your own flags), and the HTTP-native
commands accept `--proxy` / `-H/--header` / `--cookie`.

---

## Capabilities at a glance

| Command | Capability | Needs | Output |
|---------|-----------|-------|--------|
| `scan` | nmap + HTTP fingerprint in one go (quick start) | nmap* | `<host>-<port>.fp.json` |
| `nmap` | ports / services / versions | nmap* | `<host>.nmap.json` |
| `fingerprint` | stack · DB · WAF · CORS · deserialization · sensitive paths | — | `<host>-<port>.fp.json` |
| `dirs` | content brute-force + per-path hypotheses | feroxbuster* | `<host>-<port>.dirs.json` |
| `subs` | subdomain enumeration + liveness | subfinder* | `<host>.subs.json` |
| `vhost` | virtual-host brute-force (Host-header fuzzing) | ffuf* | `<host>-<port>.vhost.json` |
| `passive` | robots/sitemap paths + JS endpoints & secrets | — | `<host>-<port>.passive.json` |
| `graph` | merge saved artifacts into an interactive attack graph | — | `<host>.graph.html` |

\* optional — the tool can be imported from a file instead (see each command).

---

## `scan` — stack + fingerprint in one run
```bash
fp scan --target target.thm                       # nmap finds ports, HTTP ports fingerprinted
fp scan --target target.thm --port 5000 --no-nmap # skip nmap, port known
fp scan --target target.thm --port 80,443,8000-8100
fp scan --target app.thm --no-nmap --port 443 --proxy http://127.0.0.1:8080
```
`--port` takes comma lists and ranges. Scheme (http/https) is chosen from the port
and the nmap service. Saves one `.fp.json` per HTTP port.

## `nmap` — ports only
```bash
fp nmap --target target.thm                        # -> target.thm/target.thm.nmap.json
fp nmap --target target.thm --port 21,22,1337,8000-8100
fp nmap --from-xml existing-scan.xml --target box  # import an nmap -oX file (your own flags)
```
Run nmap your way and import it:
```bash
nmap -sV -sC -p- -oX box.xml target.thm
fp nmap --from-xml box.xml --target target.thm
```
A multi-host XML keeps each host's own ports (not blended).

## `fingerprint` — HTTP stack detection + report
```bash
fp fingerprint --target target.thm --port 5000
fp fingerprint --target target.thm --port 80,443,8080      # ports run concurrently
fp fingerprint --target app.thm --port 443 -H "Authorization: Bearer <jwt>"
fp fingerprint --target app.thm --port 443 --cookie "session=<cookie>"
fp fingerprint --target target.thm --port 5000 --nmap-json target.thm/target.thm.nmap.json
```
Actively probes ~65 sensitive paths (secrets, dependency manifests, VCS exposure,
GraphQL, API specs, framework profilers, backups), inspects cookie flags, and runs
the live CORS and deserialization checks. Soft-404 hosts are calibrated out.

## `dirs` — content brute-force with per-path hypotheses
```bash
fp dirs --target target.thm --port 5000 -w wordlist.txt --graph
fp dirs --target target.thm --port 5000 -w big.txt -t 40 -d 1        # 40 threads, depth 1
fp dirs --target app.thm --port 443 -w wl.txt --proxy http://127.0.0.1:8080 \
        -H "Authorization: Bearer <jwt>"                              # behind auth, via Burp
fp dirs --target target.thm --port 5000 --from-ferox ferox.json      # import an existing run
```
Run feroxbuster your way and import it:
```bash
feroxbuster -u http://target.thm:5000 -w wl.txt --json -o ferox.json
fp dirs --target target.thm --port 5000 --from-ferox ferox.json
```
`Ctrl+C` stops a live scan and keeps what was found.

## `subs` — subdomain enumeration (broad targets)
```bash
fp subs --target example.com
fp subs --target example.com --from-txt names.txt   # liveness over names you already have
```
Import your own subfinder output:
```bash
subfinder -d example.com -silent -o names.txt
fp subs --target example.com --from-txt names.txt
```
Splits results into live web hosts / resolve-but-no-web / dead.

## `vhost` — virtual-host brute-force (lab boxes)
```bash
fp vhost --target target.thm --port 80 -w subdomains.txt --ip 10.10.1.5
fp vhost --target target.thm --port 80 -w subs.txt -fs 1234      # filter a baseline size
fp vhost --target target.thm --port 80 --from-ffuf ffuf.json     # import an existing run
```
Run ffuf your way and import it:
```bash
ffuf -w subs.txt:FUZZ -u http://10.10.1.5/ -H "Host: FUZZ.target.thm" -ac -of json -o ffuf.json
fp vhost --target target.thm --port 80 --from-ffuf ffuf.json
```

## `passive` — passive recon (no brute-force)
```bash
fp passive --target target.thm --port 5000 --graph
fp passive --target app.thm --port 443 --cookie "session=<cookie>"
```
Pulls paths from `robots.txt` / `sitemap.xml` (follows nested sitemaps) and greps
same-host JavaScript for endpoints and leaked secrets (AWS/GCP/Slack/Stripe/GitHub
keys, private keys, JWTs). JS is pattern-matched, never executed.

## `graph` — interactive attack graph
```bash
# single host, fully offline from saved artifacts
fp graph --target target.thm --no-fingerprint \
  --nmap-json target.thm/target.thm.nmap.json \
  --dirs-json target.thm/target.thm-5000.dirs.json \
  --fingerprint-json target.thm/target.thm-5000.fp.json

# whole company: root -> subdomains -> their ports -> paths
fp graph --target example.com \
  --subs-json example.com/example.com.subs.json \
  --nmap-json app.example.com/app.example.com.nmap.json \
  --dirs-json app.example.com/app.example.com-443.dirs.json \
  --passive-json app.example.com/app.example.com-443.passive.json
```
`--nmap-json` / `--dirs-json` / `--passive-json` / `--fingerprint-json` are
repeatable and routed to their host. `--fingerprint-json` renders stack/CORS/deser
findings without a live re-scan; `--no-fingerprint` makes the whole graph offline.
Open the HTML in any browser — no server required.

---

## HTTP options (fingerprint / scan / dirs / passive)

| Flag | Purpose |
|------|---------|
| `--proxy http://127.0.0.1:8080` | Route requests through a proxy (e.g. Burp) to see/replay them. |
| `-H, --header 'Name: value'` | Extra request header (repeatable) — e.g. a bearer token for authenticated recon. |
| `--cookie 'a=b; c=d'` | Cookie header to reach areas behind login. |

---

## Typical workflows

**Single box (CTF / lab):**
```bash
fp scan    --target target.thm                                   # what stack, where to dig
fp nmap    --target target.thm -o t.nmap.json                    # ports (once)
fp passive --target target.thm --port 80 --graph                 # robots/sitemap/JS leads
fp dirs    --target target.thm --port 80 -w wl.txt --graph       # content + hypotheses
fp graph   --target target.thm --nmap-json target.thm/target.thm.nmap.json \
           --dirs-json target.thm/target.thm-80.dirs.json \
           --fingerprint-json target.thm/target.thm-80.fp.json
```

**Broad target (company):**
```bash
fp subs  --target example.com                                    # live subdomains
fp nmap  --target app.example.com                                # per host
fp dirs  --target app.example.com --port 443 -w wl.txt
fp graph --target example.com --subs-json … --nmap-json … --dirs-json …
```

**Authenticated recon through Burp:**
```bash
fp fingerprint --target app.thm --port 443 \
  --proxy http://127.0.0.1:8080 -H "Authorization: Bearer <jwt>"
fp dirs --target app.thm --port 443 -w wl.txt \
  --proxy http://127.0.0.1:8080 --cookie "session=<cookie>"
```
