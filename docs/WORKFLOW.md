# Korvex — Typical Workflows

Practical command sequences. Every stage writes JSON into a per-target folder
(`target.thm/`), so stages compose and can be re-run independently. Assumes the
alias `alias korvex='python3 /path/to/korvex/main.py'`.

Pipeline order:

```
subs / vhost  →  nmap  →  fingerprint / scan  →  dirs / passive  →  graph
 (find hosts)   (ports)   (stack, vulns)         (content, leads)   (merge)
```

---

## 1. Single box (CTF / lab)

```bash
# 1. quick triage — stack + sensitive paths (nmap + fingerprint)
korvex scan    --target target.thm

# 2. ports once (if you want the nmap artifact for the graph)
korvex nmap    --target target.thm                     # -> target.thm/target.thm.nmap.json

# 3. passive leads first (cheap, no brute): robots/sitemap + JS endpoints/secrets
korvex passive --target target.thm --port 80 --graph

# 4. content brute-force with per-path hypotheses
korvex dirs    --target target.thm --port 80 -w /usr/share/seclists/.../common.txt --graph

# 5. merge everything into one attack graph (offline, no re-scan)
korvex graph   --target target.thm --no-fingerprint \
               --nmap-json        target.thm/target.thm.nmap.json \
               --dirs-json        target.thm/target.thm-80.dirs.json \
               --passive-json     target.thm/target.thm-80.passive.json \
               --fingerprint-json target.thm/target.thm-80.fp.json
# open target.thm/target.thm.graph.html in a browser
```

Known port, skip nmap:
```bash
korvex scan --target target.thm --no-nmap --port 5000
```

---

## 2. Broad target (company / bug bounty)

```bash
# 1. live subdomains (subfinder + liveness)
korvex subs  --target example.com                      # -> example.com/example.com.subs.json

# 2. ports per live host
korvex nmap  --target app.example.com
korvex nmap  --target api.example.com

# 3. fingerprint + content per host
korvex scan  --target app.example.com --no-nmap --port 443
korvex dirs  --target app.example.com --port 443 -w wl.txt

# 4. one graph for the whole surface: root -> subdomains -> ports -> paths
korvex graph --target example.com \
             --subs-json        example.com/example.com.subs.json \
             --nmap-json        app.example.com/app.example.com.nmap.json \
             --nmap-json        api.example.com/api.example.com.nmap.json \
             --dirs-json        app.example.com/app.example.com-443.dirs.json \
             --fingerprint-json app.example.com/app.example.com-443.fp.json
```

---

## 3. Authenticated recon / through Burp

`--proxy`, `-H/--header` (repeatable) and `--cookie` work on
`scan` / `fingerprint` / `dirs` / `passive`.

```bash
# everything through Burp to see/replay the requests
korvex fingerprint --target app.thm --port 443 --proxy http://127.0.0.1:8080

# behind a login — pass a session cookie or bearer token
korvex fingerprint --target app.thm --port 443 --cookie "session=<cookie>"
korvex dirs        --target app.thm --port 443 -w wl.txt \
                   -H "Authorization: Bearer <jwt>" --proxy http://127.0.0.1:8080
```

---

## 4. Bring your own tool output (import mode)

Run the scanner with whatever flags you like, then feed its output in for
correlation + graphing (no need to have the binary on this machine):

```bash
nmap -sV -sC -p- -oX s.xml target.thm
korvex nmap  --from-xml s.xml   --target target.thm

feroxbuster -u http://target.thm:80 -w wl.txt --json -o fx.json
korvex dirs  --from-ferox fx.json --target target.thm --port 80

ffuf -w subs.txt:FUZZ -u http://10.10.1.5/ -H 'Host: FUZZ.target.thm' -ac -of json -o vh.json
korvex vhost --from-ffuf vh.json --target target.thm --port 80

subfinder -d example.com -silent -o names.txt
korvex subs  --from-txt names.txt --target example.com
```

---

## 5. Re-graphing without re-scanning

The graph is built from the saved JSON artifacts, so iterate freely:

```bash
# add a newly-fuzzed dir result to an existing engagement, no live traffic
korvex dirs  --target target.thm --port 80 -w bigger.txt
korvex graph --target target.thm --no-fingerprint \
             --nmap-json target.thm/target.thm.nmap.json \
             --dirs-json target.thm/target.thm-80.dirs.json \
             --fingerprint-json target.thm/target.thm-80.fp.json
```

---

## Reading the graph

Drag background to pan, wheel to zoom, drag nodes to arrange, double-click for
details, right-click a node to set status (testing / exploited / failed),
collapse its hypotheses, or hide noise. **Swimlanes** gives each host its own
lane; **Report** exports a Markdown findings report with a kill chain from nodes
marked exploited; **PNG** exports an image. Layout, statuses and notes persist in
`localStorage`.

Severity is per hypothesis (CRITICAL → LOW); unsignatured paths collapse into a
single hub node; auth-gated routes (30x/401/403) are shown separately. On a
soft-404 / blanket-auth host, path probing is suppressed and reported as a
`soft-404` note instead of flooding you with false positives.
