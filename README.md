# Stack Fingerprinter

A modular web reconnaissance toolkit that fingerprints a target's technology stack,
brute-forces and discovers content, correlates every finding into prioritized
attack hypotheses, and renders the whole picture as an interactive attack graph.

It wraps the standard recon tools (`nmap`, `feroxbuster`, `subfinder`, `ffuf`) behind
one consistent CLI, and adds a correlation engine of **580+ signatures** that turns raw
scan output ("here is a path, here is a header") into actionable, stack-aware leads
("`/compose` on a Flask app → server-side template injection via Jinja2").

Everything is pure Python (one dependency: `requests`) plus optional external binaries,
and every subcommand writes JSON so stages compose freely.

---

## Highlights

- **Stack fingerprinting** from HTTP headers, cookies and open ports, with a confidence
  score derived from the number of independent signals.
- **Correlation engine** — 585 path signatures + parameter/cookie/header/port databases map
  findings to prioritized vulnerability hypotheses (CRITICAL → LOW).
- **Entry-point awareness** — request parameters map to vulnerability classes (`?file` → LFI,
  `?url` → SSRF, `?cmd` → command injection), and numeric/UUID path segments (`/user/123`)
  are surfaced as IDOR / broken-object-level-authorization targets.
- **Stack-aware hypotheses** — the same path is refined by the detected stack: SSTI becomes
  *Jinja2* on Python, *Twig* on PHP, *Freemarker* on Java; file upload becomes *.php/.phtml*
  on PHP, *.jsp* on Java; SQL injection becomes *NoSQL* on Node.
- **Cookie hardening checks** — missing `HttpOnly` / `Secure` / `SameSite` flags are reported,
  and a session cookie without `HttpOnly` is flagged as stealable via XSS.
- **Class-aware vuln signals** — SSRF/OAuth parameters (`?img_url`, `?redirect_uri`,
  `?response_type`, …) and functional endpoints (`/oauth/authorize`, `/soap`, `/graphql`,
  `/webhook`) map to SSRF / XXE / OAuth / deserialization hypotheses. Two signals that static
  signatures can't express are probed live: a **permissive CORS** policy (reflected / `null` /
  `*` Origin, with credentials) and **serialized objects in cookies** (PHP `O:`, Java `rO0`,
  Python pickle, ASP.NET `__VIEWSTATE`) flagged as insecure deserialization.
- **Evidence-gating** — a path-specific finding (e.g. Werkzeug `/console` RCE) is suppressed
  when the tool actually checked that path and it returned 404, instead of crying wolf.
- **Auth-gated detection** — `301/302 → login`, `401`, `403` routes are surfaced as
  post-authentication targets, not dumped into noise.
- **Interactive attack graph** — a dependency-free single-file HTML: pan/zoom, drag,
  per-node status (testing / exploited / failed), hide/restore and collapse nodes to declutter,
  a swimlanes layout (one lane per host), search, priority/status filters, notes, a Markdown
  report with kill chain, and PNG export. State persists in `localStorage`.
- **Adaptive** — the graph only contains nodes for what was actually found; noise collapses
  into a single hub node so 50 discovered directories never turn it into a mess. On broad
  targets it renders the whole surface: root domain → subdomains → each host's ports → paths.

---

## Recon pipeline

```
subs / vhost        →  discover hosts (broad targets / lab boxes)
nmap                →  open ports, services, versions
fingerprint / scan  →  stack, database, WAF, vulnerabilities
dirs                →  content brute-force + per-path hypotheses
passive             →  robots / sitemap / JS endpoints & secrets (no brute)
graph               →  merge everything into an interactive attack graph
```

Subcommands are independent: fuzzing more directories never re-runs `nmap`, and every
stage saves JSON that later stages read.

---

## Installation

```bash
git clone https://github.com/dripentest/fingerprint
cd fingerprint
pip install -r requirements.txt        # only: requests
```

**Requirements**

- Python 3.10+
- `requests` (Python)
- External binaries, each needed only by the matching command:
  [`nmap`](https://nmap.org), [`feroxbuster`](https://github.com/epi052/feroxbuster),
  [`subfinder`](https://github.com/projectdiscovery/subfinder),
  [`ffuf`](https://github.com/ffuf/ffuf)

**Optional — a short alias** so it runs from anywhere:

```bash
alias fp='python3 /path/to/fingerprint/main.py'
```

---

## Usage

Run `fp` (or `python3 main.py`) with no arguments for the full help. Every command
writes its result as JSON into a **per-target folder** (`target.thm` → `target.thm/`), so a whole
engagement stays in one place and is removed by deleting that one folder.

### `scan` — stack + fingerprint in one run

```bash
fp scan --target target.thm
fp scan --target target.thm --port 5000 --no-nmap        # skip nmap, port known
fp scan --target target.thm --port 80,443,1337,8000-8100  # custom ports / ranges
```

`--port` accepts a comma-separated list and ranges (e.g. `21,22,1337,8000-8100`) in
`nmap`, `scan` and `fingerprint` — useful when the default top-1000 scan misses a
non-standard port.

### `nmap` — ports only

```bash
fp nmap --target target.thm                 # -> target.thm.nmap.json
fp nmap --from-xml existing-scan.xml         # parse an existing nmap -oX file
```

### `fingerprint` — HTTP stack detection + report

```bash
fp fingerprint --target target.thm --port 5000
```

```
target.thm:5000
──────────────
  stack      Python / Flask (Werkzeug)   medium
  database   SQLite, PostgreSQL, MySQL
  server     Werkzeug/2.0.2 Python/3.10.12
  cookies    session

paths
  /debug → 200

vulns
  HIGH    Flask SSTI (Jinja2)
  HIGH    Local file inclusion via parameters
  MEDIUM  Session cookie stealable via XSS (session: HttpOnly not set)

  missing    HSTS · CSP · cookie session: HttpOnly
  absent     /console        # checked and not present — not reported as a finding
```

Alongside the stack, `fingerprint` (and `scan`) actively probe ~65 sensitive paths and
report each one found with its severity and hypotheses (like `dirs` does). The set covers
information-disclosure files across stacks:

- **secrets / config** — `/.env`, `/.env.local`, `/config.php`, `/appsettings.json`,
  `/web.config`, `/.aws/credentials`, `/secrets.json`
- **dependency manifests** (version recon → CVEs) — `/composer.json`, `/composer.lock`,
  `/package.json`, `/package-lock.json`, `/yarn.lock`, `/requirements.txt`, `/pom.xml`,
  `/build.gradle`, `/Gemfile.lock`
- **VCS exposure** — `/.git/HEAD`, `/.git/config`, `/.svn/entries`, `/.DS_Store`
- **GraphQL** — `/graphql`, `/graphiql`, `/graphql-playground`, `/altair`, `/v1/graphql`
- **API specs** — `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`
- **framework debug / profilers** — `/phpinfo.php`, `/_profiler`, `/telescope`,
  `/trace.axd`, `/elmah.axd`, `/server-status`, `/metrics`
- **backups / CI / infra** — `/backup.sql`, `/dump.sql`, `/docker-compose.yml`,
  `/.gitlab-ci.yml`, `/terraform.tfstate`

It also inspects cookie security flags (`HttpOnly` / `Secure` / `SameSite`), probes the CORS
policy by sending a throwaway `Origin` and checking whether it is reflected (or `null` / `*`)
together with `Access-Control-Allow-Credentials`, and inspects cookie values for serialized
objects (PHP / Java / Python pickle) and `__VIEWSTATE` — both reported as findings.

### `dirs` — content brute-force with per-path hypotheses

```bash
fp dirs --target target.thm --port 5000 -w wordlist.txt --graph
fp dirs --target target.thm --port 5000 -w big.txt -t 40 -d 1   # 40 threads, shallow recursion
fp dirs --target target.thm --port 5000 --from-ferox ferox.json  # import a feroxbuster --json run
```

Like `nmap --from-xml`, the brute-forcing stages can **import an existing tool run**
instead of launching the tool themselves (`dirs --from-ferox`, `vhost --from-ffuf`,
`subs --from-txt`) — run the underlying tool with whatever flags you like, then feed its
output in to get the correlation, hypotheses and graph on top.

`Ctrl+C` stops the scan and keeps what was found. Each discovered path is correlated to
hypotheses and grouped by severity; auth-gated routes and unsignatured noise are separated.

### `subs` — subdomain enumeration (broad targets)

```bash
fp subs --target example.com
fp subs --target example.com --from-txt names.txt   # run liveness over names you already have
```

Runs `subfinder` (passive) then resolves and HTTP-probes every name, splitting results into
**live web hosts**, **resolve-but-no-web**, and **dead** — the `subfinder | httpx` pattern in
one command (subfinder alone does not verify liveness).

### `vhost` — virtual-host brute-force (lab boxes)

```bash
fp vhost --target target.thm --port 80 -w subdomains.txt --ip 10.10.1.5
fp vhost --target target.thm --port 80 --from-ffuf ffuf.json   # import an ffuf -of json run
```

Fuzzes the `Host` header (`Host: FUZZ.target.thm`) with `ffuf` against the box, using
auto-calibration to filter the default vhost's baseline. For targets that are not in public
DNS or passive sources.

### `passive` — passive recon (no brute-force)

```bash
fp passive --target target.thm --port 5000 --graph
```

Pulls paths from `robots.txt` / `sitemap.xml` and greps same-host JavaScript for endpoints
and leaked secrets (AWS/GCP/Slack/Stripe/GitHub keys, private keys, JWTs). JS is
pattern-matched, never executed.

### `graph` — interactive attack graph

```bash
# single host
fp graph --target target.thm \
  --nmap-json target.thm/target.thm.nmap.json \
  --dirs-json target.thm/target.thm-5000.dirs.json

# whole company: root domain -> subdomains -> their ports -> paths
fp graph --target example.com \
  --subs-json example.com/example.com.subs.json \
  --nmap-json app.example.com/app.example.com.nmap.json --nmap-json api.example.com/api.example.com.nmap.json \
  --dirs-json app.example.com/app.example.com-443.dirs.json --dirs-json api.example.com/api.example.com-443.dirs.json \
  --passive-json app.example.com/app.example.com-443.passive.json
```

Merges saved results (and an optional live fingerprint) into a single self-contained HTML
file. `--nmap-json` / `--dirs-json` / `--passive-json` are repeatable and routed to their
host, so a broad target renders as one graph: the root domain, every discovered subdomain,
each host's ports, and their paths and vulnerabilities. Open it in any browser — no server required.

**Graph controls:** drag background to pan, wheel to zoom, drag nodes to arrange,
double-click for details, right-click a node to set status, **collapse** its hypotheses
(they fold into a `+N` badge) or **hide** it (noise directories disappear, and hypotheses
orphaned by the hide go with them — restore any of them from the **Hidden** button),
right-click the background to add a note. Search and the priority/status filters dim
everything else. **Swimlanes** switches the layout so each host gets its own horizontal lane
(no cross-host tangle on broad targets); **Report** exports a Markdown findings report with a
kill chain built from the nodes marked exploited; **PNG** exports a report-ready image. Layout
choice, statuses, notes, collapsed and hidden nodes are saved per target in `localStorage`.

---

## How it works

**Signature databases** (`data/*.json`) map observations to stack, database and
vulnerability candidates:

- `path_signatures.json` — 585 keyword signatures (substring-matched, so `/api/internal/users`
  matches too; a keyword may carry an `except` list to avoid a collision, e.g. `compose`
  does not fire inside `composer.json`) covering authentication, account/access-control, admin,
  APIs, file operations, injection surfaces, SSRF, debug/dev/internal, monitoring, CMS, cloud,
  sensitive files and more.
- `param_signatures.json` — request-parameter names mapped to vulnerability classes
  (`file`/`path` → LFI, `url`/`img_url`/`webhook` → SSRF, `cmd`/`ping` → command injection,
  `redirect_uri`/`response_type`/`state` → OAuth abuse, `soap`/`xml` → XXE,
  `object`/`viewstate` → insecure deserialization, …).
- `cookie_signatures.json` / `header_signatures.json` — framework detection (PHPSESSID → PHP,
  `connect.sid` → Node/Express, `Server: Werkzeug` → Flask, …).
- `port_signatures.json`, `priority.json`, `waf_signatures.json`, `interesting_paths.json`.

**The correlation engine** (`analyzer.py`, `graph_builder.py`) combines these: it scores stack
confidence, gathers database candidates, ranks vulnerabilities by severity, gates path-specific
findings on actual path presence, and refines generic hypotheses with the detected stack. The
result is a node/edge graph rendered by a dependency-free SVG engine (`renderer.py`).

---

## Project layout

```
main.py            CLI entry point (subcommands)
nmap_parser.py     parse nmap -oX into ports/services/OS
fingerprinter.py   HTTP fingerprint: headers, cookies, paths, WAF
signatures.py      load signature DBs, path/WAF matching
analyzer.py        correlate signals -> stack/db/prioritized vulns
confidence.py      stack-confidence scoring
dir_bruteforce.py  feroxbuster wrapper (content brute-force)
subs.py            subfinder wrapper + liveness check
vhost.py           ffuf Host-header vhost brute-force
passive.py         robots/sitemap/JS passive recon
graph_builder.py   build the adaptive attack graph (nodes/edges)
renderer.py        standalone interactive HTML graph engine
reporter.py        minimalist console report
data/*.json        signature databases
```

---

## Tests

Pure-stdlib `unittest`, no extra dependencies — they cover the matching engine
(keyword collisions, per-hypothesis priority, id-segment heuristics, params,
stack refinement) and the parsing/active-check helpers:

```bash
python3 -m unittest discover -s tests
```

---

## Disclaimer

For use only against systems you are explicitly authorized to test — CTF/lab boxes,
your own infrastructure, or engagements with written permission. You are responsible for
how you use it.
