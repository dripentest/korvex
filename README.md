# Korvex

A modular web-reconnaissance toolkit that fingerprints a target's technology
stack, brute-forces and discovers content, correlates every finding into
**prioritised, stack-aware attack hypotheses**, and renders the whole picture as
an interactive attack graph.

It wraps the standard recon tools (`nmap`, `feroxbuster`, `subfinder`, `ffuf`)
behind one consistent CLI and adds a correlation engine of **580+ signatures**
that turns raw scan output ("here is a path, here is a header") into actionable
leads — `/compose` on a Flask app → *server-side template injection via Jinja2*.

Pure Python, one runtime dependency (`requests`); external scanners are optional
and each can be imported from a file instead of launched. Every stage writes
JSON, so the pipeline composes freely.

---

## Highlights

- **Correlation engine** — path/parameter/cookie/header/port signature databases
  map findings to prioritised hypotheses (CRITICAL → LOW), each carrying its own
  severity.
- **Stack-aware** — a hypothesis is refined by the detected stack: SSTI → Jinja2
  (Python) / Twig (PHP) / Freemarker (Java); file upload → `.php`/`.jsp`/`.aspx`;
  SQLi → NoSQL (Node).
- **Vuln-class signals** — SSRF/OAuth parameters and functional endpoints
  (`/oauth/authorize`, `/soap`, `/graphql`, `/webhook`) map to SSRF/XXE/OAuth/
  deserialization leads. Two signals static rules can't express are probed live:
  **permissive CORS** (reflected/`null`/`*` origin with credentials) and
  **serialized objects in cookies** (PHP `O:`, Java `rO0`, pickle, `__VIEWSTATE`).
- **Low-noise by design** — soft-404 / blanket-auth hosts are calibrated out,
  path-specific findings are evidence-gated, auth-gated routes are separated, and
  unsignatured noise collapses into a single hub node.
- **Sensible defaults** — http/https autodetected per port and nmap service;
  `--proxy` / `-H` / `--cookie` for Burp and authenticated recon.
- **Interactive attack graph** — one dependency-free HTML file: pan/zoom, drag,
  per-node status, hide/collapse, swimlanes, search/filter, notes, a Markdown
  kill-chain report and PNG export. State persists in `localStorage`.

---

## Install

```bash
git clone https://github.com/dripentest/fingerprint.git
cd fingerprint
pip install -r requirements.txt        # only: requests
```

**Requirements**

- Python 3.10+
- `requests`
- Optional external binaries, each needed only by its command (or importable from
  a saved file): [`nmap`](https://nmap.org),
  [`feroxbuster`](https://github.com/epi052/feroxbuster),
  [`subfinder`](https://github.com/projectdiscovery/subfinder),
  [`ffuf`](https://github.com/ffuf/ffuf)

Optional alias so it runs from anywhere:

```bash
alias korvex='python3 /path/to/korvex/main.py'
```

---

## Quick start

```bash
korvex scan    --target target.thm                              # stack + where to dig
korvex dirs    --target target.thm --port 80 -w wordlist.txt    # content + per-path hypotheses
korvex passive --target target.thm --port 80                    # robots/sitemap/JS leads
korvex graph   --target target.thm \
           --nmap-json target.thm/target.thm.nmap.json \
           --dirs-json target.thm/target.thm-80.dirs.json \
           --fingerprint-json target.thm/target.thm-80.fp.json
```

Each run writes JSON into a per-target folder (`target.thm/`); `graph` merges
those artifacts into `target.thm/target.thm.graph.html` — open it in any browser.

---

## Commands

| Command | What it does |
|---------|--------------|
| `scan` | nmap + HTTP fingerprint in one run (quick start) |
| `nmap` | ports / services / versions → JSON |
| `fingerprint` | stack · DB · WAF · CORS · deserialization · sensitive paths |
| `dirs` | content brute-force + per-path hypotheses |
| `subs` | subdomain enumeration + liveness |
| `vhost` | virtual-host brute-force (Host-header fuzzing) |
| `passive` | robots/sitemap paths + endpoints & secrets from linked JS |
| `graph` | merge saved artifacts into an interactive attack graph |

Every tool-launching command can **import** a run you made yourself
(`--from-xml` / `--from-ferox` / `--from-ffuf` / `--from-txt`). Run `korvex -h` or
`korvex <command> -h` for the full flags, examples (incl. `nmap` / `feroxbuster` /
`ffuf`) and end-to-end workflows.

---

## How it works

Signature databases (`data/*.json`) map observations to stack, database and
vulnerability candidates; the correlation engine scores stack confidence, ranks
vulnerabilities, gates path-specific findings on actual presence, and refines
generic hypotheses with the detected stack. The result is a node/edge graph
rendered by a dependency-free HTML engine.

The core loop is *discovered path → `match_path()` → prioritised, stack-refined
hypotheses → graph nodes*.

---

## Tests

Pure-stdlib `unittest`, no extra dependencies:

```bash
python3 -m unittest discover -s tests
```

They cover the matching engine (keyword collisions, per-hypothesis priority,
id-segment heuristics, parameters, stack refinement) and the parsing / active-check
helpers.

---

## Disclaimer

This tool is provided for authorised security testing and educational use only.
Use it **only** against systems you own or have explicit, written permission to
test (CTF/lab boxes, your own infrastructure, or a scoped engagement).

**All responsibility for using this tool lies entirely with the user.** You are
solely responsible for ensuring your use is legal and authorised. Running it
against systems without permission may be illegal. The authors and contributors
accept no liability for any misuse, damage, or consequences arising from its use,
and provide no warranty of any kind — see the [license](LICENSE).

---

## License

Released under the [MIT License](LICENSE).
