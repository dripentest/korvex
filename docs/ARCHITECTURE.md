# Architecture

Korvex is a modular web-reconnaissance toolkit. Its job is to turn
raw recon output — open ports, HTTP headers, cookies, discovered paths — into
**prioritised, stack-aware attack hypotheses** and render them as an interactive
attack graph. This document describes how the pieces fit together.

---

## 1. Design principles

- **JSON pipeline.** Every stage reads and/or writes a plain-JSON artifact, so
  stages compose freely and can be re-run independently (fuzzing more directories
  never re-runs `nmap`). The schemas are the contract between stages.
- **Data-driven correlation.** The knowledge lives in `data/*.json` signature
  databases, not in code. Adding a detection is a data edit, not a code change.
- **Dependency-light.** Pure Python; the only runtime dependency is `requests`.
  External scanners (`nmap`, `feroxbuster`, `ffuf`, `subfinder`) are optional and
  each is needed only by the matching command — and each can be *imported from a
  file* instead of launched.
- **Hypotheses, not verdicts.** The tool surfaces leads to check (ranked
  CRITICAL→LOW), it does not claim confirmed vulnerabilities. Noise collapses into
  a single hub node so volume never drowns signal.

---

## 2. The core flow

The heart of the project is a single, fast loop:

```
discovered path ──▶ match_path() ──▶ hypotheses (each with its own priority)
                                   └▶ graph vuln nodes, stack-refined
```

A path (from `dirs`, `passive`, or the active `fingerprint` probe) is matched
against the signature databases; each resulting hypothesis carries its own
severity and is attached, stack-refined, to the attack graph for the analyst to
verify.

Full engagement pipeline:

```
subs / vhost        discover hosts (subdomains / virtual hosts)
nmap                open ports, services, versions
fingerprint / scan  stack, DB, WAF, CORS, deserialization, sensitive paths
dirs                content brute-force + per-path hypotheses
passive             robots / sitemap / JS endpoints & secrets (no brute)
graph               merge every saved artifact into one interactive graph
```

---

## 3. Module map

| File | Role |
|------|------|
| `main.py` | CLI entry point: argument parsing, per-target output folders, orchestration, concurrent multi-port fingerprinting, import-vs-live routing. |
| `toolrunner.py` | Shared external-tool plumbing: PATH check, temp-output context manager, `subprocess` run with timeout. |
| `nmap_parser.py` | Parse `nmap -oX` XML → ports/services/versions, **per host** (`hosts` list) plus a flat first-host view. |
| `fingerprinter.py` | Native HTTP fingerprint: scheme autodetect, same-host redirect following, headers/cookies, cookie flags, WAF, **active CORS and deserialization checks**, deep-route stack fallback, soft-404 calibration, threaded sensitive-path probing. |
| `signatures.py` | Load the signature DBs; `match_path`, `match_params`, cookie/WAF matching, stack normalisation, per-keyword collision guards, stack refinement. |
| `confidence.py` | Stack-confidence scoring from the number of independent signals. |
| `analyzer.py` | Correlate signals → stack / DB / prioritised vulns; evidence-gating; cookie-hardening checks; CORS & deserialization findings; near-duplicate dedup. |
| `dir_bruteforce.py` | `feroxbuster` wrapper (+ `--from-ferox` importer); interactive Ctrl-C-to-save. |
| `subs.py` | `subfinder` wrapper + built-in liveness classification (+ `--from-txt`). |
| `vhost.py` | `ffuf` Host-header fuzzing wrapper (+ `--from-ffuf`). |
| `passive.py` | robots/sitemap parsing + same-host JS endpoint/secret extraction (never executes JS). |
| `graph_builder.py` | Build the adaptive node/edge graph; route findings per host; stack-refine and per-hypothesis-priority the vuln nodes. |
| `renderer.py` | Standalone dependency-free interactive SVG/HTML graph engine; escapes embedded JSON. |
| `reporter.py` | Minimalist ANSI console report. |
| `data/*.json` | Signature databases (see §5). |
| `tests/` | stdlib `unittest` suite covering the matching engine and helpers. |

---

## 4. The correlation engine (`signatures.py` + `analyzer.py`)

### Path matching — `match_path`
Substring keyword matching over the lowercased path (so `/api/internal/users`
matches `api`). For each matched keyword every hypothesis is collected **with its
own priority**; a hypothesis that several keywords produce keeps its best
severity. The function returns `hypotheses`, a parallel `hyp_priorities`, and the
path's max `priority` (for the path-level summary). This per-hypothesis priority
is what keeps the graph correctly ranked (a HIGH lead on a path that also matches
a CRITICAL keyword is not inflated to CRITICAL).

Additional path signals:
- **ID segments** (`_has_id_segment`): numeric or 16+-char-hex or UUID segments →
  IDOR / BOLA. Bare 4-digit years (1900–2099) are excluded as dates.
- **Query parameters** (`match_params`): `?url`/`?img_url` → SSRF, `?redirect_uri`
  /`?response_type` → OAuth abuse, `?file` → LFI, etc.
- **Reflected-context** heuristic for stored-injection on register/profile forms.

### Collision guards
Substring matching is deliberately aggressive but can bleed (`compose` inside
`composer.json`). A keyword may declare an opt-in `except` list of substrings that
suppress it; this changes nothing for the other signatures.

### Stack refinement — `refine_hypotheses`
A generic hypothesis is specialised by the detected stack: SSTI → Jinja2 on
Python, Twig on PHP, Freemarker on Java; file upload → `.php`/`.jsp`/`.aspx`;
SQLi → NoSQL on Node. Shared by both the graph and the console report.

### Signal correlation — `analyze`
Merges cookie/header/port signatures into a stack (+ confidence), database
candidates, and a severity-bucketed vuln list. Then:
- **Evidence-gating:** a path-specific finding (e.g. Werkzeug `/console` RCE) is
  suppressed when that path was actually probed and is absent — no crying wolf.
- **Cookie hardening:** missing `HttpOnly`/`Secure`/`SameSite`; a session cookie
  without `HttpOnly` is flagged as XSS-stealable.
- **CORS / deserialization** findings are folded in from the active checks.
- **Dedup:** a vuln that is only a less-specific prefix of another is dropped.

### Active checks (`fingerprinter.py`) — what static signatures can't express
- **Scheme autodetect:** `_candidate_schemes` picks http/https from the port and
  the nmap service hint, falling back to the other scheme on a connection error.
- **CORS:** a dedicated one-off request carries a throwaway `Origin`; a reflected
  / `null` / `*` `Access-Control-Allow-Origin` — escalated with credentials — is a
  finding. The Origin never touches the path-probe session.
- **Insecure deserialization:** cookie values are classified as PHP (`O:`/`a:`),
  Java (`rO0`/`0xACED`) or Python pickle (proto 2–5), raw or base64; `__VIEWSTATE`
  is detected in the body.
- **Soft-404 calibration:** random paths are probed first; any FOUND status they
  return is the host's catch-all (SPA soft-404, blanket auth, strict-CORS), so
  real path hits that merely echo it are suppressed (reported as a `soft-404`
  note) — otherwise such hosts produce a 65-path false-positive avalanche.
- **Deep-route stack fallback:** if the root exposes no framework signal, a few
  common routes (`/api/`, `/login`, …) are probed and the first with a framework
  header/cookie is adopted (noted `via deep route …`).

---

## 5. Data layer (`data/*.json`)

| File | Maps |
|------|------|
| `path_signatures.json` | ~585 keyword signatures → `{hypotheses, priority, except?}`. |
| `param_signatures.json` | request-parameter names → vulnerability classes. |
| `cookie_signatures.json` | cookie names (exact / prefix `*` / `/regex/`) → stack + db + vulns. |
| `header_signatures.json` | response-header substrings → stack + db + vulns. |
| `port_signatures.json` | open-port → service + vulns. |
| `priority.json` | keyword → severity bucket. |
| `waf_signatures.json` | header/cookie → WAF product. |
| `interesting_paths.json` | the ~65 sensitive paths the active probe requests. |

Adding coverage is a data edit; the matching engine picks it up automatically.

---

## 6. Graph & rendering

`graph_builder.build_graph` assembles an adaptive node/edge graph:
`target → subdomains → ports → stack → {db, waf, vulns, paths} → hypotheses`.
Findings are routed to their host, so a broad target renders as one graph.
Unsignatured noise paths collapse into a single hub node; auth-gated routes
(30x/401/403) are separated. `renderer.render_to_file` embeds the graph as JSON
(escaping `< > &`) into one self-contained HTML file with a dependency-free SVG
engine: pan/zoom, drag, per-node status, hide/collapse, swimlanes, search,
filters, a Markdown kill-chain report and PNG export. State persists in
`localStorage`.

---

## 7. I/O conventions

- Each run writes JSON into a **per-target folder** named after the host verbatim
  (`target.thm/`, `app.example.com/`).
- File names: `<host>.nmap.json`, `<host>-<port>.dirs.json`,
  `<host>-<port>.fp.json`, `<host>-<port>.passive.json`, `<host>-<port>.vhost.json`,
  `<host>.subs.json`, `<host>.graph.html`.
- Every launch-a-tool stage also accepts an import flag (`--from-xml`,
  `--from-ferox`, `--from-ffuf`, `--from-txt`) so you can run the underlying tool
  with your own flags and feed its output in for correlation.

---

## 8. Testing

`python3 -m unittest discover -s tests` — stdlib only, no extra deps. Covers the
matching engine (collisions, per-hypothesis priority, id-segment heuristics,
params, refinement), port/header parsing, serialized-cookie and CORS detection,
multi-host nmap parsing, dedup, and end-to-end per-hypothesis priority in the
built graph.
