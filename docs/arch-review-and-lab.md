# Stack Fingerprinter — Architectural Review & Docker Test Lab

> Living document. Section 1 is the architectural review (weak points, ranked).
> Section 2 is the Docker lab that exercises every command. Section 3 is the
> running bug log — appended as bugs are found during testing, with the exact
> command, persona, and observed vs expected behaviour.

Status legend: 🔴 critical · 🟠 high · 🟡 medium · ⚪ low/meta · ✅ verified-OK

---

## 0. Test environment

- Tool runs in the cloud container; Docker daemon started locally (`dockerd`,
  v29.x). Registry **pulls are blocked** by the network allowlist (image blobs
  live on CloudFront/Cloudflare → `403` from the agent proxy), so the lab base
  image `lab-base` is built from the container's own system dirs via
  `docker import` (Python 3.13 + stdlib, no credentials dirs).
- External recon binaries are **absent** (`nmap`, `feroxbuster`, `ffuf`,
  `subfinder` all MISSING). Live paths of `nmap`/`dirs`/`vhost`/`subs` are
  therefore tested through their **import modes** (`--from-xml`, `--from-ferox`,
  `--from-ffuf`, `--from-txt`) plus the "tool not found" branches. HTTP-only
  commands (`fingerprint`, `scan` HTTP phase, `passive`, `graph`) are tested
  live against the lab.
- Lab services run as containers from `lab-base`, each publishing to
  `127.0.0.1:80XX` (in `no_proxy`, so requests don't traverse the agent proxy).

---

## 1. Architectural review — weak points

### 🔴 A1. CORS probe `Origin` is sent on *every* request, incl. path probes
`fingerprinter.fingerprint_target` sets `session.headers["Origin"]` once, and the
interesting-path probes reuse that session. Any target that rejects cross-origin
requests with `401/403` (common for APIs/WAFs) will answer **every** probed path
with `403` — and `403 ∈ FOUND_STATUSES`, so *all* probed paths get reported as
"found/gated". This is a self-inflicted mass false positive introduced together
with the CORS feature.
- **Lab:** persona `origin403` (returns 403 whenever `Origin` present).
- **Expected failure:** fingerprint reports a huge list of gated paths that don't exist.

### 🟠 A2. Detection keyed solely on the root `/` response
Stack/DB/cookie/CORS/deser detection reads only the final response after
same-host redirects to `/`. Apps that expose `X-Powered-By`/framework cookies
only on deeper routes (e.g. `/api/`) are fingerprinted as "no stack".
- **Lab:** persona `deep-headers` (root bare; `/api/` reveals Express + `connect.sid`).
- **Expected limitation:** stack = "—" though the app is clearly Express.

### 🟠 A3. `FOUND_STATUSES` has no baseline/calibration
Includes `401`/`403`. A blanket-auth host (or A1) makes all probes "found". Unlike
feroxbuster's auto-filter, there's no "does every random path return the same
status?" calibration.
- **Lab:** `origin403`, and `php` (`/phpmyadmin/`→403).

### 🟠 A4. `_parse_ports` crashes on malformed input
`int(part)` throws on `--port abc`, `--port 80-`, `--port 8o`. Reversed ranges
(`100-1`) silently yield nothing. No validation → uncaught `ValueError` traceback
for `scan`/`fingerprint`/`nmap`.
- **Lab/test:** run `fingerprint --port abc`, `--port 100-1`.

### 🟡 A5. `match_path` substring collisions (engine-inherent)
Fixed `compose`/`uat` via opt-in `except`, but the matcher is still a blind
substring union; short keywords (`sso`, `rpc`, `git`, `.db`, `api`) can bleed into
unrelated longer words. The `except` guard is manual and will always lag.
- **Lab:** probe-path set is checked for spurious hypotheses.

### 🟡 A6. `nmap_parser` blends multiple hosts
Keeps only the first host's `address`/`os` but merges **all** hosts' ports into
one list. `graph`/`--from-xml` of a multi-host scan attributes every port to one
host.
- **Lab/test:** synthetic multi-host nmap XML → `graph`.

### 🟡 A7. Port fingerprinting is sequential and uncapped
`fingerprint`/`graph` fingerprint each port one-by-one with up to `8s×(1+65)`
request budget. `--port 8000-8100` → 101 serial fingerprints; looks hung, no
overall timeout.
- **Lab/test:** `fingerprint --port 8001-8011` timing.

### 🟡 A8. Deserialization base64 false-positive surface
`_looks_serialized` base64-decodes arbitrary cookie values and checks 1–2 byte
prefixes (`\x80\x02..`, `\xac\xed`). Random high-entropy cookies can (rarely)
decode to those prefixes.
- **Lab:** personas set random 32-byte base64 session cookies; expect no deser flag.

### 🟡 A9. Renderer XSS surface from target-controlled data
Graph node labels/notes derive from target-controlled headers, cookie names,
paths and JS endpoints. `_embed_json` escapes `< > &` at JSON level; the client
`esc()` was hardened. Needs confirming end-to-end with hostile input.
- **Lab:** persona `hostile` (Server header + content with `</script>`, `onerror=`).
- **Expected OK:** generated HTML contains no unescaped `<script`/`onerror=`.

### ⚪ A10. `_target_dir` strips the last dotted label
`example.com`→`example/`, `app.example.com`→`app.example/`. Output folders are
non-obvious; cross-command file discovery (`graph` reading saved JSON) depends on
the user knowing the mangling. Fragile UX.

### ⚪ A11. Redirect follow compares hostname only (ignores port/scheme)
Same-host redirect to another port/scheme is followed as "same host" (bounded by
5 hops). Minor.

### ⚪ A12. No automated test suite
Zero tests in the repo; every change is verified by hand. Highest long-term risk.

---

## 2. Docker lab architecture

One stdlib HTTP server (`lab/server.py`), parametrised by `PERSONA` env, run as
one container per persona from `lab-base`, published to `127.0.0.1:80XX`.
Brought up by `lab/up.sh`, torn down by `lab/down.sh`.

| Port | Persona         | What it exercises                                              | Weak point |
|------|-----------------|---------------------------------------------------------------|-----------|
| 8001 | `flask`         | Werkzeug stack, weak `session` cookie, `/console` `/debug`    | gating, confidence |
| 8002 | `php`           | `X-Powered-By: PHP`, `PHPSESSID`, `/composer.json` `/.env`, `/phpmyadmin/`→403 | info-disclosure, gating |
| 8003 | `cors-reflect`  | reflects `Origin` + `ACAC:true`                                | CORS HIGH |
| 8004 | `cors-null`     | `ACAO: null` + `ACAC:true`                                     | CORS HIGH (null) |
| 8005 | `cors-wildcard` | `ACAO: *`                                                      | CORS LOW |
| 8006 | `deser`         | Java `rO0` cookie + `__VIEWSTATE` in body                      | deser detect |
| 8007 | `origin403`     | **403 to any request carrying `Origin`**                       | **A1/A3** |
| 8008 | `login-redirect`| `/`→302→`/login`; full security headers                       | redirect, A11 |
| 8009 | `deep-headers`  | bare root; stack only on `/api/`                               | **A2** |
| 8010 | `passive`       | robots/sitemap(+nested)/JS secrets & endpoints                 | passive |
| 8011 | `hostile`       | `</script>`/`onerror=` in Server header & content              | **A9** |
| 8012 | `spa`           | React/Vue catch-all 200 (soft-404) for every path              | **A3/A1** |

Offline-tool tests (binaries absent) use fixtures under `lab/fixtures/`:
`nmap-multihost.xml` (A6), `ferox.jsonl`, `ffuf.json`, `subs.txt`.

---

## 3. Bug log

_(appended during testing; newest at bottom)_

### Lab realism note
Personas model **real server behaviours** found in the wild, not inputs hand-tuned
to our signatures: a strict-CORS API (`origin403`), a React/Vue-style SPA with a
catch-all 200 (`spa`, soft-404), a redirect-to-login app, a reverse-proxy `Server`
header, high-entropy random session cookies, etc. The goal is architectural
robustness under production conditions, not a green demo.

---

### 🔴 BUG-1 (A1 + A3) — CORS probe `Origin` turns every strict-CORS/soft-404 host into a 65-path false-positive avalanche
- **Command:** `fingerprint --target 127.0.0.1 --port 8007` (persona `origin403`,
  a realistic API that returns `403` to any cross-origin request).
- **Observed:** ALL 65 probed paths reported as "found → 403", each with
  CRITICAL/HIGH hypotheses (`/.aws/credentials`, `/.git/config`, `/terraform.tfstate`,
  …). A pentester would drown in fabricated findings.
- **Root cause:** `fingerprinter.fingerprint_target` sets `session.headers["Origin"]`
  globally; the interesting-path probes reuse that session, so a strict-CORS server
  rejects every probe with `403`, and `403 ∈ FOUND_STATUSES`. Compounded by the
  absence of any soft-404/baseline calibration (A3): the same avalanche happens on a
  plain SPA that serves `index.html` (200) for every path.
- **Severity:** 🔴 critical — destroys signal on two extremely common prod setups.
- **Fix direction:**
  1. Send the probe `Origin` only on the dedicated CORS request, not on the shared
     session used for path probing.
  2. Add baseline calibration: probe a random non-existent path first; if it returns
     a "found" status, treat that status as the host's catch-all and suppress paths
     that merely echo it.
- **Status:** OPEN (confirmed). Also reproduced on persona `spa` (soft-404) with
  **no CORS involved** — all 65 paths "found → 200" — proving the A3 half is
  independent of the Origin header.

### 🟠 BUG-2 (A4) — malformed `--port` crashes with a raw traceback
- **Command:** `fingerprint --target 127.0.0.1 --port abc` / `scan … --port 8o`.
- **Observed:** uncaught `ValueError: invalid literal for int()` traceback (exit 1).
  `--port 100-1` (reversed range) exits 0 and silently does nothing.
- **Root cause:** `main._parse_ports` calls `int(part)` with no validation and
  builds `range(a, b+1)` without checking `a<=b`.
- **Severity:** 🟠 high (bad UX / looks broken on a typo).
- **Fix direction:** validate tokens, emit `! invalid --port: …` + clean exit;
  warn-and-skip reversed ranges.
- **Status:** OPEN (confirmed).

### Verified behaviours (no bug)
- ✅ **A9 (renderer XSS):** persona `hostile` Server value
  `Werkzeug/2.0.1</script><img … onerror=…>` and XSS-laden dirs paths embed only
  as escaped `<…` in the graph HTML — zero raw `<img`/`<svg`/`</script>`.
- ✅ **A8 (deser FP):** high-entropy random base64 session cookies
  (`PHPSESSID`, `session`, `s`) are **not** flagged; only the real Java `rO0`
  cookie and `__VIEWSTATE` are.
- ✅ **Feature detections** are correct once the host has real 404s: Flask &
  PHP stacks + DBs + cookie weaknesses (`php`), CORS HIGH (`cors-reflect`),
  deser HIGH ×2 (`deser`), Django-by-cookie after redirect (`login-redirect`),
  passive robots + nested sitemap + JS endpoints + AWS/Slack/JWT secrets
  (`passive`), and all four import modes (`--from-xml/-ferox/-ffuf/-txt`).

### Confirmed limitations (lower priority)
- 🟡 **A2 (`deep-headers`):** stack `—` though Express is obvious on `/api/`
  (root-only fingerprint). Real limitation; by design.
- 🟡 **A6 (`nmap --from-xml` multi-host):** ports of all hosts merged
  (`[80,22,5432,8080]`), `address` = first host only. Silent blend.
- 🟡 **A7 (port range):** 12 live ports = 3.9 s; only *filtered* ports (8 s
  timeout each, no RST) would accumulate — not reproducible on localhost.
- ⚪ **Cosmetic:** near-duplicate labels — stack `Python / Flask · Python / Flask
  (Werkzeug)`, and `php` vulns list `unserialize` twice / `file_upload` twice
  (independent signals, redundant display).

---

## 4. Fixes applied
_(each re-verified against the lab)_

### FIX BUG-1 — `fingerprinter.py` + `reporter.py`  ✅
1. **Origin scoped to a dedicated CORS probe.** `session.headers` no longer carries
   `Origin`; CORS is read from a single extra `GET /` with the probe Origin, so the
   path-probing session is clean. A strict-CORS host no longer 403s every probe.
2. **Soft-404 / catch-all calibration.** Before trusting path probes,
   `_baseline_statuses()` fires 2 random `token_hex(12)` paths; any FOUND status they
   return becomes a baseline, and interesting-path hits that merely echo it are
   suppressed. `result["soft404_baseline"]` is surfaced by the report
   (`soft-404  host returns 200 for unknown paths — path probing suppressed`).
- **Lab re-verify:** `origin403` & `spa` → **0** paths (was 65) + soft-404 note;
  `cors-reflect` → CORS HIGH kept, **0** false paths; `flask` → `/console`,`/debug`
  still found; `php` → `/.env`,`/phpmyadmin/`,`/composer.json` still found.

### FIX BUG-2 — `main._parse_ports`  ✅
Validates each token; a non-numeric port prints `! invalid --port value '…'` and
exits 2 (no traceback); a reversed range prints `! ignoring reversed port range`
and is skipped.
- **Lab re-verify:** `--port abc` → clean exit 2; `--port 100-1` → warn + continue.

### FIX A2 — deep-route stack fallback ✅
When the root exposes no framework signal (`_stack_detected` checks header/cookie
signatures, so a bare `Server: nginx` does not count), the fingerprinter probes
`/api/ /login /index.php /home` and adopts the first that reveals a framework
header/cookie; the report shows `via deep route /api/`.
- **Lab:** `deep-headers` → `Node.js / Express … via deep route /api/`; `flask`
  still detected from root (no needless extra probe).

### FIX A6 — multi-host nmap no longer blended ✅
`parse_nmap_xml` keeps the flat first-host shape (back-compat) **and** adds a
`hosts` list (each host's own ports/os). `nmap` prints per host; `graph` expands a
multi-host file into one routed node per host.
- **Lab:** `nmap --from-xml nmap-multihost.xml` → `10.0.0.1 80,22` / `10.0.0.2
  5432,8080`; graph shows two host nodes.

### FIX A7 — port fingerprinting parallelised ✅
`_fingerprint_ports` (and the `graph` fingerprint jobs) run on a bounded
`ThreadPoolExecutor` (≤8), results in input order. 12 ports: 3.9 s → 1.9 s;
filtered ports no longer serialise 8 s timeouts.

### FIX A10 — output folder = verbatim host ✅
`_target_dir` returns the full safe host name (`target.thm/`, `app.example.com/`),
no label stripping — the path always matches the typed target. README updated.

### FIX M5 — stack refinement shared by graph and console ✅
`refine_hypotheses` moved to `signatures.py`; both the graph and the
`fingerprint`/`scan` console now show stack-refined leads (SSTI→Jinja2 on Python,
Twig on PHP, …).

### FIX (cosmetic) — near-duplicate labels removed ✅
`analyzer._dedup_prefixes` drops a vuln that is only a less-specific prefix of
another (`unserialize` vs `unserialize (PHPGGC)`); the report collapses a stack
label contained in a more specific one (`Python / Flask` vs `… (Werkzeug)`).

### FIX A12 — test suite added ✅
`tests/` (stdlib `unittest`, no new deps) locks in the matching engine and every
fix above: run `python3 -m unittest discover -s tests`.

### Not fixed — by design
- **M3:** parameter hypotheses need a query string; directory brute-forcing yields
  bare paths, so `param_signatures` is fed by `passive` JS endpoints, not `dirs`.
  Inherent to what dir brute-forcing is — not a code defect.

---

## 5. Parsing & matching review (the core: "dir found → match in the graph")

Pipeline: `found path → match_path() → hypotheses(+priority) → graph vuln nodes`
(`dir_bruteforce._parse_ferox_line` → `graph_builder._add_paths` → `_path_node`).

### Parsing — ✅ robust
`match_path` runs `urlsplit`, uses `.path`, lowercases. Verified against: uppercase
(`/ADMIN/Config`), trailing slash, `%2e%2e` (left encoded, correct), fragment
(`/admin#section`), double slash (`//admin`), unicode (`/café/login`), array params
(`/search?q[]=1` → `[]` stripped). All parse and match sensibly. `_parse_ferox_line`
falls back `obj.path or urlsplit(url).path` and filters by `FOUND_STATUSES`. No
parsing bugs found.

### Matching — philosophy vs. defects
Aggressive substring matching is **intended**: `login`, `admin`, `console`, `config`,
`backup`, `api`, `dashboard`, etc. are surfaced as *hypotheses to check*, not
confirmed findings. An audit of ~80 common dir names showed the vast majority of
matches are legitimate leads; noise-only paths collapse into the hub node. Two
genuine defects were found and fixed:

#### 🟠 BUG-3 (M6) — every hypothesis inherited the path's MAX priority  ✅ FIXED
`match_path` returned one `priority` (the best over all matched keywords) and a flat
hypothesis list; `graph_builder._path_node` coloured **every** hyp node with that
single value. So on `/.git/config`, the intrinsically-HIGH "Configuration disclosure"
rendered as **CRITICAL** (inherited from `.git`); on any path with a numeric segment,
MEDIUM leads jumped to HIGH. This defeats the graph's whole purpose — prioritised
leads.
- **Fix:** `match_path` now returns `hyp_priorities` (each hypothesis at its own best
  severity); `_refine_hyps`/`_path_node` carry it through so each vuln node is
  coloured by its own priority. Path-level `priority` (the max) is kept for the
  path summary / console tag.
- **Lab re-verify:** `/.git/config` → `Configuration disclosure` HIGH, `Exposed
  installer` HIGH, `Git disclosure` CRITICAL (distinct, correct).

#### 🟡 BUG-4 (M4) — spurious IDOR on 4-digit years & short hex slugs  ✅ FIXED
`_has_id_segment` treated any `\d+` segment (incl. `2024`) and any `[0-9a-f]{12,}`
(incl. 12-char slugs like `deadbeefcafe`) as an object id → false HIGH "IDOR". E.g.
`/report/2024` and `/news/2024` were pushed to HIGH purely by the year.
- **Fix:** skip bare 4-digit years (1900–2099); raise the hex-id floor to 16 chars
  (still catches md5/sha1/mongo/uuid). `/user/1337`, 16+-hex and UUID segments still
  flag IDOR.

### Matching — documented (not changed)
- 🟡 **M3:** parameter hypotheses (SSRF/OAuth/IDOR-via-`?param`) only fire when the
  path carries a query string. Directory brute-forcing yields **bare** paths, so the
  whole `param_signatures` DB is exercised almost only by `passive` JS endpoints
  (which do carry `?id=…`), not by the core `dirs` flow. Coverage gap, not a bug.
- ⚪ **M5:** stack refinement (`_refine_hyps`, e.g. SSTI→Jinja2) is applied only in the
  **graph** (where the stack is known), not in the `dirs`/`fingerprint` console
  output. Cosmetic inconsistency.
- ⚪ **Collisions** are inherent to substring matching and handled case-by-case by the
  opt-in `except` guard (see BUG from the earlier session: `compose`/`composer`).
