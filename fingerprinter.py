import base64
import re
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from signatures import HEADER_SIGNATURES, INTERESTING_PATHS, match_cookie, match_waf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
PATH_CHECK_WORKERS = 10
MAX_SAME_HOST_REDIRECTS = 5
CORS_PROBE_ORIGIN = "https://evil.example"
BASELINE_PROBES = 2

_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def _sanitize(value: str) -> str:
    return _CONTROL_CHARS_RE.sub("", value)


def _cookie_flags(jar) -> list[dict]:
    flags = []
    for c in jar:
        rest = {k.lower(): v for k, v in (getattr(c, "_rest", None) or {}).items()}
        flags.append({
            "name": _sanitize(c.name),
            "httponly": "httponly" in rest,
            "secure": bool(c.secure),
            "samesite": rest.get("samesite") or None,
        })
    return flags

FOUND_STATUSES = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}

TRACKED_HEADERS = [
    "server",
    "x-powered-by",
    "x-generator",
    "x-drupal-cache",
    "x-runtime",
    "x-aspnet-version",
    "x-application-context",
]

REQUIRED_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


_PHP_SERIALIZED = re.compile(r'^(O:\d+:"|a:\d+:\{)')


def _looks_serialized(value: str) -> str | None:
    """Classify a cookie value as a serialized object (Insecure Deserialization
    signal). Covers PHP `O:`/`a:`, Java stream (`rO0`/0xACED) and Python pickle
    (proto 2-5), raw or base64/url-safe encoded."""
    v = (value or "").strip()
    if not v:
        return None
    if _PHP_SERIALIZED.match(v):
        return "PHP"
    if v.startswith("rO0"):
        return "Java"
    for variant in (v, v.replace("-", "+").replace("_", "/")):
        try:
            raw = base64.b64decode(variant + "=" * (-len(variant) % 4))
        except Exception:
            continue
        if raw[:2] == b"\xac\xed":
            return "Java"
        if raw[:1] == b"\x80" and len(raw) > 1 and raw[1] in (2, 3, 4, 5):
            return "Python pickle"
        if _PHP_SERIALIZED.match(raw.decode("latin-1", "ignore")):
            return "PHP"
    return None


def _detect_serialized(cookies, body: str | None) -> list[dict]:
    out, seen = [], set()
    for c in cookies:
        kind = _looks_serialized(getattr(c, "value", "") or "")
        if kind and c.name not in seen:
            seen.add(c.name)
            out.append({"type": kind, "where": f"cookie {_sanitize(c.name)}"})
    if body and "__VIEWSTATE" in body[:200_000]:
        out.append({"type": ".NET ViewState", "where": "form field __VIEWSTATE"})
    return out


def _stack_detected(headers: dict, cookies: list) -> bool:
    """True if the collected headers/cookies already reveal a framework (so a
    generic `Server: nginx` with no framework signal does NOT count as detected)."""
    for hname, hval in headers.items():
        if not hval:
            continue
        for needle in HEADER_SIGNATURES.get(hname, {}):
            if needle.lower() in hval.lower():
                return True
    return any(match_cookie(c) for c in cookies)


def _classify_cors(headers_lower: dict) -> dict | None:
    """Flag a permissive CORS policy from the response to a probe Origin."""
    acao = headers_lower.get("access-control-allow-origin")
    if not acao:
        return None
    acao_s = acao.strip()
    creds = (headers_lower.get("access-control-allow-credentials") or "").strip().lower() == "true"
    return {
        "acao": _sanitize(acao_s),
        "credentials": creds,
        "reflects_origin": acao_s.lower() == CORS_PROBE_ORIGIN,
        "null_origin": acao_s.lower() == "null",
        "wildcard": acao_s == "*",
    }


def _build_url(host: str, port: int, path: str = "/", scheme: str | None = None) -> str:
    if scheme is None:
        scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}{path}"


def _candidate_schemes(port: int, hint: str | None) -> list[str]:
    """Scheme order to try. An explicit hint (e.g. nmap 'ssl/http') wins; otherwise
    default by port but keep the other as a fallback for TLS on odd ports / plain
    HTTP on 8443-style ports."""
    if hint in ("http", "https"):
        return [hint]
    return ["https", "http"] if port in (443, 8443) else ["http", "https"]


def _check_path(session: requests.Session, base_url: str, path: str) -> tuple[str, int | None]:
    try:
        resp = session.get(base_url + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        return path, resp.status_code
    except requests.RequestException:
        return path, None


def _baseline_statuses(session: requests.Session, base_url: str) -> set[int]:
    """Probe random non-existent paths. Any FOUND status they return is the host's
    catch-all (soft-404 SPA, blanket auth, strict-CORS 403, …): real path findings
    that merely echo it are indistinguishable noise and must be suppressed."""
    seen: set[int] = set()
    for _ in range(BASELINE_PROBES):
        _, status = _check_path(session, base_url, "/" + secrets.token_hex(12))
        if status in FOUND_STATUSES:
            seen.add(status)
    return seen


def fingerprint_target(host: str, port: int, scheme: str | None = None,
                       proxies: dict | None = None, headers: dict | None = None) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": "korvex/1.0"})
    if headers:
        session.headers.update(headers)
    if proxies:
        session.proxies.update(proxies)

    result = {
        "headers": {h: None for h in TRACKED_HEADERS},
        "cookies": [],
        "cookie_flags": [],
        "secure_scheme": False,
        "waf": None,
        "cors": None,
        "deserialization": [],
        "interesting_paths": [],
        "soft404_baseline": [],
        "security_headers_missing": [],
        "stack_source": None,
        "error": None,
    }

    resp = None
    last_exc = None
    for sch in _candidate_schemes(port, scheme):
        base_url = _build_url(host, port, scheme=sch)
        try:
            resp = session.get(base_url + "/", timeout=TIMEOUT, verify=False, allow_redirects=False)
            break
        except requests.RequestException as exc:
            last_exc = exc
            continue
    if resp is None:
        result["error"] = f"Could not connect to {_build_url(host, port, scheme=scheme)}: {last_exc}"
        return result
    result["secure_scheme"] = base_url.startswith("https://")

    for _ in range(MAX_SAME_HOST_REDIRECTS):
        if resp.status_code not in (301, 302, 303, 307, 308):
            break
        location = resp.headers.get("Location")
        if not location:
            break
        absolute = urljoin(resp.url, location)
        if urlsplit(absolute).hostname != host:
            break
        try:
            resp = session.get(absolute, timeout=TIMEOUT, verify=False, allow_redirects=False)
        except requests.RequestException:
            break

    resp_headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for h in TRACKED_HEADERS:
        if h in resp_headers_lower:
            result["headers"][h] = _sanitize(resp_headers_lower[h])

    result["cookies"] = [_sanitize(name) for name in resp.cookies.keys()]
    result["cookie_flags"] = _cookie_flags(resp.cookies)

    result["security_headers_missing"] = [
        label for key, label in REQUIRED_SECURITY_HEADERS.items() if key not in resp_headers_lower
    ]

    result["waf"] = match_waf(resp_headers_lower, result["cookies"])
    try:
        body = resp.text
    except Exception:
        body = ""
    result["deserialization"] = _detect_serialized(session.cookies, body)

    # A2: the root revealed no stack signal (bare page / SPA shell). Try a few
    # common deeper routes and adopt the first that exposes a framework header or
    # cookie, so apps that only leak their stack under /api/ aren't missed.
    if not _stack_detected(result["headers"], result["cookies"]):
        for probe in ("/api/", "/login", "/index.php", "/home"):
            try:
                r = session.get(base_url + probe, timeout=TIMEOUT, verify=False, allow_redirects=False)
            except requests.RequestException:
                continue
            rl = {k.lower(): v for k, v in r.headers.items()}
            if any(h in rl for h in TRACKED_HEADERS) or len(r.cookies):
                for h in TRACKED_HEADERS:
                    if result["headers"][h] is None and h in rl:
                        result["headers"][h] = _sanitize(rl[h])
                if len(r.cookies):
                    names = [_sanitize(n) for n in r.cookies.keys()]
                    result["cookies"] = list(dict.fromkeys(result["cookies"] + names))
                    result["cookie_flags"] += _cookie_flags(r.cookies)
                result["stack_source"] = f"deep route {probe}"
                break

    # CORS is checked with a dedicated, one-off request carrying a probe Origin,
    # so the Origin header never touches the path-probing session (a strict-CORS
    # host would otherwise 403 every probe → mass false positives).
    try:
        cors_resp = session.get(base_url + "/", timeout=TIMEOUT, verify=False,
                                allow_redirects=False, headers={"Origin": CORS_PROBE_ORIGIN})
        result["cors"] = _classify_cors({k.lower(): v for k, v in cors_resp.headers.items()})
    except requests.RequestException:
        pass

    # Calibrate against the host's catch-all before trusting path probes.
    baseline = _baseline_statuses(session, base_url)
    result["soft404_baseline"] = sorted(baseline)

    found_paths = []
    with ThreadPoolExecutor(max_workers=PATH_CHECK_WORKERS) as pool:
        futures = {pool.submit(_check_path, session, base_url, path): path for path in INTERESTING_PATHS}
        for future in as_completed(futures):
            path, status = future.result()
            if status in FOUND_STATUSES and status not in baseline:
                found_paths.append((path, status))

    found_paths.sort(key=lambda p: p[0])
    result["interesting_paths"] = [f"{path} → {status}" for path, status in found_paths]

    return result
