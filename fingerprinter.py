import base64
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlsplit

import requests
import urllib3

from signatures import INTERESTING_PATHS, match_waf

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 8
PATH_CHECK_WORKERS = 10
MAX_SAME_HOST_REDIRECTS = 5
CORS_PROBE_ORIGIN = "https://evil.example"

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


def _build_url(host: str, port: int, path: str = "/") -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}{path}"


def _check_path(session: requests.Session, base_url: str, path: str) -> tuple[str, int | None]:
    try:
        resp = session.get(base_url + path, timeout=TIMEOUT, verify=False, allow_redirects=False)
        return path, resp.status_code
    except requests.RequestException:
        return path, None


def fingerprint_target(host: str, port: int) -> dict:
    session = requests.Session()
    session.headers.update({"User-Agent": "stack-fingerprinter/1.0", "Origin": CORS_PROBE_ORIGIN})
    base_url = _build_url(host, port)

    result = {
        "headers": {h: None for h in TRACKED_HEADERS},
        "cookies": [],
        "cookie_flags": [],
        "secure_scheme": port in (443, 8443),
        "waf": None,
        "cors": None,
        "deserialization": [],
        "interesting_paths": [],
        "security_headers_missing": [],
        "error": None,
    }

    try:
        resp = session.get(base_url + "/", timeout=TIMEOUT, verify=False, allow_redirects=False)
        for _ in range(MAX_SAME_HOST_REDIRECTS):
            if resp.status_code not in (301, 302, 303, 307, 308):
                break
            location = resp.headers.get("Location")
            if not location:
                break
            absolute = urljoin(resp.url, location)
            if urlsplit(absolute).hostname != host:
                break
            resp = session.get(absolute, timeout=TIMEOUT, verify=False, allow_redirects=False)
    except requests.RequestException as exc:
        result["error"] = f"Could not connect to {base_url}: {exc}"
        return result

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
    result["cors"] = _classify_cors(resp_headers_lower)
    try:
        body = resp.text
    except Exception:
        body = ""
    result["deserialization"] = _detect_serialized(session.cookies, body)

    found_paths = []
    with ThreadPoolExecutor(max_workers=PATH_CHECK_WORKERS) as pool:
        futures = {pool.submit(_check_path, session, base_url, path): path for path in INTERESTING_PATHS}
        for future in as_completed(futures):
            path, status = future.result()
            if status in FOUND_STATUSES:
                found_paths.append((path, status))

    found_paths.sort(key=lambda p: p[0])
    result["interesting_paths"] = [f"{path} → {status}" for path, status in found_paths]

    return result
