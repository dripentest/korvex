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
    session.headers.update({"User-Agent": "stack-fingerprinter/1.0"})
    base_url = _build_url(host, port)

    result = {
        "headers": {h: None for h in TRACKED_HEADERS},
        "cookies": [],
        "cookie_flags": [],
        "secure_scheme": port in (443, 8443),
        "waf": None,
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
