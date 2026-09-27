import re
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlsplit

import requests

from fingerprinter import TIMEOUT, _build_url, _sanitize

MAX_JS_FILES = 20
MAX_JS_BYTES = 400_000
_ASSET_EXT = (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2",
              ".ttf", ".ico", ".map", ".mp4", ".webp", ".webm")

_SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH"),
    ("Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"), "HIGH"),
    ("Stripe key", re.compile(r"(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"), "HIGH"),
    ("GitHub token", re.compile(r"gh[pousr]_[0-9A-Za-z]{36}"), "HIGH"),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "MEDIUM"),
    ("Generic secret",
     re.compile(r"""(?i)(?:api[_-]?key|secret|passwd|password|access[_-]?token|auth[_-]?token)['"]?\s*[:=]\s*['"][^'"\s]{8,64}['"]"""),
     "MEDIUM"),
]

_ENDPOINT_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{2,120})["'`]""")
_SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)


def _new_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": "stack-fingerprinter/1.0"})
    return s


def _get_text(session: requests.Session, url: str, limit: int = MAX_JS_BYTES) -> str | None:
    try:
        resp = session.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None
    if resp.status_code != 200:
        return None
    return resp.text[:limit]


def _paths_from_robots(text: str) -> tuple[list[str], list[str]]:
    paths, sitemaps = [], []
    for line in text.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith(("disallow:", "allow:")):
            val = line.split(":", 1)[1].strip()
            if not val.startswith("/"):
                continue
            for ch in ("*", "$", "?", "#"):
                val = val.split(ch)[0]
            val = val.rstrip("/")
            if len(val) > 1:
                paths.append(val)
        elif low.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
    return paths, sitemaps


def _locs_from_sitemap(text: str) -> list[str]:
    try:
        root = ET.fromstring(text.encode("utf-8", "replace"))
    except Exception:
        return []
    return [el.text.strip() for el in root.iter() if el.tag.endswith("loc") and el.text]


def _is_interesting_endpoint(p: str) -> bool:
    if p in ("/", "//") or " " in p:
        return False
    return not p.lower().endswith(_ASSET_EXT)


def run_passive(host: str, port: int) -> dict:
    session = _new_session()
    base = _build_url(host, port)
    result = {
        "target": base, "robots": [], "sitemap": [],
        "js_files": [], "js_endpoints": [], "js_secrets": [], "error": None,
    }

    robots = _get_text(session, base + "/robots.txt")
    sitemap_urls = [base + "/sitemap.xml"]
    if robots and "<html" not in robots.lower():
        rpaths, rsitemaps = _paths_from_robots(robots)
        result["robots"] = sorted({_sanitize(p) for p in rpaths})
        sitemap_urls += rsitemaps

    sm_paths, seen_sm = set(), set()
    queue = list(dict.fromkeys(sitemap_urls))
    while queue:
        url = queue.pop(0)
        if url in seen_sm or len(seen_sm) > 5:
            continue
        seen_sm.add(url)
        text = _get_text(session, url)
        if not text:
            continue
        for loc in _locs_from_sitemap(text):
            if loc.endswith(".xml") and urlsplit(loc).hostname == host:
                queue.append(loc)
            else:
                path = urlsplit(loc).path
                if path and path != "/":
                    sm_paths.add(_sanitize(path))
    result["sitemap"] = sorted(sm_paths)

    home = _get_text(session, base + "/")
    if home:
        js_urls = []
        for src in _SCRIPT_SRC_RE.findall(home):
            absu = urljoin(base + "/", src)
            if urlsplit(absu).hostname == host and absu not in js_urls:
                js_urls.append(absu)
        endpoints, secrets = set(), []
        seen_secret = set()
        for jurl in js_urls[:MAX_JS_FILES]:
            js = _get_text(session, jurl)
            if not js:
                continue
            result["js_files"].append(_sanitize(urlsplit(jurl).path))
            for m in _ENDPOINT_RE.findall(js):
                if _is_interesting_endpoint(m):
                    endpoints.add(_sanitize(m))
            src_name = urlsplit(jurl).path.rsplit("/", 1)[-1]
            for name, rx, prio in _SECRET_PATTERNS:
                for hit in rx.findall(js):
                    val = hit if isinstance(hit, str) else hit[0]
                    key = (name, val)
                    if key in seen_secret:
                        continue
                    seen_secret.add(key)
                    secrets.append({"type": name, "value": _sanitize(val)[:80],
                                    "priority": prio, "source": _sanitize(src_name)})
        result["js_endpoints"] = sorted(endpoints)
        result["js_secrets"] = secrets

    return result


def passive_paths(result: dict) -> list[dict]:
    seen, out = set(), []
    for p in result.get("robots", []) + result.get("sitemap", []) + result.get("js_endpoints", []):
        if p not in seen:
            seen.add(p)
            out.append({"path": p, "status": None})
    return out
