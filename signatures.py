import json
import re
from pathlib import Path

_DATA_DIR = Path(__file__).parent / "data"


def _load(name: str) -> dict:
    with open(_DATA_DIR / name, encoding="utf-8") as f:
        return json.load(f)


COOKIE_SIGNATURES = _load("cookie_signatures.json")
HEADER_SIGNATURES = _load("header_signatures.json")
PORT_SIGNATURES = {int(k): v for k, v in _load("port_signatures.json").items()}
INTERESTING_PATHS = _load("interesting_paths.json")
WAF_SIGNATURES = _load("waf_signatures.json")
PRIORITY = _load("priority.json")
PATH_SIGNATURES = _load("path_signatures.json")

_PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_PRIORITY_RANK = {p: i for i, p in enumerate(_PRIORITY_ORDER)}
_PATH_KEYWORDS = PATH_SIGNATURES.get("keywords", {})


def match_path(path: str) -> dict | None:
    path_lower = path.lower()
    hypotheses: list[str] = []
    seen: set[str] = set()
    best_rank = len(_PRIORITY_ORDER)

    for keyword, sig in _PATH_KEYWORDS.items():
        if keyword in path_lower:
            rank = _PRIORITY_RANK.get(sig["priority"], best_rank)
            if rank < best_rank:
                best_rank = rank
            for h in sig["hypotheses"]:
                if h not in seen:
                    seen.add(h)
                    hypotheses.append(h)

    if not hypotheses:
        return None

    return {"hypotheses": hypotheses, "priority": _PRIORITY_ORDER[best_rank]}

SPRING_BOOT_SIGNATURE = {
    "stack": "Spring Boot",
    "db": [],
    "vulns": [
        "Spring4Shell (CVE-2022-22965)",
        "Actuator (/heapdump /env /jolokia)",
        "SpEL injection",
        "Log4Shell",
    ],
}


_COOKIE_PREFIXES = [(k[:-1], v) for k, v in COOKIE_SIGNATURES.items() if k.endswith("*")]
_COOKIE_REGEX = [(re.compile(k[1:-1]), v) for k, v in COOKIE_SIGNATURES.items()
                 if len(k) > 2 and k.startswith("/") and k.endswith("/")]


def stack_kind(stack: str | None) -> str | None:
    if not stack:
        return None
    s = stack.lower()
    if any(t in s for t in ("php", "wordpress", "drupal", "joomla", "laravel", "symfony",
                            "cakephp", "codeigniter", "craft", "phpmyadmin", "roundcube")):
        return "php"
    if any(t in s for t in ("node", "express", "koa", "next")):
        return "node"
    if any(t in s for t in ("python", "flask", "django", "pyramid")):
        return "python"
    if "ruby" in s or "rails" in s:
        return "ruby"
    if ".net" in s or "asp" in s:
        return "dotnet"
    if "javascript" not in s and any(t in s for t in ("java", "spring", "servlet", "tomcat", "jetty")):
        return "java"
    return None


def match_cookie(name: str) -> dict | None:
    sig = COOKIE_SIGNATURES.get(name)
    if sig:
        return sig
    for prefix, v in _COOKIE_PREFIXES:
        if name.startswith(prefix):
            return v
    for rx, v in _COOKIE_REGEX:
        if rx.fullmatch(name):
            return v
    return None


def match_waf(headers: dict, cookies: list) -> str | None:
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for waf_name, sig in WAF_SIGNATURES.items():
        for hkey, hval in sig.get("headers", {}).items():
            actual = headers_lower.get(hkey.lower())
            if actual is None:
                continue
            if hval == "*" or hval.lower() in actual.lower():
                return waf_name

        for cookie_sig in sig.get("cookies", []):
            prefix = cookie_sig[:-1] if cookie_sig.endswith("*") else cookie_sig
            if any(c.startswith(prefix) for c in cookies):
                return waf_name

    return None
