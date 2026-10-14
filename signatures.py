import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

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
PARAM_SIGNATURES = _load("param_signatures.json")

_PRIORITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
_PRIORITY_RANK = {p: i for i, p in enumerate(_PRIORITY_ORDER)}
_PATH_KEYWORDS = PATH_SIGNATURES.get("keywords", {})
_PARAMS = PARAM_SIGNATURES.get("params", {})

_ID_SEGMENT = re.compile(
    r"\d+|[0-9a-f]{12,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

_REFLECT_FIELDS = {"username", "email", "name", "user", "bio", "nickname", "displayname", "fullname"}
_REFLECT_CONTEXT = ("register", "signup", "profile", "account", "settings", "update", "edit")


def _has_id_segment(path_only: str) -> bool:
    return any(seg and _ID_SEGMENT.fullmatch(seg) for seg in path_only.split("/"))


def match_params(query: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, _ in parse_qsl(query, keep_blank_values=True):
        key = name.lower().strip().rstrip("[]")
        sig = _PARAMS.get(key)
        if sig:
            for h in sig["hypotheses"]:
                out.append((f"{h} [?{key}]", sig["priority"]))
    return out


def _context_hyps(path_lower: str, query: str) -> list[tuple[str, str]]:
    names = {n.lower().strip().rstrip("[]") for n, _ in parse_qsl(query, keep_blank_values=True)}
    if (names & _REFLECT_FIELDS) and any(c in path_lower for c in _REFLECT_CONTEXT):
        return [("Stored/reflected injection via user-controlled value (SSTI/XSS)", "HIGH")]
    return []


def match_path(path: str) -> dict | None:
    parts = urlsplit(path)
    path_only = parts.path or path
    path_lower = path_only.lower()

    collected: list[tuple[str, str]] = []
    for keyword, sig in _PATH_KEYWORDS.items():
        if keyword not in path_lower:
            continue
        # Opt-in collision guard: a keyword may list substrings that, when present,
        # mean this match is a longer word, not the token we want (e.g. "compose"
        # inside "composer.json"). Keywords without "except" are unaffected.
        if any(ex in path_lower for ex in sig.get("except", ())):
            continue
        for h in sig["hypotheses"]:
            collected.append((h, sig["priority"]))
    if _has_id_segment(path_only):
        collected.append(("IDOR / broken object-level authorization [/:id]", "HIGH"))
    collected.extend(match_params(parts.query))
    collected.extend(_context_hyps(path_lower, parts.query))

    if not collected:
        return None

    seen: set[str] = set()
    hypotheses: list[str] = []
    best_rank = len(_PRIORITY_ORDER)
    for h, prio in collected:
        if h not in seen:
            seen.add(h)
            hypotheses.append(h)
        rank = _PRIORITY_RANK.get(prio, best_rank)
        if rank < best_rank:
            best_rank = rank

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
