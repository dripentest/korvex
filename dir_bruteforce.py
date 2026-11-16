import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

from fingerprinter import FOUND_STATUSES, _build_url


def _parse_ferox_line(line: str) -> dict | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        return None
    if obj.get("type") != "response":
        return None

    status = obj.get("status")
    if status not in FOUND_STATUSES:
        return None

    url = obj.get("url", "")
    path = obj.get("path") or urlsplit(url).path or "/"

    return {
        "path": path,
        "status": status,
        "length": obj.get("content_length"),
        "url": url,
    }


def _parse_url_line(line: str, host: str) -> dict | None:
    """One line of a URL/endpoint list → a found entry (or None to skip).
    Accepts a full URL, a bare path, or a katana `-jsonl` object. Full URLs on a
    different host are skipped; the query string is kept so parameter-based
    hypotheses (?id=, ?file=) fire."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    status = None
    if line.startswith("{"):  # katana -jsonl (or a similar JSON-lines crawl)
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            return None
        line = (obj.get("request") or {}).get("endpoint") or obj.get("url") or obj.get("endpoint") or ""
        status = (obj.get("response") or {}).get("status_code")
        if not line:
            return None

    if "://" in line:
        parts = urlsplit(line)
        if host and parts.hostname and parts.hostname != host:
            return None
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
    else:
        path = line if line.startswith("/") else "/" + line

    return {"path": path, "status": status}


def load_urls(path: str, host: str, port: int) -> dict:
    """Import a list of URLs/endpoints (katana -o or -jsonl, gau, waybackurls, or a
    hand-made list; one per line) into the pipeline schema. No crawling is run —
    the file you already have is normalised and fed straight to the graph."""
    result = {"target": _build_url(host, port), "found": [], "error": None, "interrupted": False}

    if not Path(path).is_file():
        result["error"] = f"endpoint list not found: {path}"
        print(f"[!] {result['error']}", file=sys.stderr)
        return result

    seen = set()
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                entry = _parse_url_line(line, host)
                if entry and entry["path"] not in seen:
                    seen.add(entry["path"])
                    result["found"].append(entry)
    except OSError as exc:
        result["error"] = f"could not read {path}: {exc}"
        print(f"[!] {result['error']}", file=sys.stderr)
        return result

    result["found"].sort(key=lambda e: e["path"])
    return result


def load_dir_bruteforce(path: str, host: str, port: int) -> dict:
    """Parse an existing feroxbuster --json output file into the pipeline schema.
    Run feroxbuster yourself with whatever flags you need, then import its output."""
    result = {"target": _build_url(host, port), "found": [], "error": None, "interrupted": False}

    if not Path(path).is_file():
        result["error"] = f"feroxbuster output not found: {path}"
        print(f"[!] {result['error']}", file=sys.stderr)
        return result

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                entry = _parse_ferox_line(line)
                if entry:
                    result["found"].append(entry)
    except OSError as exc:
        result["error"] = f"could not read {path}: {exc}"
        print(f"[!] {result['error']}", file=sys.stderr)
        return result

    result["found"].sort(key=lambda e: e["path"])
    return result
