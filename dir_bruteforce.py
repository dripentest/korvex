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
