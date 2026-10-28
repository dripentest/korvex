import json
import sys
from pathlib import Path

from fingerprinter import _build_url


def _parse_ffuf_results(data: dict, domain: str) -> list[dict]:
    found = []
    for r in data.get("results", []):
        word = (r.get("input") or {}).get("FUZZ", "")
        found.append({
            "vhost": f"{word}.{domain}" if word else domain,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
        })
    found.sort(key=lambda e: e["vhost"])
    return found


def load_vhost(path: str, domain: str, port: int, *, connect_host: str | None = None) -> dict:
    """Parse an existing ffuf JSON output file (-of json) into the pipeline schema.
    Run ffuf yourself with whatever flags you need, then import its output."""
    host = connect_host or domain
    result = {"domain": domain, "target": _build_url(host, port), "found": [], "error": None}

    if not Path(path).is_file():
        result["error"] = f"ffuf output not found: {path}"
        print(f"! {result['error']}", file=sys.stderr)
        return result

    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["error"] = f"could not read {path}: {exc}"
        print(f"! {result['error']}", file=sys.stderr)
        return result

    result["found"] = _parse_ffuf_results(data, domain)
    return result
