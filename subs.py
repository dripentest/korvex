import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

from fingerprinter import _sanitize

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = 6
LIVENESS_WORKERS = 40


def _resolve(host: str) -> list[str] | None:
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return None
    return sorted({i[4][0] for i in infos})


def _probe_http(host: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            resp = requests.get(f"{scheme}://{host}", timeout=PROBE_TIMEOUT, verify=False, allow_redirects=False)
            return {"scheme": scheme, "status": resp.status_code}
        except requests.RequestException:
            continue
    return None


def _check(sub: str) -> tuple[list[str] | None, dict | None]:
    ips = _resolve(sub)
    if not ips:
        return None, None
    return ips, _probe_http(sub)


def run_subs_from_file(path: str, domain: str, threads: int = LIVENESS_WORKERS) -> dict:
    """Run the liveness check over a list of subdomain names from a file (one per
    line — e.g. a saved `subfinder -silent` run). Enumerate subdomains yourself
    with subfinder/amass/etc; the liveness classification (resolve + HTTP probe)
    is the value Korvex adds over the raw name list, so it still runs here."""
    result = {"domain": domain, "found": 0, "live": [], "resolved_no_web": [], "dead": 0, "error": None}

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        result["error"] = f"could not read {path}: {exc}"
        print(f"! {result['error']}", file=sys.stderr)
        return result

    subs = sorted({_sanitize(line.strip()) for line in text.splitlines() if line.strip()})
    result["found"] = len(subs)
    if not subs:
        return result

    return _classify_liveness(result, subs, threads)


def _classify_liveness(result: dict, subs: list[str], threads: int) -> dict:
    print(f"\033[2mchecking liveness of {len(subs)} names…\033[0m")
    sys.stdout.flush()
    try:
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_check, s): s for s in subs}
            for fut in as_completed(futs):
                sub = futs[fut]
                ips, http = fut.result()
                if not ips:
                    result["dead"] += 1
                elif http:
                    result["live"].append({"subdomain": sub, "ips": ips, **http})
                else:
                    result["resolved_no_web"].append({"subdomain": sub, "ips": ips})
    except KeyboardInterrupt:
        result["error"] = "liveness check interrupted (partial results)"
        print(f"\n! {result['error']}", file=sys.stderr)

    result["live"].sort(key=lambda x: x["subdomain"])
    result["resolved_no_web"].sort(key=lambda x: x["subdomain"])
    return result
