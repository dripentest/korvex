import shutil
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

from fingerprinter import _sanitize

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SUBFINDER_TIMEOUT = 600
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


def run_subs(domain: str, timeout: int = SUBFINDER_TIMEOUT, threads: int = LIVENESS_WORKERS) -> dict:
    result = {"domain": domain, "found": 0, "live": [], "resolved_no_web": [], "dead": 0, "error": None}

    if shutil.which("subfinder") is None:
        result["error"] = "subfinder not found in PATH"
        print(f"! {result['error']} - install from github.com/projectdiscovery/subfinder", file=sys.stderr)
        return result

    print(f"\033[2msubfinder -d {domain}\033[0m")
    sys.stdout.flush()
    try:
        proc = subprocess.run(["subfinder", "-d", domain, "-silent"],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        result["error"] = f"subfinder timed out ({timeout}s)"
        print(f"! {result['error']}", file=sys.stderr)
        return result

    subs = sorted({_sanitize(line.strip()) for line in proc.stdout.splitlines() if line.strip()})
    result["found"] = len(subs)
    if not subs:
        return result

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
