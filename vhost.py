import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from fingerprinter import _build_url


def run_vhost(domain: str, port: int, wordlist: str, *, connect_host: str | None = None,
              threads: int | None = None, filter_size: int | None = None,
              timeout: int = 1800) -> dict:
    host = connect_host or domain
    url = _build_url(host, port)
    result = {"domain": domain, "target": url, "found": [], "error": None}

    if shutil.which("ffuf") is None:
        result["error"] = "ffuf not found in PATH"
        print(f"! {result['error']}", file=sys.stderr)
        return result
    if not Path(wordlist).is_file():
        result["error"] = f"wordlist not found: {wordlist}"
        print(f"! {result['error']}", file=sys.stderr)
        return result

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = ["ffuf", "-w", f"{wordlist}:FUZZ", "-u", url + "/",
           "-H", f"Host: FUZZ.{domain}", "-o", tmp_path, "-of", "json"]
    cmd += ["-fs", str(filter_size)] if filter_size is not None else ["-ac"]
    if threads:
        cmd += ["-t", str(threads)]

    print(f"\033[2mffuf vhost {url}  ·  Host: FUZZ.{domain}  ·  Ctrl+C to stop\033[0m")
    sys.stdout.flush()
    try:
        subprocess.run(cmd, check=True, timeout=timeout)
    except subprocess.CalledProcessError:
        result["error"] = "ffuf exited with an error (see output above)"
        print(f"! {result['error']}", file=sys.stderr)
        Path(tmp_path).unlink(missing_ok=True)
        return result
    except (KeyboardInterrupt, subprocess.TimeoutExpired):
        result["error"] = "scan interrupted (ffuf writes results only on completion)"
        print(f"\n! {result['error']}", file=sys.stderr)
        Path(tmp_path).unlink(missing_ok=True)
        return result
    print()

    try:
        data = json.loads(Path(tmp_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        result["error"] = f"could not read ffuf output: {exc}"
        print(f"! {result['error']}", file=sys.stderr)
        Path(tmp_path).unlink(missing_ok=True)
        return result
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    for r in data.get("results", []):
        word = (r.get("input") or {}).get("FUZZ", "")
        result["found"].append({
            "vhost": f"{word}.{domain}" if word else domain,
            "status": r.get("status"),
            "length": r.get("length"),
            "words": r.get("words"),
            "lines": r.get("lines"),
        })
    result["found"].sort(key=lambda e: e["vhost"])
    return result
