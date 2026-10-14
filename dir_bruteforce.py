import json
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import toolrunner
from fingerprinter import FOUND_STATUSES, _build_url

DEFAULT_TIMEOUT = 1800


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


def run_dir_bruteforce(
    host: str,
    port: int,
    wordlist: str,
    *,
    extensions: list[str] | None = None,
    threads: int | None = None,
    depth: int | None = None,
    no_recursion: bool = False,
    timeout: int = DEFAULT_TIMEOUT,
) -> dict:

    result = {"target": _build_url(host, port), "found": [], "error": None}

    if not toolrunner.has_tool("feroxbuster"):
        result["error"] = "feroxbuster not found in PATH"
        print(f"! {result['error']} - skipping directory brute-force.", file=sys.stderr)
        return result

    err = toolrunner.file_missing(wordlist, "wordlist")
    if err:
        result["error"] = err
        print(f"[!] {result['error']}", file=sys.stderr)
        return result

    result["interrupted"] = False

    # feroxbuster is launched via Popen (not toolrunner.run) because its Ctrl+C
    # handling is interactive: stop, ask to save, keep partial findings.
    with toolrunner.temp_output(".json") as tmp_path:
        cmd = [
            "feroxbuster",
            "-u", result["target"],
            "-w", wordlist,
            "-o", tmp_path,
            "--json",
        ]
        if threads:
            cmd += ["-t", str(threads)]
        if extensions:
            cmd += ["-x", ",".join(extensions)]
        if no_recursion:
            cmd += ["--no-recursion"]
        elif depth is not None:
            cmd += ["-d", str(depth)]

        print(f"\033[2mferoxbuster {result['target']}  ·  Ctrl+C to stop and save\033[0m")
        sys.stdout.flush()

        proc = subprocess.Popen(cmd)
        try:
            proc.wait(timeout=timeout)
        except KeyboardInterrupt:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

            print()
            try:
                answer = input("[?] Stop the scan and save findings? (y/n): ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                answer = "n"

            if answer != "y":
                result["error"] = "scan aborted, results discarded"
                return result

            result["interrupted"] = True
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            result["error"] = f"feroxbuster timed out ({timeout}s)"
            print(f"[!] {result['error']}", file=sys.stderr)
            return result
        else:
            if proc.returncode != 0:
                result["error"] = "feroxbuster exited with an error (see output above)"
                print(f"[!] {result['error']}", file=sys.stderr)
                return result

        print()

        try:
            with open(tmp_path, encoding="utf-8") as f:
                for line in f:
                    entry = _parse_ferox_line(line)
                    if entry:
                        result["found"].append(entry)
        except OSError as exc:
            result["error"] = f"could not read feroxbuster output: {exc}"
            print(f"[!] {result['error']}", file=sys.stderr)

    result["found"].sort(key=lambda e: e["path"])
    return result


def load_dir_bruteforce(path: str, host: str, port: int) -> dict:
    """Parse an existing feroxbuster --json output file into the pipeline schema,
    without launching feroxbuster. Mirrors `nmap --from-xml`."""
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
