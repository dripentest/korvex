#!/usr/bin/env python3
import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import toolrunner
from analyzer import analyze
from dir_bruteforce import load_dir_bruteforce, run_dir_bruteforce
from fingerprinter import fingerprint_target
from graph_builder import GATED_STATUSES, build_graph
from nmap_parser import NmapParseError, parse_nmap_xml
from passive import passive_paths, run_passive
from renderer import render_to_file
from reporter import _BOLD, _DIM, _RESET, PRIORITY_COLORS, render_report
from subs import run_subs, run_subs_from_file
from vhost import load_vhost, run_vhost
from signatures import INTERESTING_PATHS, match_path


def _parse_ports(spec) -> list[int]:
    if not spec:
        return []
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = (int(x) for x in part.split("-", 1))
                if a > b:
                    print(f"! ignoring reversed port range '{part}'", file=sys.stderr)
                    continue
                out.extend(range(a, b + 1))
            else:
                out.append(int(part))
        except ValueError:
            print(f"! invalid --port value '{part}' (expected a number or a-b range)", file=sys.stderr)
            sys.exit(2)
    return out


def run_nmap(target: str, ports: str | None) -> dict:
    empty = {"ports": [], "os": "", "address": target}
    if not toolrunner.has_tool("nmap"):
        print("! nmap not found in PATH - skipping nmap scan, using HTTP only.", file=sys.stderr)
        return empty

    with toolrunner.temp_output(".xml") as tmp_path:
        cmd = ["nmap", "-sV", "-sC", "-oX", tmp_path]
        if ports:
            cmd += ["-p", str(ports)]
        cmd.append(target)

        print(f"{_DIM}nmap {target}{_RESET}")
        sys.stdout.flush()
        err, _ = toolrunner.run(cmd, timeout=300, label="nmap")
        if err:
            print(f"! {err}", file=sys.stderr)
            return empty
        print()

        try:
            return parse_nmap_xml(tmp_path)
        except NmapParseError as exc:
            print(f"! could not parse nmap output: {exc}", file=sys.stderr)
            return empty


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _save_json(data: dict, path: str) -> None:
    _ensure_parent(path)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{_DIM}saved {path}{_RESET}")


def _safe_name(target: str) -> str:
    return target.replace("/", "_").replace(":", "_")


def _target_dir(target: str) -> str:
    # One folder per host, named after the host verbatim (e.g. target.thm ->
    # target.thm/, app.example.com -> app.example.com/). No label stripping — the
    # output path always matches the target the user typed.
    return _safe_name(target) or target


def _default_out(target: str, filename: str) -> str:
    return str(Path(_target_dir(target)) / filename)


def cmd_nmap(args: argparse.Namespace) -> None:
    if args.from_xml:
        try:
            nmap_data = parse_nmap_xml(args.from_xml)
        except NmapParseError as exc:
            print(f"! {exc}", file=sys.stderr)
            sys.exit(1)
        target_for_name = args.target or nmap_data.get("address") or "target"
    else:
        if not args.target:
            print("! provide --target or --from-xml", file=sys.stderr)
            sys.exit(1)
        nmap_data = run_nmap(args.target, args.port)
        target_for_name = args.target

    nmap_data["host"] = target_for_name
    out = args.output or _default_out(target_for_name, f"{_safe_name(target_for_name)}.nmap.json")
    _save_json(nmap_data, out)

    hosts = nmap_data.get("hosts") or [{"address": nmap_data.get("address", ""), "ports": nmap_data["ports"]}]
    if len(hosts) > 1:
        for h in hosts:
            label = h.get("address") or "?"
            ports = ", ".join(str(p["port"]) for p in h["ports"]) or "—"
            print(f"{label:<18}{ports}")
    elif nmap_data["ports"]:
        print(f"ports  {', '.join(str(p['port']) for p in nmap_data['ports'])}")
    else:
        print(f"{_DIM}no open ports found{_RESET}")


def cmd_dirs(args: argparse.Namespace) -> None:
    if args.from_ferox:
        result = load_dir_bruteforce(args.from_ferox, args.target, args.port)
    else:
        if not args.wordlist:
            print("! provide -w/--wordlist (or --from-ferox to import an existing scan)", file=sys.stderr)
            sys.exit(1)
        result = run_dir_bruteforce(
            args.target,
            args.port,
            args.wordlist,
            extensions=args.extensions.split(",") if args.extensions else None,
            threads=args.threads,
            depth=args.depth,
            no_recursion=args.no_recursion,
        )

    if result["error"] and not result["found"]:
        print(f"! {result['error']}")
        return

    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}-{args.port}.dirs.json")
    _save_json(result, out)

    head = f"{args.target}:{args.port}"
    tag = " · partial" if result.get("interrupted") else ""
    print(f"\n{_BOLD}{head}{_RESET}   {_DIM}{len(result['found'])} paths{tag}{_RESET}")
    print(f"{_DIM}{'─' * len(head)}{_RESET}")

    interesting = []
    gated = []
    noise = 0
    for entry in result["found"]:
        sig = match_path(entry["path"])
        if sig or entry["path"] in INTERESTING_PATHS:
            interesting.append((entry, sig))
        elif entry["status"] in GATED_STATUSES:
            gated.append(entry)
        else:
            noise += 1

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}
    interesting.sort(key=lambda t: order.get(t[1]["priority"] if t[1] else None, 4))
    for entry, sig in interesting:
        if sig:
            tag = f"{PRIORITY_COLORS.get(sig['priority'], '')}{sig['priority']:<8}{_RESET}"
            print(f"  {tag}{entry['path']}")
            print(f"          {_DIM}{' · '.join(sig['hypotheses'])}{_RESET}")
        else:
            print(f"  {'':<8}{entry['path']}")

    if gated:
        joined = " · ".join(f"{e['status']} {e['path']}" for e in sorted(gated, key=lambda e: e["path"]))
        print(f"\n  {_DIM}gated{_RESET}   {joined}")

    if noise:
        print(f"  {_DIM}noise   {noise} paths → hub{_RESET}")

    if args.graph:
        graph = build_graph(args.target, dirs=[result])
        gout = _default_out(args.target, f"{_safe_name(args.target)}-{args.port}.graph.html")
        _ensure_parent(gout)
        render_to_file(graph, args.target, gout)
        print(f"\n{_DIM}graph {gout}{_RESET}")
        print(f"{_DIM}      file://{Path(gout).resolve()}{_RESET}")


def _load_json_file(path: str) -> dict | None:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"! could not read {path}: {exc}", file=sys.stderr)
        return None


def _load_open_ports(nmap_json: str | None) -> list[int]:
    if not nmap_json:
        return []
    data = _load_json_file(nmap_json)
    return [p["port"] for p in data.get("ports", [])] if data else []


def _fingerprint_ports(target: str, ports: list[int], open_ports: list[int]) -> list[tuple]:
    """Fingerprint several ports concurrently (bounded), results in input order —
    so a port range no longer serializes 8s-per-filtered-port timeouts."""
    def job(port):
        fp_result = fingerprint_target(target, port)
        return port, fp_result, analyze(fp_result, open_ports=open_ports)

    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
        return list(pool.map(job, ports))


def cmd_fingerprint(args: argparse.Namespace) -> None:
    ports = _parse_ports(args.port)
    open_ports = _load_open_ports(args.nmap_json) or ports
    for port, fp_result, analysis in _fingerprint_ports(args.target, ports, open_ports):
        print(render_report(args.target, port, fp_result, analysis))


def cmd_subs(args: argparse.Namespace) -> None:
    if args.from_txt:
        result = run_subs_from_file(args.from_txt, args.target, threads=args.threads or 40)
    else:
        result = run_subs(args.target, threads=args.threads or 40)
    if result["error"] and not result["live"] and not result["resolved_no_web"]:
        print(f"! {result['error']}")
        return

    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}.subs.json")
    _save_json(result, out)

    head = args.target
    live, noweb = result["live"], result["resolved_no_web"]
    print(f"\n{_BOLD}{head}{_RESET}   {_DIM}subdomains · {result['found']} found · {len(live)} live{_RESET}")
    print(f"{_DIM}{'─' * len(head)}{_RESET}")

    for e in live:
        print(f"  {e['status']:<4}{_DIM}{e['scheme']:<6}{_RESET}{e['subdomain']:<40}{_DIM}{', '.join(e['ips'][:2])}{_RESET}")
    if noweb:
        print(f"\n  {_DIM}resolve, no web ({len(noweb)}){_RESET}")
        for e in noweb:
            print(f"    {e['subdomain']:<40}{_DIM}{', '.join(e['ips'][:2])}{_RESET}")
    if result["dead"]:
        print(f"\n  {_DIM}{result['dead']} dead (no DNS){_RESET}")


def cmd_vhost(args: argparse.Namespace) -> None:
    if args.from_ffuf:
        result = load_vhost(args.from_ffuf, args.target, args.port, connect_host=args.ip)
    else:
        if not args.wordlist:
            print("! provide -w/--wordlist (or --from-ffuf to import an existing scan)", file=sys.stderr)
            sys.exit(1)
        result = run_vhost(args.target, args.port, args.wordlist,
                           connect_host=args.ip, threads=args.threads, filter_size=args.filter_size)
    if result["error"] and not result["found"]:
        print(f"! {result['error']}")
        return

    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}-{args.port}.vhost.json")
    _save_json(result, out)

    head = f"{args.target}:{args.port}"
    print(f"\n{_BOLD}{head}{_RESET}   {_DIM}vhosts · {len(result['found'])} found{_RESET}")
    print(f"{_DIM}{'─' * len(head)}{_RESET}")
    if not result["found"]:
        print(f"  {_DIM}nothing found (tune -fs if the baseline slipped through){_RESET}")
    for e in result["found"]:
        print(f"  {e['status']:<4}{e['vhost']:<40}{_DIM}{e['length']} bytes · {e['words']} words{_RESET}")


def cmd_passive(args: argparse.Namespace) -> None:
    result = run_passive(args.target, args.port)
    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}-{args.port}.passive.json")
    _save_json(result, out)

    head = f"{args.target}:{args.port}"
    print(f"\n{_BOLD}{head}{_RESET}   {_DIM}passive recon{_RESET}")
    print(f"{_DIM}{'─' * len(head)}{_RESET}")

    if result["robots"]:
        print(f"  {_DIM}robots{_RESET}    " + " · ".join(result["robots"]))
    if result["sitemap"]:
        extra = f"  (+{len(result['sitemap']) - 20})" if len(result["sitemap"]) > 20 else ""
        print(f"  {_DIM}sitemap{_RESET}   " + " · ".join(result["sitemap"][:20]) + extra)
    if result["js_files"]:
        print(f"  {_DIM}js files{_RESET}  " + ", ".join(result["js_files"]))

    if result["js_endpoints"]:
        print(f"\n  {_DIM}js endpoints{_RESET}")
        for e in result["js_endpoints"]:
            print(f"    {e}")

    if result["js_secrets"]:
        print(f"\n  {_DIM}secrets{_RESET}")
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        for s in sorted(result["js_secrets"], key=lambda s: order.get(s["priority"], 4)):
            tag = f"{PRIORITY_COLORS.get(s['priority'], '')}{s['priority']:<9}{_RESET}"
            print(f"    {tag}{s['type']:<16}{s['value']}  {_DIM}{s['source']}{_RESET}")

    if not any((result["robots"], result["sitemap"], result["js_endpoints"], result["js_secrets"])):
        print(f"  {_DIM}nothing discovered{_RESET}")

    if args.graph:
        graph = build_graph(args.target, dirs=[{"target": result["target"], "found": passive_paths(result)}])
        gout = _default_out(args.target, f"{_safe_name(args.target)}-{args.port}.graph.html")
        _ensure_parent(gout)
        render_to_file(graph, args.target, gout)
        print(f"\n{_DIM}graph {gout}{_RESET}")
        print(f"{_DIM}      file://{Path(gout).resolve()}{_RESET}")


def cmd_graph(args: argparse.Namespace) -> None:
    subs = _load_json_file(args.subs_json) if args.subs_json else None

    nmaps = []
    for path in args.nmap_json or []:
        nd = _load_json_file(path)
        if not nd:
            continue
        # A multi-host scan expands into one routed entry per host so their ports
        # are not collapsed onto a single node.
        hosts = nd.get("hosts")
        if hosts and len(hosts) > 1:
            for h in hosts:
                nmaps.append({"host": h.get("address"), "address": h.get("address"),
                              "os": h.get("os", ""), "ports": h.get("ports", [])})
        else:
            nmaps.append(nd)

    dirs = []
    for path in args.dirs_json or []:
        d = _load_json_file(path)
        if d:
            dirs.append(d)
    for path in args.passive_json or []:
        pv = _load_json_file(path)
        if pv:
            dirs.append({"target": pv["target"], "found": passive_paths(pv)})

    # per-host open-port map (host -> its open ports) for evidence-gating in analyze()
    host_open: dict[str, list[int]] = {}
    for nd in nmaps:
        host = nd.get("host") or nd.get("address") or args.target
        host_open.setdefault(host, []).extend(p["port"] for p in nd.get("ports", []))

    fingerprints = []
    if not args.no_fingerprint:
        jobs = []
        for nd in nmaps:
            host = nd.get("host") or nd.get("address") or args.target
            for p in nd.get("ports", []):
                if "http" in (p.get("service") or ""):
                    jobs.append((host, p["port"]))
        for port in args.port or []:
            jobs.append((args.target, port))
        uniq = list(dict.fromkeys(jobs))

        def gjob(hp):
            host, port = hp
            fp_result = fingerprint_target(host, port)
            return host, port, fp_result, analyze(fp_result, open_ports=host_open.get(host) or [port])

        if uniq:
            with ThreadPoolExecutor(max_workers=min(8, len(uniq))) as pool:
                fingerprints = list(pool.map(gjob, uniq))

    graph = build_graph(args.target, subs=subs, nmap=nmaps, fingerprints=fingerprints, dirs=dirs)
    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}.graph.html")
    _ensure_parent(out)
    render_to_file(graph, args.target, out)
    print(f"graph  {out}   {_DIM}{len(graph['nodes'])} nodes, {len(graph['edges'])} edges{_RESET}")
    print(f"{_DIM}       file://{Path(out).resolve()}{_RESET}")


def cmd_scan(args: argparse.Namespace) -> None:
    if args.no_nmap:
        if not args.port:
            print("! --no-nmap requires --port", file=sys.stderr)
            sys.exit(1)
        open_ports = _parse_ports(args.port)
        http_ports = list(open_ports)
    else:
        nmap_data = run_nmap(args.target, args.port)
        if not nmap_data["ports"]:
            print(f"{_DIM}nmap found no open ports (or is unavailable){_RESET}")
            return
        open_ports = [p["port"] for p in nmap_data["ports"]]
        http_ports = [p["port"] for p in nmap_data["ports"] if "http" in p["service"]]
        if not http_ports:
            print(f"{_DIM}no HTTP services found. Ports: {open_ports}{_RESET}")
            return

    for port, fp_result, analysis in _fingerprint_ports(args.target, http_ports, open_ports):
        print(render_report(args.target, port, fp_result, analysis))


_HELP_EPILOG = """\
commands:
  scan          nmap + HTTP fingerprint in one run (quick start)
  nmap          nmap only -> JSON (ports/services/versions)
  fingerprint   HTTP only: stack from headers/cookies, paths, vulnerabilities
  dirs          feroxbuster only: paths + per-path hypotheses (Ctrl+C saves)
  subs          subdomain enum (subfinder + liveness) - broad targets
  vhost         vhost brute via ffuf (Host-header fuzzing) - boxes
  passive       robots/sitemap paths + endpoints and secrets from linked JS
  graph         interactive HTML graph from saved nmap/dirs + fingerprint

typical flow:
  fp subs    --target example.com                   # live subdomains (broad target)
  fp scan    --target host                          # what stack, where to dig
  fp nmap    --target host -o t.nmap.json           # ports (once)
  fp passive --target host --port 80                # robots/sitemap/JS leads (no brute)
  fp dirs    --target host --port 80 -w wl.txt --graph
  fp graph   --target host --nmap-json t.nmap.json --dirs-json host-80.dirs.json

notes:
  - subcommands are independent: fuzzing more dirs does not re-run nmap
  - import an existing tool run instead of launching it (your own flags):
      nmap --from-xml  ·  dirs --from-ferox  ·  vhost --from-ffuf  ·  subs --from-txt
  - dirs: -t threads, -d recursion depth, --no-recursion, Ctrl+C saves findings
  - per-path hypotheses (/login -> SQLi/brute), 30x/401/403 -> "auth-gated"
  - output is written to the current directory; `fp <command> -h` for details
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fp",
        description="Stack Fingerprinter - stack detection, directory brute-forcing, vulnerability prioritization, attack graph.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="{scan,nmap,fingerprint,dirs,subs,vhost,passive,graph}")

    p_nmap = sub.add_parser("nmap", help="nmap scan only, saves the result as JSON")
    p_nmap.add_argument("--target", help="Target host")
    p_nmap.add_argument("--port", help="Scan only these ports, comma-separated or ranges (e.g. 80,443,1337 or 8000-8100)")
    p_nmap.add_argument("--from-xml", help="Parse an existing nmap XML instead of a live scan")
    p_nmap.add_argument("-o", "--output", help="Where to save JSON (default <target>.nmap.json)")
    p_nmap.set_defaults(func=cmd_nmap)

    p_dirs = sub.add_parser("dirs", help="feroxbuster directory brute-force only (Ctrl+C to stop and save findings)")
    p_dirs.add_argument("--target", required=True, help="Target host")
    p_dirs.add_argument("--port", type=int, required=True, help="Target port")
    p_dirs.add_argument("-w", "--wordlist", help="Path to wordlist (required unless --from-ferox)")
    p_dirs.add_argument("--from-ferox", help="Parse an existing feroxbuster --json output instead of a live scan")
    p_dirs.add_argument("-x", "--extensions", help="Comma-separated extensions (php,html,...)")
    p_dirs.add_argument("-t", "--threads", type=int, help="Number of feroxbuster threads")
    p_dirs.add_argument("-d", "--depth", type=int, help="feroxbuster recursion depth (default 4; 0 = unlimited)")
    p_dirs.add_argument("--no-recursion", action="store_true", help="Disable recursion (scan top level only)")
    p_dirs.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.dirs.json)")
    p_dirs.add_argument("--graph", action="store_true", help="Also build an HTML graph from the found paths")
    p_dirs.set_defaults(func=cmd_dirs)

    p_fp = sub.add_parser("fingerprint", help="HTTP fingerprint + report for a single port")
    p_fp.add_argument("--target", required=True, help="Target host")
    p_fp.add_argument("--port", required=True, help="Target HTTP port(s), comma-separated (e.g. 80,443,8080)")
    p_fp.add_argument("--nmap-json", help="Previously saved `nmap` result - adds open ports to the analysis")
    p_fp.set_defaults(func=cmd_fingerprint)

    p_scan = sub.add_parser("scan", help="nmap + fingerprint in one run (combined mode)")
    p_scan.add_argument("--target", required=True, help="Target host")
    p_scan.add_argument("--port", help="Target port(s), comma-separated (e.g. 80,443,1337); restricts nmap or, with --no-nmap, fingerprinted directly")
    p_scan.add_argument("--no-nmap", action="store_true", help="Do not run nmap (requires --port)")
    p_scan.set_defaults(func=cmd_scan)

    p_subs = sub.add_parser("subs", help="Subdomain enumeration via subfinder + built-in liveness check (broad targets)")
    p_subs.add_argument("--target", required=True, help="Root domain (e.g. example.com)")
    p_subs.add_argument("--from-txt", help="Run the liveness check over subdomain names from a file (one per line) instead of running subfinder")
    p_subs.add_argument("-t", "--threads", type=int, help="Liveness-check concurrency (default 40)")
    p_subs.add_argument("-o", "--output", help="Where to save JSON (default <target>.subs.json)")
    p_subs.set_defaults(func=cmd_subs)

    p_vhost = sub.add_parser("vhost", help="Virtual-host brute-force via ffuf (Host-header fuzzing; for boxes)")
    p_vhost.add_argument("--target", required=True, help="Base domain fuzzed in Host: FUZZ.<target> (e.g. target.thm)")
    p_vhost.add_argument("--port", type=int, required=True, help="Target port")
    p_vhost.add_argument("-w", "--wordlist", help="Path to subdomain wordlist (required unless --from-ffuf)")
    p_vhost.add_argument("--from-ffuf", help="Parse an existing ffuf JSON output (-of json) instead of a live scan")
    p_vhost.add_argument("--ip", help="Connect to this IP/host instead of --target")
    p_vhost.add_argument("-t", "--threads", type=int, help="Number of ffuf threads")
    p_vhost.add_argument("-fs", "--filter-size", type=int, help="Filter this response size (bytes); default is ffuf -ac auto-calibration")
    p_vhost.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.vhost.json)")
    p_vhost.set_defaults(func=cmd_vhost)

    p_pass = sub.add_parser("passive", help="Passive recon: robots/sitemap paths + endpoints and secrets from linked JS")
    p_pass.add_argument("--target", required=True, help="Target host")
    p_pass.add_argument("--port", type=int, required=True, help="Target HTTP port")
    p_pass.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.passive.json)")
    p_pass.add_argument("--graph", action="store_true", help="Also build an HTML graph from discovered paths")
    p_pass.set_defaults(func=cmd_passive)

    p_graph = sub.add_parser("graph", help="Build the interactive HTML graph from saved results (subs/nmap/dirs/passive) + fingerprint")
    p_graph.add_argument("--target", required=True, help="Root domain (graph root)")
    p_graph.add_argument("--subs-json", help="Saved `subs` result — adds subdomains under the root")
    p_graph.add_argument("--nmap-json", action="append", help="Saved `nmap` result (repeatable; routed to its host)")
    p_graph.add_argument("--dirs-json", action="append", help="Saved `dirs` result (repeatable; routed to its host)")
    p_graph.add_argument("--passive-json", action="append", help="Saved `passive` result (repeatable; routed to its host)")
    p_graph.add_argument("--port", type=int, action="append", help="HTTP port on --target to fingerprint (repeatable)")
    p_graph.add_argument("--no-fingerprint", action="store_true", help="No HTTP requests - build the graph from saved data only")
    p_graph.add_argument("-o", "--output", help="Output HTML (default <target>.graph.html)")
    p_graph.set_defaults(func=cmd_graph)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if not getattr(args, "func", None):
        parser.print_help()
        return
    args.func(args)


if __name__ == "__main__":
    main()
