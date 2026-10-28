#!/usr/bin/env python3
import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from analyzer import analyze
from dir_bruteforce import load_dir_bruteforce
from fingerprinter import fingerprint_target
from graph_builder import GATED_STATUSES, build_graph
from nmap_parser import NmapParseError, parse_nmap_xml
from passive import passive_paths, run_passive
from renderer import render_to_file
from reporter import _BOLD, _DIM, _RESET, PRIORITY_COLORS, render_report
from subs import run_subs_from_file
from vhost import load_vhost
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


def _ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def _save_json(data: dict, path: str) -> None:
    _ensure_parent(path)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{_DIM}saved {path}{_RESET}")


# A target must look like a hostname/IP: it is passed as a positional argument to
# nmap and embedded in URLs/Host headers, so a leading '-' (argument injection) or
# whitespace/path characters are rejected rather than sanitised away.
_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _target_arg(value: str) -> str:
    v = value.strip()
    if not _TARGET_RE.match(v):
        raise argparse.ArgumentTypeError(
            f"invalid target {value!r}: expected a hostname or IP "
            "(letters, digits, '.', '-', '_'; no leading '-', no spaces or slashes)")
    return v


def _safe_name(target: str) -> str:
    # Whitelist the charset and drop leading dots so a crafted target can never
    # escape the output folder (e.g. '..', '../etc').
    name = _SAFE_NAME_RE.sub("_", target).lstrip(".")
    return name or "target"


def _target_dir(target: str) -> str:
    # One folder per host, named after the host verbatim (e.g. target.thm ->
    # target.thm/, app.example.com -> app.example.com/). No label stripping — the
    # output path always matches the target the user typed.
    return _safe_name(target) or target


def _default_out(target: str, filename: str) -> str:
    return str(Path(_target_dir(target)) / filename)


def _parse_headers(header_args, cookie) -> dict:
    headers = {}
    for raw in header_args or []:
        if ":" not in raw:
            print(f"! ignoring malformed --header '{raw}' (expected 'Name: value')", file=sys.stderr)
            continue
        k, v = raw.split(":", 1)
        headers[k.strip()] = v.strip()
    if cookie:
        headers["Cookie"] = cookie
    return headers


def _http_opts(args: argparse.Namespace) -> tuple[dict | None, dict | None]:
    proxy = getattr(args, "proxy", None)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = _parse_headers(getattr(args, "header", None), getattr(args, "cookie", None))
    return proxies, (headers or None)


def _save_fingerprint(target: str, port: int, fp_result: dict, analysis: dict) -> None:
    data = {"host": target, "port": port, "fp": fp_result, "analysis": analysis}
    out = _default_out(target, f"{_safe_name(target)}-{port}.fp.json")
    _save_json(data, out)


def cmd_nmap(args: argparse.Namespace) -> None:
    try:
        nmap_data = parse_nmap_xml(args.from_xml)
    except NmapParseError as exc:
        print(f"! {exc}", file=sys.stderr)
        sys.exit(1)
    target_for_name = args.target or nmap_data.get("address") or "target"

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
    result = load_dir_bruteforce(args.from_ferox, args.target, args.port)

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


def _fingerprint_ports(target: str, ports: list[int], open_ports: list[int], *,
                       proxies: dict | None = None, headers: dict | None = None,
                       schemes: dict | None = None) -> list[tuple]:
    """Fingerprint several ports concurrently (bounded), results in input order —
    so a port range no longer serializes 8s-per-filtered-port timeouts."""
    schemes = schemes or {}

    def job(port):
        fp_result = fingerprint_target(target, port, scheme=schemes.get(port),
                                       proxies=proxies, headers=headers)
        return port, fp_result, analyze(fp_result, open_ports=open_ports)

    if not ports:
        return []
    with ThreadPoolExecutor(max_workers=min(8, len(ports))) as pool:
        return list(pool.map(job, ports))


def cmd_fingerprint(args: argparse.Namespace) -> None:
    ports = _parse_ports(args.port)
    open_ports = _load_open_ports(args.nmap_json) or ports
    proxies, headers = _http_opts(args)
    for port, fp_result, analysis in _fingerprint_ports(args.target, ports, open_ports,
                                                        proxies=proxies, headers=headers):
        print(render_report(args.target, port, fp_result, analysis))
        _save_fingerprint(args.target, port, fp_result, analysis)


def cmd_subs(args: argparse.Namespace) -> None:
    result = run_subs_from_file(args.from_txt, args.target, threads=args.threads or 40)
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
    result = load_vhost(args.from_ffuf, args.target, args.port, connect_host=args.ip)
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
    proxies, headers = _http_opts(args)
    result = run_passive(args.target, args.port, proxies=proxies, headers=headers)
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

    # Saved `fingerprint`/`scan` results feed the graph without a live re-scan.
    fingerprints = []
    seen_fp = set()
    for path in args.fingerprint_json or []:
        fj = _load_json_file(path)
        if fj and "fp" in fj and "analysis" in fj:
            host = fj.get("host") or args.target
            fingerprints.append((host, fj.get("port"), fj["fp"], fj["analysis"]))
            seen_fp.add((host, fj.get("port")))

    if not args.no_fingerprint:
        jobs = []
        scheme_hint: dict[tuple, str] = {}
        for nd in nmaps:
            host = nd.get("host") or nd.get("address") or args.target
            for p in nd.get("ports", []):
                svc = p.get("service") or ""
                if "http" in svc:
                    jobs.append((host, p["port"]))
                    if "ssl" in svc or "https" in svc:
                        scheme_hint[(host, p["port"])] = "https"
        for port in args.port or []:
            jobs.append((args.target, port))
        uniq = [hp for hp in dict.fromkeys(jobs) if hp not in seen_fp]

        def gjob(hp):
            host, port = hp
            fp_result = fingerprint_target(host, port, scheme=scheme_hint.get(hp))
            return host, port, fp_result, analyze(fp_result, open_ports=host_open.get(host) or [port])

        if uniq:
            with ThreadPoolExecutor(max_workers=min(8, len(uniq))) as pool:
                fingerprints += list(pool.map(gjob, uniq))

    graph = build_graph(args.target, subs=subs, nmap=nmaps, fingerprints=fingerprints, dirs=dirs)
    out = args.output or _default_out(args.target, f"{_safe_name(args.target)}.graph.html")
    _ensure_parent(out)
    render_to_file(graph, args.target, out)
    print(f"graph  {out}   {_DIM}{len(graph['nodes'])} nodes, {len(graph['edges'])} edges{_RESET}")
    print(f"{_DIM}       file://{Path(out).resolve()}{_RESET}")


_HELP_EPILOG = """\
Korvex runs its own HTTP recon (fingerprint, passive) and correlates it with the
output of tools you run yourself (nmap, feroxbuster, ffuf, subfinder) into one graph.

live recon (Korvex's own, no external tools):
  fingerprint   HTTP: stack from headers/cookies, paths, CORS/deser, vulnerabilities
  passive       robots/sitemap paths + endpoints and secrets from linked JS

ingest a tool's output you ran yourself (normalise -> JSON):
  nmap   --from-xml    parse an nmap -oX file
  dirs   --from-ferox  parse a feroxbuster --json file
  vhost  --from-ffuf   parse an ffuf -of json file
  subs   --from-txt    liveness-check a list of subdomain names (resolve + HTTP probe)

build the picture:
  graph         interactive HTML graph from the saved JSON (subs/nmap/dirs/passive/fp)

examples:
  korvex fingerprint --target target.thm --port 80,443,8080    # live, several ports (concurrent)
  korvex passive     --target target.thm --port 80             # robots/sitemap/JS (no brute)

  # run tools yourself with any flags, then import their output:
  nmap -sV -sC -p- -oX s.xml target.thm
      korvex nmap  --from-xml s.xml     --target target.thm
  feroxbuster -u http://target.thm:80 -w wl.txt --rate-limit 20 --json -o fx.json
      korvex dirs  --from-ferox fx.json --target target.thm --port 80 --graph
  ffuf -w subs.txt:FUZZ -u http://10.10.1.5/ -H 'Host: FUZZ.target.thm' -ac -of json -o vh.json
      korvex vhost --from-ffuf vh.json  --target target.thm --port 80
  subfinder -d example.com -silent -o names.txt
      korvex subs  --from-txt names.txt --target example.com

  korvex graph --target target.thm --no-fingerprint \\
               --nmap-json target.thm/target.thm.nmap.json \\
               --dirs-json target.thm/target.thm-80.dirs.json \\
               --fingerprint-json target.thm/target.thm-80.fp.json

parameters:
  --port VALUE     single, list or range: 80,443,1337,8000-8100  (fingerprint)
  --proxy URL      route requests through a proxy, e.g. Burp http://127.0.0.1:8080
  -H 'Name: val'   extra request header, repeatable (e.g. 'Authorization: Bearer <jwt>')
  --cookie STR     cookie header for areas behind login, e.g. 'session=abc; other=1'
  --nmap-json      fingerprint: feed saved nmap ports into the analysis
  --fingerprint-json  graph: render a saved fingerprint without a live re-scan
  --graph          dirs/passive: also build the interactive HTML graph

notes:
  - subcommands are independent; each writes JSON into a per-target folder (target.thm/)
  - --proxy / -H / --cookie apply to the live commands (fingerprint, passive)
  - http/https is auto-detected from the port and the nmap service
  - fingerprint saves <target>-<port>.fp.json for the graph
  - `korvex <command> -h` for the full flag list of a command
"""


def _add_http_opts(p: argparse.ArgumentParser) -> None:
    p.add_argument("--proxy", help="Route requests through this HTTP proxy (e.g. http://127.0.0.1:8080 for Burp)")
    p.add_argument("-H", "--header", action="append", metavar="'Name: value'",
                   help="Extra request header (repeatable) — e.g. authenticated fingerprinting")
    p.add_argument("--cookie", help="Cookie header value, e.g. 'session=abc; other=1'")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="korvex",
        description="Korvex - stack detection, directory brute-forcing, vulnerability prioritization, attack graph.",
        epilog=_HELP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="{fingerprint,passive,nmap,dirs,vhost,subs,graph}")

    p_nmap = sub.add_parser("nmap", help="Import an nmap -oX file into the pipeline schema")
    p_nmap.add_argument("--from-xml", required=True, help="nmap XML (-oX) file to parse")
    p_nmap.add_argument("--target", type=_target_arg, help="Target host (default: from the XML)")
    p_nmap.add_argument("-o", "--output", help="Where to save JSON (default <target>.nmap.json)")
    p_nmap.set_defaults(func=cmd_nmap)

    p_dirs = sub.add_parser("dirs", help="Import a feroxbuster --json output into the pipeline schema")
    p_dirs.add_argument("--from-ferox", required=True, help="feroxbuster --json output file to parse")
    p_dirs.add_argument("--target", type=_target_arg, required=True, help="Target host")
    p_dirs.add_argument("--port", type=int, required=True, help="Target port")
    p_dirs.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.dirs.json)")
    p_dirs.add_argument("--graph", action="store_true", help="Also build an HTML graph from the found paths")
    p_dirs.set_defaults(func=cmd_dirs)

    p_fp = sub.add_parser("fingerprint", help="HTTP fingerprint + report for a single port")
    p_fp.add_argument("--target", type=_target_arg, required=True, help="Target host")
    p_fp.add_argument("--port", required=True, help="Target HTTP port(s), comma-separated (e.g. 80,443,8080)")
    p_fp.add_argument("--nmap-json", help="Previously saved `nmap` result - adds open ports to the analysis")
    _add_http_opts(p_fp)
    p_fp.set_defaults(func=cmd_fingerprint)

    p_subs = sub.add_parser("subs", help="Liveness-check a list of subdomain names (resolve + HTTP probe)")
    p_subs.add_argument("--from-txt", required=True, help="File of subdomain names, one per line (e.g. a saved subfinder/amass run)")
    p_subs.add_argument("--target", type=_target_arg, required=True, help="Root domain (e.g. example.com)")
    p_subs.add_argument("-t", "--threads", type=int, help="Liveness-check concurrency (default 40)")
    p_subs.add_argument("-o", "--output", help="Where to save JSON (default <target>.subs.json)")
    p_subs.set_defaults(func=cmd_subs)

    p_vhost = sub.add_parser("vhost", help="Import an ffuf -of json output into the pipeline schema")
    p_vhost.add_argument("--from-ffuf", required=True, help="ffuf JSON output (-of json) file to parse")
    p_vhost.add_argument("--target", type=_target_arg, required=True, help="Base domain (Host: FUZZ.<target>)")
    p_vhost.add_argument("--port", type=int, required=True, help="Target port")
    p_vhost.add_argument("--ip", type=_target_arg, help="Connect-host used in the scan (for the target URL)")
    p_vhost.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.vhost.json)")
    p_vhost.set_defaults(func=cmd_vhost)

    p_pass = sub.add_parser("passive", help="Passive recon: robots/sitemap paths + endpoints and secrets from linked JS")
    p_pass.add_argument("--target", type=_target_arg, required=True, help="Target host")
    p_pass.add_argument("--port", type=int, required=True, help="Target HTTP port")
    p_pass.add_argument("-o", "--output", help="Where to save JSON (default <target>-<port>.passive.json)")
    p_pass.add_argument("--graph", action="store_true", help="Also build an HTML graph from discovered paths")
    _add_http_opts(p_pass)
    p_pass.set_defaults(func=cmd_passive)

    p_graph = sub.add_parser("graph", help="Build the interactive HTML graph from saved results (subs/nmap/dirs/passive) + fingerprint")
    p_graph.add_argument("--target", type=_target_arg, required=True, help="Root domain (graph root)")
    p_graph.add_argument("--subs-json", help="Saved `subs` result — adds subdomains under the root")
    p_graph.add_argument("--nmap-json", action="append", help="Saved `nmap` result (repeatable; routed to its host)")
    p_graph.add_argument("--dirs-json", action="append", help="Saved `dirs` result (repeatable; routed to its host)")
    p_graph.add_argument("--passive-json", action="append", help="Saved `passive` result (repeatable; routed to its host)")
    p_graph.add_argument("--fingerprint-json", action="append", help="Saved `fingerprint`/`scan` result (repeatable; no live re-scan)")
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
