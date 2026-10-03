import re
from urllib.parse import urlsplit

from signatures import INTERESTING_PATHS, match_path, stack_kind

PRIORITY_COLORS = {
    "CRITICAL": "#d7263d",
    "HIGH": "#f46036",
    "MEDIUM": "#ffc857",
    "LOW": "#2a9d8f",
}

TYPE_COLORS = {
    "target": "#5b8def",
    "subdomain": "#7d8cff",
    "port": "#3a4250",
    "stack": "#38b2c4",
    "db": "#7a49c9",
    "waf": "#8a4a12",
    "path": "#1f6d43",
    "gated": "#c9932b",
    "hub": "#232a38",
}

_NOWEB_COLOR = "#3a4250"

_REDIRECT_MARK = " → "
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
RESTRICTED_STATUSES = {401, 403}
GATED_STATUSES = REDIRECT_STATUSES | RESTRICTED_STATUSES


def _gated_hint(status) -> str:
    if status in REDIRECT_STATUSES:
        return "→ login?"
    if status == 401:
        return "unauth"
    if status == 403:
        return "forbidden"
    return "auth?"


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_") or "x"


_REFINE = {
    ("Unrestricted file upload", "php"): "Unrestricted file upload (.php/.phtml/.phar webshell)",
    ("Unrestricted file upload", "java"): "Unrestricted file upload (.jsp/.war webshell)",
    ("Unrestricted file upload", "node"): "Unrestricted file upload (path traversal/overwrite; no PHP shell)",
    ("Unrestricted file upload", "dotnet"): "Unrestricted file upload (.aspx/.asmx webshell)",
    ("template injection", "python"): "Server-side template injection - Jinja2 ({{7*7}})",
    ("template injection", "php"): "Server-side template injection - Twig/Smarty",
    ("template injection", "java"): "Server-side template injection - Freemarker/Velocity",
    ("template injection", "ruby"): "Server-side template injection - ERB/Slim",
    ("template injection", "node"): "Server-side template injection - EJS/Pug/Handlebars",
    ("SQL / NoSQL injection", "node"): "NoSQL injection ($ne/$gt/$regex/$where)",
    ("SQL / NoSQL injection", "php"): "SQL injection",
    ("SQL / NoSQL injection", "python"): "SQL injection",
    ("SQL / NoSQL injection", "java"): "SQL injection",
    ("SQL / NoSQL injection", "dotnet"): "SQL injection (MSSQL)",
    ("Local file inclusion", "php"): "Local file inclusion (php://filter, log poisoning, /proc/self/environ)",
    ("SQL/NoSQL injection", "node"): "NoSQL injection ($ne/$gt/$regex/$where)",
    ("SQL/NoSQL injection", "php"): "SQL injection",
}


def _refine_hyps(hyps: list[str], kind: str | None) -> list[str]:
    if not kind or not hyps:
        return hyps
    out, seen = [], set()
    for h in hyps:
        base, sep, anno = h.partition(" [")
        refined = base
        for (needle, k), replacement in _REFINE.items():
            if k == kind and needle in base:
                refined = replacement
                break
        full = refined + (sep + anno if sep else "")
        if full not in seen:
            seen.add(full)
            out.append(full)
    return out


class _Graph:
    def __init__(self):
        self._nodes: dict[str, dict] = {}
        self._edges: list[dict] = []
        self._edge_keys: set[tuple[str, str]] = set()

    def node(self, node_id: str, ntype: str, label: str, **meta) -> str:
        if node_id not in self._nodes:
            node = {"id": node_id, "type": ntype, "label": label, "color": TYPE_COLORS.get(ntype)}
            node.update({k: v for k, v in meta.items() if v is not None})
            self._nodes[node_id] = node
        return node_id

    def edge(self, src: str, dst: str) -> None:
        key = (src, dst)
        if key not in self._edge_keys and src in self._nodes and dst in self._nodes:
            self._edge_keys.add(key)
            self._edges.append({"from": src, "to": dst})

    def result(self) -> dict:
        return {"nodes": list(self._nodes.values()), "edges": self._edges}


def _port_from_url(url: str) -> int | None:
    try:
        return urlsplit(url).port
    except ValueError:
        return None


def _host_from_url(url: str) -> str | None:
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _host_anchor(g: _Graph, root: str, host: str | None, target: str) -> str:
    if not host or host == target:
        return root
    hid = g.node(f"host:{host}", "subdomain", host, host=host)
    g.edge(root, hid)
    return hid


def _ensure_port(g: _Graph, anchor: str, port: int | None) -> str:
    if port is None:
        return anchor
    pid = g.node(f"{anchor}::port:{port}", "port", str(port), port=port)
    g.edge(anchor, pid)
    return pid


def _add_fingerprint(g: _Graph, anchor: str, fp_result: dict, analysis: dict) -> None:
    stacks: list[str] = []
    stack_ids: dict[str, str] = {}
    for m in analysis.get("matches", []):
        if m["stack"] in stacks:
            continue
        stacks.append(m["stack"])
        sid = g.node(
            f"{anchor}::stack:{_slug(m['stack'])}",
            "stack",
            m["stack"],
            confidence=analysis.get("confidence"),
            source=m.get("source"),
        )
        stack_ids[m["stack"]] = sid
        g.edge(anchor, sid)

    def attach(dst: str) -> None:
        if stacks:
            for s in stacks:
                g.edge(stack_ids[s], dst)
        else:
            g.edge(anchor, dst)

    for db in analysis.get("db_candidates", []):
        attach(g.node(f"{anchor}::db:{_slug(db)}", "db", db))

    if fp_result.get("waf"):
        wid = g.node(f"waf:{anchor}", "waf", f"WAF: {fp_result['waf']}")
        g.edge(anchor, wid)

    for level, vulns in analysis.get("vulns_by_priority", {}).items():
        for v in vulns:
            vid = g.node(
                f"{anchor}::vuln:{level}:{_slug(v)}",
                "vuln",
                v,
                priority=level,
                color=PRIORITY_COLORS.get(level),
            )
            attach(vid)

    kind = stack_kind(stacks[0]) if stacks else None
    for entry in fp_result.get("interesting_paths", []):
        path, _, status = entry.partition(_REDIRECT_MARK)
        _path_node(g, anchor, path.strip(), status.strip() or None, kind=kind)


def _path_node(g: _Graph, anchor: str, path: str, status=None, sig=None, kind=None) -> None:
    if sig is None:
        sig = match_path(path)
    note = INTERESTING_PATHS.get(path)
    hyps = _refine_hyps(sig["hypotheses"], kind) if sig else None
    pid = g.node(
        f"{anchor}::path:{path}",
        "path",
        f"{path}\n{status}" if status is not None else path,
        path=path,
        status=status,
        note=note,
        hypotheses=hyps,
    )
    g.edge(anchor, pid)
    if sig:
        for h in hyps:
            hid = g.node(
                f"{anchor}::hyp:{sig['priority']}:{_slug(h)}",
                "vuln",
                h,
                priority=sig["priority"],
                color=PRIORITY_COLORS.get(sig["priority"]),
            )
            g.edge(pid, hid)


def _add_paths(g: _Graph, anchor: str, found: list[dict], kind: str | None = None) -> None:
    unknown = []
    for e in found:
        path = e["path"]
        status = e.get("status")
        sig = match_path(path)
        if sig or path in INTERESTING_PATHS:
            _path_node(g, anchor, path, status, sig=sig, kind=kind)
        elif status in GATED_STATUSES:
            rid = g.node(
                f"{anchor}::gated:{path}",
                "gated",
                f"{path}\n{status} {_gated_hint(status)}",
                path=path,
                status=status,
            )
            g.edge(anchor, rid)
        else:
            unknown.append(path)

    if unknown:
        hid = g.node(
            f"hub:{anchor}",
            "hub",
            f"Other paths: {len(unknown)}",
            paths=sorted(unknown),
        )
        g.edge(anchor, hid)


def build_graph(
    target: str,
    *,
    subs: dict | None = None,
    nmap: list[dict] | None = None,
    fingerprints: list[tuple] | None = None,
    dirs: list[dict] | None = None,
) -> dict:
    g = _Graph()
    root = g.node("target", "target", target)

    if subs:
        for e in subs.get("live", []):
            sd = e["subdomain"]
            label = f"{sd}\n{e.get('status', '')} {e.get('scheme', '')}".strip()
            g.node(f"host:{sd}", "subdomain", label, host=sd,
                   status=e.get("status"), scheme=e.get("scheme"), ips=e.get("ips"))
            g.edge(root, f"host:{sd}")
        for e in subs.get("resolved_no_web", []):
            sd = e["subdomain"]
            g.node(f"host:{sd}", "subdomain", f"{sd}\n(no web)", host=sd,
                   ips=e.get("ips"), color=_NOWEB_COLOR)
            g.edge(root, f"host:{sd}")

    for nd in (nmap or []):
        host = nd.get("host") or nd.get("address") or target
        anchor = _host_anchor(g, root, host, target)
        for p in nd.get("ports", []):
            label = f"{p['port']}/{p['service']}" if p.get("service") else str(p["port"])
            if p.get("version"):
                label += f"\n{p['version']}"
            pid = g.node(f"{anchor}::port:{p['port']}", "port", label, port=p["port"], service=p.get("service"))
            g.edge(anchor, pid)

    hostport_kind: dict[tuple, str | None] = {}
    for host, port, fp_result, analysis in (fingerprints or []):
        anchor = _host_anchor(g, root, host, target)
        panchor = _ensure_port(g, anchor, port)
        _add_fingerprint(g, panchor, fp_result, analysis)
        matches = analysis.get("matches", [])
        hostport_kind[(host, port)] = stack_kind(matches[0]["stack"]) if matches else None

    for d in (dirs or []):
        url = d.get("target", "")
        host = _host_from_url(url) or target
        port = _port_from_url(url)
        anchor = _host_anchor(g, root, host, target)
        panchor = _ensure_port(g, anchor, port)
        _add_paths(g, panchor, d.get("found", []), kind=hostport_kind.get((host, port)))

    return g.result()
