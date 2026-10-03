PRIORITY_COLORS = {
    "CRITICAL": "\033[31m",
    "HIGH": "\033[33m",
    "MEDIUM": "\033[36m",
    "LOW": "\033[32m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"
_BOLD = "\033[1m"

_PW = 8


def _label(text: str) -> str:
    return f"{_DIM}{text}{_RESET}"


def _kv(key: str, value: str) -> str:
    return f"  {key:<11}{value}"


def render_report(target: str, port: int, fp_result: dict, analysis: dict) -> str:
    head = f"{target}:{port}"
    out = ["", f"{_BOLD}{head}{_RESET}", f"{_DIM}{'─' * len(head)}{_RESET}"]

    if fp_result.get("error"):
        out.append(f"  error  {fp_result['error']}")
        return "\n".join(out) + "\n"

    stack = " · ".join(dict.fromkeys(m["stack"] for m in analysis["matches"])) or "—"
    conf = analysis["confidence"].lower()
    out.append(_kv("stack", f"{stack}   {_DIM}{conf}{_RESET}" if analysis["matches"] else "—"))
    out.append(_kv("database", ", ".join(analysis["db_candidates"]) or "—"))
    out.append(_kv("waf", fp_result.get("waf") or "—"))
    server = fp_result["headers"].get("server")
    if server:
        out.append(_kv("server", server))
    if fp_result["cookies"]:
        out.append(_kv("cookies", ", ".join(fp_result["cookies"])))

    if fp_result["interesting_paths"]:
        out.append("")
        out.append(_label("paths"))
        for entry in fp_result["interesting_paths"]:
            out.append(f"  {entry}")

    out.append("")
    out.append(_label("vulns"))
    any_vulns = False
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for v in analysis["vulns_by_priority"][level]:
            if v.startswith("Missing security header"):
                continue
            any_vulns = True
            tag = f"{PRIORITY_COLORS[level]}{level:<{_PW}}{_RESET}"
            out.append(f"  {tag}{v}")
    if not any_vulns:
        out.append(f"  {_DIM}—{_RESET}")

    out.append("")
    missing = list(fp_result["security_headers_missing"])
    missing += [f"cookie {w}" for w in analysis.get("cookie_weaknesses", [])]
    out.append(_kv("missing", " · ".join(missing) if missing else "—"))

    suppressed = analysis.get("suppressed", [])
    if suppressed:
        out.append(_kv("absent", " · ".join(s["path"] for s in suppressed)))

    return "\n".join(out) + "\n"
