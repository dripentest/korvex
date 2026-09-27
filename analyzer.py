from confidence import score_stack
from signatures import (
    HEADER_SIGNATURES,
    PORT_SIGNATURES,
    PRIORITY,
    SPRING_BOOT_SIGNATURE,
    match_cookie,
)


GATING_PATHS = [
    "/console", "/.git", "/.env", "/actuator", "/graphql",
    "/swagger", "/phpmyadmin", "/adminer", "/server-status", "/xmlrpc",
]


def _priority_of(vuln: str) -> str:
    vuln_lower = vuln.lower()
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        for known in PRIORITY.get(level, []):
            if known.lower() in vuln_lower or vuln_lower in known.lower():
                return level
    return "LOW"


def analyze(fp_result: dict, open_ports: list[int] | None = None) -> dict:
    cookies = fp_result.get("cookies", [])
    headers = fp_result.get("headers", {})

    matches = []

    for cookie_name in cookies:
        sig = match_cookie(cookie_name)
        if sig:
            matches.append({"source": f"Cookie: {cookie_name}", **sig})

    for header_name, header_value in headers.items():
        if not header_value:
            continue
        header_sigs = HEADER_SIGNATURES.get(header_name, {})
        for needle, sig in header_sigs.items():
            if needle.lower() in header_value.lower():
                matches.append({"source": f"Header: {header_name}: {header_value}", **sig})

    if "JSESSIONID" in cookies and headers.get("x-application-context"):
        matches.append({
            "source": "Cookie: JSESSIONID + Header: X-Application-Context",
            **SPRING_BOOT_SIGNATURE,
        })

    cookie_stacks = [m["stack"] for m in matches if m["source"].startswith("Cookie:")]
    header_stacks = [m["stack"] for m in matches if m["source"].startswith("Header:")]
    confidence, confidence_note = score_stack(cookie_stacks, header_stacks)

    db_candidates = []
    for m in matches:
        for db in m.get("db", []):
            if db not in db_candidates:
                db_candidates.append(db)

    all_vulns = []
    for m in matches:
        for v in m.get("vulns", []):
            if v not in all_vulns:
                all_vulns.append(v)

    open_ports = open_ports or []
    for port in open_ports:
        port_sig = PORT_SIGNATURES.get(port)
        if port_sig:
            for v in port_sig["vulns"]:
                if v not in all_vulns:
                    all_vulns.append(v)

    for missing in fp_result.get("security_headers_missing", []):
        v = f"Missing security header: {missing}"
        if v not in all_vulns:
            all_vulns.append(v)

    suppressed = []
    if not fp_result.get("error"):
        found_paths = {e.split(" ")[0].strip() for e in fp_result.get("interesting_paths", [])}
        kept = []
        for v in all_vulns:
            gate = next((gp for gp in GATING_PATHS if gp in v), None)
            if gate and not any(fp.startswith(gate) for fp in found_paths):
                suppressed.append({"vuln": v, "path": gate})
            else:
                kept.append(v)
        all_vulns = kept

    vulns_by_priority = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    for v in all_vulns:
        vulns_by_priority[_priority_of(v)].append(v)

    return {
        "matches": matches,
        "confidence": confidence,
        "confidence_note": confidence_note,
        "db_candidates": db_candidates,
        "vulns_by_priority": vulns_by_priority,
        "suppressed": suppressed,
    }
