import xml.etree.ElementTree as ET


class NmapParseError(Exception):
    pass


def parse_nmap_xml(path: str) -> dict:
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise NmapParseError(f"Invalid nmap XML ({path}): {exc}") from exc
    except OSError as exc:
        raise NmapParseError(f"Could not read file {path}: {exc}") from exc

    root = tree.getroot()
    if root.tag != "nmaprun":
        raise NmapParseError(f"{path} does not look like nmap -oX output (root tag: {root.tag})")

    hosts = []
    for host in root.findall("host"):
        address_el = host.find("address")
        address = address_el.get("addr", "") if address_el is not None else ""

        ports = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                service_el = port_el.find("service")
                service_name = service_el.get("name", "") if service_el is not None else ""
                product = service_el.get("product", "") if service_el is not None else ""
                version = service_el.get("version", "") if service_el is not None else ""
                version_str = f"{product} {version}".strip()

                ports.append({
                    "port": int(port_el.get("portid")),
                    "service": service_name,
                    "version": version_str,
                })

        os_name = ""
        os_el = host.find("os")
        if os_el is not None:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                os_name = osmatch.get("name", "")

        hosts.append({"address": address, "os": os_name, "ports": ports})

    # Flat shape = first host (back-compat for the single-host common case);
    # `hosts` keeps every host's own ports so multi-host scans are not blended.
    first = hosts[0] if hosts else {"address": "", "os": "", "ports": []}
    return {
        "ports": first["ports"],
        "os": first["os"],
        "address": first["address"],
        "hosts": hosts,
    }
