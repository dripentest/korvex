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

    result = {"ports": [], "os": "", "address": ""}

    for host in root.findall("host"):
        if not result["address"]:
            address_el = host.find("address")
            if address_el is not None:
                result["address"] = address_el.get("addr", "")

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

                result["ports"].append({
                    "port": int(port_el.get("portid")),
                    "service": service_name,
                    "version": version_str,
                })

        os_el = host.find("os")
        if os_el is not None and not result["os"]:
            osmatch = os_el.find("osmatch")
            if osmatch is not None:
                result["os"] = osmatch.get("name", "")

    return result
