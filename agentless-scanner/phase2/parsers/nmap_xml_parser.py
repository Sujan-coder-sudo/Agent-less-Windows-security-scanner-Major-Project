import xml.etree.ElementTree as ET

def parse_nmap_xml(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    results = []

    for host in root.findall("host"):
        addr_elem = host.find("address")
        if addr_elem is None:
            continue

        host_ip = addr_elem.attrib.get("addr")
        ports_data = []

        ports_elem = host.find("ports")
        if ports_elem is None:
            continue

        for port in ports_elem.findall("port"):
            port_id = int(port.attrib.get("portid"))
            protocol = port.attrib.get("protocol")

            state_elem = port.find("state")
            state = state_elem.attrib.get("state") if state_elem is not None else "unknown"

            service_elem = port.find("service")

            ports_data.append({
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": {
                    "name": service_elem.attrib.get("name") if service_elem is not None else None,
                    "product": service_elem.attrib.get("product") if service_elem is not None else None,
                    "version": service_elem.attrib.get("version") if service_elem is not None else None,
                    "extra_info": service_elem.attrib.get("extrainfo") if service_elem is not None else None,
                    "confidence": service_elem.attrib.get("method") if service_elem is not None else None
                }
            })

        results.append({
            "host": host_ip,
            "ports": ports_data
        })

    return results
