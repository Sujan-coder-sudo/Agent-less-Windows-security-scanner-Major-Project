import xml.etree.ElementTree as ET

def extract_ips_from_xml(xml_file):
    """
    Extracts live host IPs from an Nmap -sn XML output.
    No port data, no DNS, no MAC logic.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    live_hosts = []

    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.attrib.get("state") == "up":
            address = host.find("address")
            if address is not None:
                live_hosts.append(address.attrib.get("addr"))

    return live_hosts
