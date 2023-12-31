"""Data Model for sifting those nmap results"""

from __future__ import annotations
from typing import Any


def filter_results(
    results: dict[str, Any], ip_add: str
) -> tuple[dict[str, str], str]:  # noqa: E501
    """Filter nmap results"""

    if results["scan"] == {}:
        return results

    port_number = results["scan"][ip_add]["tcp"]

    protocol = int()

    if 443 in port_number and port_number[443].get("product"):
        protocol = 443
    elif 80 in port_number and port_number[80].get("product"):
        protocol = 80
    else:
        exit()

    # Grab Server and Engine version
    # Return if 1 of 2 not found
    server_results: dict[str, str] = {}

    server_type = results["scan"][ip_add]["tcp"][protocol]["product"]
    if "unknown" in server_type:
        print(f"Unable to determine Engine version or type for {ip_add}")

    else:
        server_version = results["scan"][ip_add]["tcp"][protocol]["version"]
        server_results[server_type] = server_version

    return server_results, protocol


def strip_junk(domain_name: str) -> str:
    """Strip website junk to try and form website url"""

    # Strip junk
    stripped_name = ""
    if "dns" in domain_name:
        if ".com" not in domain_name:
            domain_name.strip(".dns")
            stripped_name = f"{domain_name}.com"
        stripped_name = f'{domain_name.strip(".dns")}'

    elif ".com" in domain_name:
        stripped_name = f'{domain_name.strip(".com")}'
    elif ".com" not in domain_name:
        stripped_name = f"{domain_name}.com"
    else:
        return domain_name

    return stripped_name
