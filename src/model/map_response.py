"""Data Model for sifting those nmap results"""

from __future__ import annotations
from typing import Any


def filter_results(results: dict[str, Any], ip_add: str) -> dict[str, str]:
    """Filter nmap results"""

    if results['scan'] == {}:
        return

    protocol = ""
    port_number = results['scan'][ip_add]['tcp']
    if 443 in port_number:
        protocol = 443
    elif 80 in port_number:
        protocol = 80
            
    server_type = results['scan'][ip_add]['tcp'][protocol]['product']
    if 'unknown' in server_type:
        print('Unable to determine Engine version or type.')
        return

    else:
        server_version = results['scan'][ip_add]['tcp'][protocol]['version']
        server_results = {server_type: server_version}

    return server_results
