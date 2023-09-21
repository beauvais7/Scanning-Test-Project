"""Data Model for sifting those nmap results"""

from __future__ import annotations
from typing import Any


def filter_results(results: dict[str, Any], ip_add: str) -> dict[str, str]:
    """Filter nmap results"""

    if results['scan'] == {}:
        return

    port_number = results['scan'][ip_add]['tcp']
    
    protocol = ""

    if 443 in port_number and port_number[443].get('product'):
        protocol = 443
    elif 80 in port_number and port_number[80].get('product'):
        protocol = 80
    else:
        print(f'Unable to determine Engine version or type for {ip_add}')
        return

    # Grab Server and Engine version
    # Return if 1 of 2 not found
    server_results: dict[str, str] = {}   

    server_type = results['scan'][ip_add]['tcp'][protocol]['product']
    if 'unknown' in server_type:
        print(f'Unable to determine Engine version or type for {ip_add}')
        return
    else:
        server_version = results['scan'][ip_add]['tcp'][protocol]['version']
        server_results[server_type] = [server_version]

    return server_results
