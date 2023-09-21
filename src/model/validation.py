import ipaddress


def verify_ip_format(ip_addr: str) -> bool:
    """Check IP Format from user input"""
    given_ip = ipaddress.ip_address(ip_addr)

    if not given_ip:
        return False
    return True
